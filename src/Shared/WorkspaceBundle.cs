using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ClaudeCodeProtection.Workspaces;

internal sealed record WorkspaceFile(string Path,byte[] Content,string SHA256);
internal sealed record WorkspaceChange(string Path,string Kind,string? BeforeSHA256,string? AfterSHA256);

internal sealed record WorkspaceGitPlan(int SchemaVersion,string BranchName,string CommitMessage,string CommitDateUtc)
{
    internal const string AuthorName="Local Workspace";
    internal const string AuthorEmail="local@invalid.example";
    internal void Validate()
    {
        if(SchemaVersion!=1 || BranchName!="main" || string.IsNullOrWhiteSpace(CommitMessage) ||
            CommitMessage.Length>160 || CommitMessage.Trim()!=CommitMessage ||
            CommitMessage.Any(c=>char.IsControl(c) || c=='\u2028' || c=='\u2029') || string.IsNullOrEmpty(CommitDateUtc) ||
            !DateTimeOffset.TryParseExact(CommitDateUtc,"yyyy-MM-ddTHH:mm:ssZ",CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal|DateTimeStyles.AdjustToUniversal,out var commitDate) ||
            commitDate.ToUnixTimeSeconds() is <0 or >4102444800)
            throw new InvalidDataException("Workspace Git plan contract refused");
        try{_=new UTF8Encoding(false,true).GetByteCount(CommitMessage);}
        catch(EncoderFallbackException){throw new InvalidDataException("Workspace Git commit message encoding refused");}
    }
    internal long CommitUnixTime=>DateTimeOffset.ParseExact(CommitDateUtc,"yyyy-MM-ddTHH:mm:ssZ",CultureInfo.InvariantCulture,
        DateTimeStyles.AssumeUniversal|DateTimeStyles.AdjustToUniversal).ToUnixTimeSeconds();
}

internal sealed record WorkspaceGitReceipt(int SchemaVersion,string PlanSHA256,string BranchName,string CommitId,string TreeId,
    string CommitMessage,string AuthorName,string AuthorEmail,long CommitUnixTime,int FileCount,int AddedLines,int DeletedLines,
    int BinaryFileCount,bool CleanAfterCommit,bool ObjectIntegrityVerified)
{
    internal void Validate()
    {
        if(SchemaVersion!=1 || !WorkspaceBundle.IsHash(PlanSHA256) || BranchName!="main" ||
            !IsObjectId(CommitId) || !IsObjectId(TreeId) || string.IsNullOrWhiteSpace(CommitMessage) ||
            CommitMessage.Length>160 || CommitMessage.Trim()!=CommitMessage ||
            CommitMessage.Any(c=>char.IsControl(c) || c=='\u2028' || c=='\u2029') ||
            AuthorName!=WorkspaceGitPlan.AuthorName || AuthorEmail!=WorkspaceGitPlan.AuthorEmail ||
            CommitUnixTime is <0 or >4102444800 || FileCount is <1 or >WorkspaceBundle.MaxFiles ||
            AddedLines is <0 or >100000000 || DeletedLines is <0 or >100000000 ||
            BinaryFileCount<0 || BinaryFileCount>FileCount || !CleanAfterCommit || !ObjectIntegrityVerified)
            throw new InvalidDataException("Workspace Git receipt contract refused");
    }
    private static bool IsObjectId(string? value)=>value is {Length:40} && value.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f');
}

// Data only. Neither paths, scripts, Git metadata nor these hashes grant
// execution, elevation, network access or admission. No host path is serialized.
// Schema 2 carries a declarative offline Git plan or its bounded result receipt;
// it never carries or imports a host .git directory.
internal sealed record WorkspaceBundle(int SchemaVersion,string Scope,string? BaseSHA256,WorkspaceFile[] Files)
{
    internal const int MaxFiles=512,MaxFileBytes=1024*1024,MaxTotalBytes=8*1024*1024,MaxBundleBytes=12*1024*1024;
    internal const string DataScope="EXPLICIT_WORKSPACE_DATA_ONLY";
    internal const string GitWorkflowScope="EXPLICIT_OFFLINE_GIT_WORKFLOW_DATA_ONLY";
    [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]
    public WorkspaceGitPlan? GitPlan {get;init;}
    [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]
    public WorkspaceGitReceipt? GitReceipt {get;init;}
    internal static string Hash(ReadOnlySpan<byte> bytes)=>Convert.ToHexString(SHA256.HashData(bytes));
    internal static bool IsHash(string? hash)=>hash is {Length:64} && hash.All(c=>c is >= '0' and <= '9' or >= 'A' and <= 'F');
    internal static string Relative(string path)
    {
        if(string.IsNullOrEmpty(path) || path.Length>160)throw new InvalidDataException("Workspace relative path bounds");
        var parts=path.Split('/');
        if(parts.Length>12)throw new InvalidDataException("Workspace path depth bounds");
        foreach(var part in parts)
        {
            // Deliberately narrow v1 Windows filename contract. Excludes ADS,
            // device aliases, traversal, normalization and wildcard ambiguity.
            if(part.Length is <1 or >80 || part is "." or ".." || part.EndsWith('.') || part.EndsWith(' ') ||
                part.Any(c=>!char.IsAsciiLetterOrDigit(c) && c is not ('.' or '_' or '-' or ' ')))
                throw new InvalidDataException("Ambiguous workspace path refused");
            var stem=part.Split('.')[0].ToUpperInvariant();
            if(stem is "CON" or "PRN" or "AUX" or "NUL" or "CLOCK$" ||
                stem.Length==4 && (stem.StartsWith("COM",StringComparison.Ordinal) || stem.StartsWith("LPT",StringComparison.Ordinal)) && stem[3] is >= '0' and <= '9' ||
                part.Equals(".git",StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Workspace device or Git metadata refused");
        }
        return path;
    }
    internal void Validate()
    {
        var dataOnly=SchemaVersion==1 && Scope==DataScope && GitPlan is null && GitReceipt is null;
        var gitPlan=SchemaVersion==2 && Scope==GitWorkflowScope && GitPlan is not null && GitReceipt is null && BaseSHA256 is null;
        var gitReceipt=SchemaVersion==2 && Scope==GitWorkflowScope && GitPlan is null && GitReceipt is not null && BaseSHA256 is not null;
        if((!dataOnly && !gitPlan && !gitReceipt) || BaseSHA256 is not null && !IsHash(BaseSHA256) || Files is null || Files.Length>MaxFiles)
            throw new InvalidDataException("Workspace bundle contract refused");
        GitPlan?.Validate();GitReceipt?.Validate();
        if(GitReceipt is not null && GitReceipt.FileCount!=Files.Length)throw new InvalidDataException("Workspace Git receipt file count differs");
        var names=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        var directories=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);long total=0;
        foreach(var file in Files)
        {
            if(file is null)throw new InvalidDataException("Workspace file missing");
            var path=Relative(file.Path);
            if(!names.TryAdd(path,path) || file.Content is null || file.Content.Length>MaxFileBytes ||
                !IsHash(file.SHA256) || Hash(file.Content)!=file.SHA256 || (total+=file.Content.Length)>MaxTotalBytes)
                throw new InvalidDataException("Workspace file content, duplicate or bounds refused");
            var split=path.LastIndexOf('/');
            while(split>=0)
            {
                var directory=path[..split];
                if(directories.TryGetValue(directory,out var original) && original!=directory)
                    throw new InvalidDataException("Workspace directory case alias refused");
                directories[directory]=directory;split=directory.LastIndexOf('/');
            }
        }
        if(directories.Count>MaxFiles)throw new InvalidDataException("Workspace directory inventory bounds");
        if(names.Keys.Any(directories.ContainsKey))throw new InvalidDataException("Workspace file-directory collision refused");
        foreach(var file in Files)
            foreach(var directory in directories.Keys)
                if(file.Path.StartsWith(directory+"/",StringComparison.OrdinalIgnoreCase) && !file.Path.StartsWith(directory+"/",StringComparison.Ordinal))
                    throw new InvalidDataException("Workspace ancestor case alias refused");
    }
    internal byte[] Serialize()
    {
        Validate();var bytes=JsonSerializer.SerializeToUtf8Bytes(this);
        if(bytes.Length>MaxBundleBytes)throw new InvalidDataException("Workspace serialized bounds");return bytes;
    }
    internal static WorkspaceBundle Parse(byte[] bytes)
    {
        if(bytes.Length is <1 or >MaxBundleBytes)throw new InvalidDataException("Workspace input bounds");
        using var doc=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=7});
        var root=doc.RootElement;
        if(root.ValueKind!=JsonValueKind.Object)throw new InvalidDataException("Workspace JSON object required");
        var schema=root.GetProperty("SchemaVersion").GetInt32();
        var fields=new[]{"SchemaVersion","Scope","BaseSHA256","Files"};
        if(schema==2)
        {
            var hasPlan=root.TryGetProperty("GitPlan",out var plan);
            var hasReceipt=root.TryGetProperty("GitReceipt",out var receipt);
            if(hasPlan==hasReceipt)throw new InvalidDataException("Exactly one Git workflow contract required");
            Fields(hasPlan?plan:receipt,hasPlan?new[]{"SchemaVersion","BranchName","CommitMessage","CommitDateUtc"}:
                new[]{"SchemaVersion","PlanSHA256","BranchName","CommitId","TreeId","CommitMessage","AuthorName","AuthorEmail","CommitUnixTime","FileCount","AddedLines","DeletedLines","BinaryFileCount","CleanAfterCommit","ObjectIntegrityVerified"});
            fields=fields.Append(hasPlan?"GitPlan":"GitReceipt").ToArray();
        }
        else if(schema!=1)throw new InvalidDataException("Unknown workspace schema");
        Fields(root,fields);
        if(root.GetProperty("Files").ValueKind!=JsonValueKind.Array || root.GetProperty("Files").GetArrayLength()>MaxFiles)
            throw new InvalidDataException("Workspace inventory bounds");
        foreach(var file in root.GetProperty("Files").EnumerateArray())Fields(file,"Path","Content","SHA256");
        var bundle=JsonSerializer.Deserialize<WorkspaceBundle>(bytes)??throw new InvalidDataException("Workspace bundle missing");
        bundle.Validate();return bundle;
    }
    private static void Fields(JsonElement value,params string[] expected)
    {
        if(value.ValueKind!=JsonValueKind.Object)throw new InvalidDataException("Workspace JSON object required");
        var actual=value.EnumerateObject().Select(p=>p.Name).ToArray();
        if(actual.Length!=expected.Length || actual.Distinct(StringComparer.Ordinal).Count()!=actual.Length ||
            actual.Except(expected,StringComparer.Ordinal).Any())throw new InvalidDataException("Workspace JSON fields refused");
    }
    internal static WorkspaceBundle CreateGitWorkflow(byte[] dataBytes,string commitMessage)
    {
        var data=Parse(dataBytes);
        if(data.SchemaVersion!=1 || data.BaseSHA256 is not null || data.Files.Length==0)
            throw new InvalidDataException("Fresh data-only workspace required for Git initialization");
        var plan=new WorkspaceGitPlan(1,"main",commitMessage,DateTimeOffset.UtcNow.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ",CultureInfo.InvariantCulture));
        plan.Validate();
        return new WorkspaceBundle(2,GitWorkflowScope,null,data.Files){GitPlan=plan}.AlsoValidateAndSerialize();
    }
    internal static string GitPlanHash(WorkspaceGitPlan plan)
        =>Hash(JsonSerializer.SerializeToUtf8Bytes(plan));
    internal static byte[] AttachGitReceipt(byte[] resultBytes,byte[] baselineBytes,WorkspaceGitReceipt receipt)
    {
        var baseline=Parse(baselineBytes);var result=Parse(resultBytes);
        if(baseline.GitPlan is null || result.BaseSHA256!=Hash(baselineBytes) ||
            receipt.PlanSHA256!=GitPlanHash(baseline.GitPlan) || receipt.BranchName!=baseline.GitPlan.BranchName ||
            receipt.CommitMessage!=baseline.GitPlan.CommitMessage || receipt.CommitUnixTime!=baseline.GitPlan.CommitUnixTime ||
            receipt.FileCount!=baseline.Files.Length)
            throw new InvalidDataException("Git receipt is not bound to the exact workflow input");
        return new WorkspaceBundle(2,GitWorkflowScope,result.BaseSHA256,result.Files){GitReceipt=receipt}.AlsoValidateAndSerialize();
    }
    private byte[] AlsoValidateAndSerialize()=>Serialize();
    internal static WorkspaceBundle Create(IEnumerable<(string Path,byte[] Content)> files,string? baseSHA256=null)
    {
        // Bound enumeration too; do not materialize unbounded caller input.
        var selected=files.Take(MaxFiles+1).Select(f=>new WorkspaceFile(f.Path,f.Content,Hash(f.Content))).ToArray();
        var bundle=new WorkspaceBundle(1,DataScope,baseSHA256,selected.OrderBy(f=>f.Path,StringComparer.Ordinal).ToArray());
        bundle.Validate();return bundle;
    }
    internal static WorkspaceChange[] Compare(byte[] baselineBytes,byte[] resultBytes)
    {
        var baseline=Parse(baselineBytes);var result=Parse(resultBytes);
        if(baseline.BaseSHA256 is not null || result.BaseSHA256!=Hash(baselineBytes) ||
            baseline.Scope!=result.Scope ||
            baseline.GitPlan is null && result.GitReceipt is not null ||
            baseline.GitPlan is not null && (result.GitReceipt is null ||
                result.GitReceipt.PlanSHA256!=GitPlanHash(baseline.GitPlan) ||
                result.GitReceipt.BranchName!=baseline.GitPlan.BranchName ||
                result.GitReceipt.CommitMessage!=baseline.GitPlan.CommitMessage ||
                result.GitReceipt.CommitUnixTime!=baseline.GitPlan.CommitUnixTime ||
                result.GitReceipt.FileCount!=baseline.Files.Length))
            throw new InvalidDataException("Workspace result not bound to this exact baseline");
        var before=baseline.Files.ToDictionary(f=>f.Path,StringComparer.OrdinalIgnoreCase);
        var after=result.Files.ToDictionary(f=>f.Path,StringComparer.OrdinalIgnoreCase);
        // Case-only renames cannot silently disappear on Windows.
        if(before.Keys.Any(p=>after.TryGetValue(p,out var file) && p!=file.Path))throw new InvalidDataException("Workspace result case rename refused");
        return before.Keys.Union(after.Keys,StringComparer.OrdinalIgnoreCase).OrderBy(p=>p,StringComparer.Ordinal).Select(path=>
        {
            before.TryGetValue(path,out var old);after.TryGetValue(path,out var next);
            return new WorkspaceChange(path,old is null?"ADD":next is null?"DELETE":old.SHA256==next.SHA256?"UNCHANGED":"MODIFY",old?.SHA256,next?.SHA256);
        }).Where(c=>c.Kind!="UNCHANGED").ToArray();
    }
}
