using System.Security.Cryptography;
using System.Text.Json;

namespace ClaudeCodeProtection.Workspaces;

internal sealed record WorkspaceFile(string Path,byte[] Content,string SHA256);
internal sealed record WorkspaceChange(string Path,string Kind,string? BeforeSHA256,string? AfterSHA256);

// Data only. Neither paths, scripts, Git metadata nor these hashes grant
// execution, elevation, network access or admission. No host path is serialized.
internal sealed record WorkspaceBundle(int SchemaVersion,string Scope,string? BaseSHA256,WorkspaceFile[] Files)
{
    internal const int MaxFiles=512,MaxFileBytes=1024*1024,MaxTotalBytes=8*1024*1024,MaxBundleBytes=12*1024*1024;
    internal const string DataScope="EXPLICIT_WORKSPACE_DATA_ONLY";
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
        if(SchemaVersion!=1 || Scope!=DataScope || BaseSHA256 is not null && !IsHash(BaseSHA256) || Files is null || Files.Length>MaxFiles)
            throw new InvalidDataException("Workspace bundle contract refused");
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
        using var doc=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=5});
        Fields(doc.RootElement,"SchemaVersion","Scope","BaseSHA256","Files");
        if(doc.RootElement.GetProperty("Files").ValueKind!=JsonValueKind.Array || doc.RootElement.GetProperty("Files").GetArrayLength()>MaxFiles)
            throw new InvalidDataException("Workspace inventory bounds");
        foreach(var file in doc.RootElement.GetProperty("Files").EnumerateArray())Fields(file,"Path","Content","SHA256");
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
        if(baseline.BaseSHA256 is not null || result.BaseSHA256!=Hash(baselineBytes))
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
