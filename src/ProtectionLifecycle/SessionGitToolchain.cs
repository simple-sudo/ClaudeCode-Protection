using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal sealed record GitToolchainReport(bool InputHashMatched,bool InitAddCommitObserved,string? CommitId,
    bool PrivateFixtureReadRefused,int? DenialExit,string? FailureStage,string? FailureType,int? FailureCode);

// Personal-machine deployment assumption, like the current FlClash path.
// Only these reviewed installed Git bytes are allowed; an update requires new
// qualification. No host Git configuration, credentials, hooks or remote URL
// is imported. Git always executes inside the existing confined child/Job.
internal sealed class SessionGitToolchain : IDisposable
{
    private static readonly (string Name,string Hash)[] Assets={
        ("git.exe","11CE9BFCB40927767C474326EE87477079E1CC24A9782E69936B3351B6C3C205"),
        ("libiconv-2.dll","FF31FA811F9C07CC7FDAA68C9E8BCA3A7B4FDF6E0A079A58175EA58BA139C7AE"),
        ("libintl-8.dll","479C8BFFC0DA6D28747CDE0F4DD4D7714050811EBDFDF1FCC807EFD9818E5A7F"),
        ("libpcre2-8-0.dll","21D741E2C5089776A535587CD5FCD933B51054E16BF8E50855E74E68B3790228"),
        ("libwinpthread-1.dll","212E84730CE3EE28CD9FAB37113A34931EA947FF538085372BEF27C009010182"),
        ("zlib1.dll","CB7AB3788D10940DF874ACD97B1821BBB5EE4A91F3EEC11982BB5BF7A3C96443")
    };
    internal static string DirectoryPath=>WindowsPathSeal.Child(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"Git/mingw64/bin");
    internal static string ToolPath=>WindowsPathSeal.Child(DirectoryPath,"git.exe");
    internal static string AssetSetSHA256=>Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(string.Join('\n',Assets.Select(a=>a.Name+":"+a.Hash)))));
    private readonly PathLease directory;
    private readonly List<FileStream> files=new();
    private SessionGitToolchain(PathLease directory){this.directory=directory;}
    internal static SessionGitToolchain Open()
    {
        // The last directory must also deny untrusted DLL creation, rather
        // than merely preventing its own rename. No ACL is changed here.
        PathLease directory;
        try{directory=WindowsPathSeal.LockDirectory(DirectoryPath,PathPolicy.CreationParent);}
        catch(Exception ex){if(ex.Data["Stage"] is null)ex.Data["Stage"]="VerifyFixedGitDirectory";throw;}
        var result=new SessionGitToolchain(directory);var stage="VerifyGitAssetSet";
        try
        {
            foreach(var asset in Assets)
            {
                stage="VerifyGitAsset:"+asset.Name;
                var file=new FileStream(WindowsPathSeal.OpenReviewedGitAsset(asset.Name),FileAccess.Read,65536,false);
                result.files.Add(file);WindowsPathSeal.AssertAcl(file.SafeFileHandle,false,true);
                if(file.Length is <1 or >16*1024*1024 || Convert.ToHexString(SHA256.HashData(file))!=asset.Hash)throw WfpNative.Contract("ReviewedGitAssetChanged");
                file.Position=0;
            }
            result.AssertHeld();return result;
        }
        catch(Exception ex){if(ex.Data["Stage"] is null)ex.Data["Stage"]=stage;result.Dispose();throw;}
    }
    internal void AssertHeld()
    {
        directory.AssertHeld();if(files.Count!=Assets.Length)throw WfpNative.Contract("GitAssetLeaseIncomplete");
        foreach(var file in files){if(file.SafeFileHandle.IsClosed)throw WfpNative.Contract("GitAssetLeaseLost");WindowsPathSeal.AssertAcl(file.SafeFileHandle,false,true);}
    }
    public void Dispose(){foreach(var file in files)file.Dispose();directory.Dispose();}
    internal static bool Qualified(GitToolchainReport value)=>value.InputHashMatched && value.InitAddCommitObserved && IsObjectId(value.CommitId) &&
        value.PrivateFixtureReadRefused && value.DenialExit==128 && value.FailureStage is null && value.FailureType is null && value.FailureCode is null;
    private static bool IsObjectId(string? value)=>value?.Length==40 && value.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f');
    internal static string BlobId(byte[] input)=>Convert.ToHexString(SHA1.HashData(Encoding.ASCII.GetBytes("blob "+input.Length+"\0").Concat(input).ToArray())).ToLowerInvariant();
    internal static GitToolchainReport RunChild(ResourceProbePlan plan,string workspace)
    {
        bool hashMatched=false,committed=false,denied=false;string? commit=null;int? denialExit=null;var stage="VERIFY_GIT_INPUTS";
        try
        {
            if(plan.GitAssetSetSHA256!=AssetSetSHA256)throw WfpNative.Contract("GitResourcePlanMismatch");
            foreach(var asset in Assets)
            {
                // The manager holds the ancestry and each complete asset.
                // This side performs ordinary file I/O, no privileged metadata.
                using var file=File.OpenRead(WindowsPathSeal.Child(DirectoryPath,asset.Name));
                if(file.Length is <1 or >16*1024*1024 || Convert.ToHexString(SHA256.HashData(file))!=asset.Hash)throw WfpNative.Contract("ChildGitAssetChanged");
            }
            stage="HASH_INPUT_WITH_INSPECTED_GIT";
            using(var process=Process.Start(Start(workspace,"hash-object","--stdin"))??throw WfpNative.Contract("GitStartFailed"))
            {
                var stdout=SessionResources.ReadBounded(process.StandardOutput);var stderr=SessionResources.ReadBounded(process.StandardError);
                Signal(workspace,"git-ready",plan.Nonce);
                var clock=Stopwatch.StartNew();
                while(!File.Exists(WindowsPathSeal.Child(workspace,"git-go.signal")))
                {
                    if(process.HasExited){RecordResult(workspace,Finish(process,stdout,stderr));throw WfpNative.Contract("GitExitedBeforeInputAdmission");}
                    if(clock.ElapsedMilliseconds>=8000)throw WfpNative.Contract("GitInspectionGateExpired");Thread.Sleep(20);
                }
                if(File.ReadAllText(WindowsPathSeal.Child(workspace,"git-go.txt"))!=plan.Nonce)throw WfpNative.Contract("GitGateBindingMismatch");
                process.StandardInput.Write(Encoding.UTF8.GetString(plan.Input));process.StandardInput.Close();
                var result=Finish(process,stdout,stderr);
                RecordResult(workspace,result);Require(result);
                hashMatched=result.Exit==0 && result.Out.Trim()==BlobId(plan.Input) && result.Error.Length==0;
                if(!hashMatched)throw WfpNative.Contract("GitInputHashMismatch");
            }
            var repo=WindowsPathSeal.Child(workspace,"git-project");
            Directory.CreateDirectory(WindowsPathSeal.Child(workspace,"empty-git-template"));
            Directory.CreateDirectory(WindowsPathSeal.Child(workspace,"empty-git-hooks"));
            var project=WorkspaceBundle.Parse(plan.ProjectBundle);
            foreach(var file in project.Files)
                if(!File.ReadAllBytes(WindowsPathSeal.Child(repo,file.Path)).AsSpan().SequenceEqual(file.Content))throw WfpNative.Contract("GitProjectInputChanged");
            stage="GIT_INIT";Require(Run(workspace,"init","--quiet","--initial-branch=qualification","--template="+WindowsPathSeal.Child(workspace,"empty-git-template"),repo));
            // Highest-precedence info attributes override project-controlled
            // transformations. Data processing preserves exact selected bytes,
            // independent of .gitattributes or .gitignore in the source bundle.
            var info=WindowsPathSeal.Child(repo,".git/info");Directory.CreateDirectory(info);
            File.WriteAllText(WindowsPathSeal.Child(info,"attributes"),"* -text -filter -ident -working-tree-encoding\n",new UTF8Encoding(false));
            stage="GIT_ADD";Require(Run(workspace,new[]{"-C",repo,"add","--force","--"}.Concat(project.Files.Select(f=>f.Path)).ToArray()));
            stage="GIT_COMMIT";Require(Run(workspace,"-C",repo,"commit","--quiet","--no-gpg-sign","-m","Controlled offline qualification"));
            stage="READ_COMMIT";var head=Run(workspace,"-C",repo,"rev-parse","--verify","HEAD");Require(head);commit=head.Out.Trim();
            if(!IsObjectId(commit))throw WfpNative.Contract("GitHeadMissing");
            // The trusted owner verifies every committed blob and complete
            // tree below. Text-decoding `git show` cannot prove binary data.
            committed=true;
            stage="GIT_PRIVATE_FIXTURE_DENIAL";var negative=Run(workspace,"hash-object","--",plan.Fixture);denialExit=negative.Exit;
            denied=negative.Exit==128 && negative.Out.Length==0 && negative.Error.TrimEnd().EndsWith(": Permission denied",StringComparison.Ordinal);
            if(!denied)throw WfpNative.Contract("GitPrivateFixtureDenialNotConfirmed");
            return new(hashMatched,committed,commit,denied,denialExit,null,null,null);
        }
        catch(Exception ex){return new(hashMatched,committed,commit,denied,denialExit,stage+(ex.Data["Stage"] is string nativeStage?"/"+nativeStage:""),ex.GetType().Name,ex is System.ComponentModel.Win32Exception native?native.NativeErrorCode:ex.HResult);}
    }
    private static void Signal(string workspace,string stem,string nonce)
    {
        File.WriteAllText(WindowsPathSeal.Child(workspace,stem+".txt"),nonce,new UTF8Encoding(false));
        File.WriteAllText(WindowsPathSeal.Child(workspace,stem+".signal"),"");
    }
    private static ProcessStartInfo Start(string workspace,params string[] arguments)
    {
        var start=new ProcessStartInfo(ToolPath){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=workspace,
            RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardInputEncoding=new UTF8Encoding(false),StandardOutputEncoding=new UTF8Encoding(false),StandardErrorEncoding=new UTF8Encoding(false)};
        start.Environment.Clear();
        foreach(var name in new[]{"SystemRoot","windir","SystemDrive","PROCESSOR_ARCHITECTURE"})
        {var value=Environment.GetEnvironmentVariable(name);if(value is not null)start.Environment[name]=value;}
        foreach(var name in new[]{"TEMP","TMP","HOME","USERPROFILE","LOCALAPPDATA","XDG_CONFIG_HOME"})start.Environment[name]=workspace;
        start.Environment["PATH"]=DirectoryPath+";"+Environment.GetFolderPath(Environment.SpecialFolder.System);
        start.Environment["GIT_EXEC_PATH"]=DirectoryPath;start.Environment["GIT_CONFIG_NOSYSTEM"]="1";start.Environment["GIT_ATTR_NOSYSTEM"]="1";
        start.Environment["GIT_CONFIG_GLOBAL"]=WindowsPathSeal.Child(workspace,"empty-git-config");start.Environment["GIT_CONFIG_COUNT"]="0";
        start.Environment["GIT_CEILING_DIRECTORIES"]=workspace;start.Environment["GIT_DISCOVERY_ACROSS_FILESYSTEM"]="0";
        start.Environment["GIT_TERMINAL_PROMPT"]="0";start.Environment["GCM_INTERACTIVE"]="never";start.Environment["GIT_NO_LAZY_FETCH"]="1";
        foreach(var name in new[]{"GIT_AUTHOR_NAME","GIT_COMMITTER_NAME"})start.Environment[name]="CPC Qualification";
        foreach(var name in new[]{"GIT_AUTHOR_EMAIL","GIT_COMMITTER_EMAIL"})start.Environment[name]="offline@invalid.example";
        foreach(var name in new[]{"GIT_AUTHOR_DATE","GIT_COMMITTER_DATE"})start.Environment[name]="2026-10-28T00:00:00+00:00";
        start.Environment["LC_ALL"]="C";start.Environment["LANG"]="C";
        foreach(var arg in new[]{"--no-pager","-c","credential.helper=","-c","protocol.allow=never","-c","core.autocrlf=false","-c","core.filemode=false",
            "-c","core.fsmonitor=false","-c","maintenance.auto=false","-c","gc.auto=0","-c","commit.gpgsign=false",
            "-c","core.hooksPath="+WindowsPathSeal.Child(workspace,"empty-git-hooks"),"-c","safe.directory="+WindowsPathSeal.Child(workspace,"git-project")}.Concat(arguments))start.ArgumentList.Add(arg);
        return start;
    }
    private static (int Exit,string Out,string Error) Run(string workspace,params string[] args)
    {
        using var process=Process.Start(Start(workspace,args))??throw WfpNative.Contract("GitStartFailed");process.StandardInput.Close();
        var result=Finish(process,SessionResources.ReadBounded(process.StandardOutput),SessionResources.ReadBounded(process.StandardError));
        RecordResult(workspace,result);return result;
    }
    private static void RecordResult(string workspace,(int Exit,string Out,string Error) result)=>
        File.WriteAllText(WindowsPathSeal.Child(workspace,"git-last-result.json"),JsonSerializer.Serialize(new {ExitCode=result.Exit,Stdout=result.Out,Stderr=result.Error}),new UTF8Encoding(false));
    private static (int Exit,string Out,string Error) Finish(Process process,Task<string> stdout,Task<string> stderr)
    {
        if(!process.WaitForExit(8000))throw WfpNative.Contract("FixedGitDeadlineExpired");
        return(process.ExitCode,stdout.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult(),stderr.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult());
    }
    private static void Require((int Exit,string Out,string Error) result)
    {if(result.Exit!=0 || result.Error.Length!=0)throw WfpNative.Contract("FixedGitCommandFailed");}
    internal static void AssertRepository(string workspace,ResourceProbePlan plan,GitToolchainReport report)
    {
        if(!Qualified(report))throw WfpNative.Contract("GitToolchainReportRefused");
        var objects=WindowsPathSeal.Child(workspace,"git-project/.git/objects");
        byte[] ReadObject(string id)
        {
            if(!IsObjectId(id))throw WfpNative.Contract("GitObjectNameRefused");
            using var parent=WindowsPathSeal.LockDirectory(WindowsPathSeal.Child(objects,id[..2]),PathPolicy.Source);
            using var source=new FileStream(WindowsPathSeal.Open(WindowsPathSeal.Child(parent.Path,id[2..]),false,true),FileAccess.Read,4096,false);
            if(source.Length<1 || source.Length>WorkspaceBundle.MaxFileBytes+65536)throw WfpNative.Contract("GitObjectBounds");
            using var decoder=new ZLibStream(source,CompressionMode.Decompress);using var target=new MemoryStream();
            var buffer=new byte[1024];int count;
            while((count=decoder.Read(buffer))>0){if(target.Length+count>WorkspaceBundle.MaxFileBytes+64)throw WfpNative.Contract("GitInflatedObjectBounds");target.Write(buffer,0,count);}
            var bytes=target.ToArray();if(Convert.ToHexString(SHA1.HashData(bytes)).ToLowerInvariant()!=id)throw WfpNative.Contract("GitObjectHashMismatch");return bytes;
        }
        var project=WorkspaceBundle.Parse(plan.ProjectBundle);
        string VerifyTree(string prefix)
        {
            var entries=new List<(string Name,bool Directory,string Id)>();
            foreach(var file in project.Files.Where(f=>f.Path.StartsWith(prefix,StringComparison.Ordinal)))
            {
                var rest=file.Path[prefix.Length..];var slash=rest.IndexOf('/');
                if(slash>=0)
                {
                    var name=rest[..slash];if(entries.Any(e=>e.Name==name))continue;
                    entries.Add((name,true,VerifyTree(prefix+name+"/")));
                }
                else
                {
                    var id=BlobId(file.Content);var bytes=Encoding.ASCII.GetBytes("blob "+file.Content.Length+"\0").Concat(file.Content).ToArray();
                    if(!ReadObject(id).AsSpan().SequenceEqual(bytes))throw WfpNative.Contract("GitCommittedBlobMismatch");
                    entries.Add((rest,false,id));
                }
            }
            using var treeBody=new MemoryStream();
            foreach(var entry in entries.OrderBy(e=>e.Name+(e.Directory?"/":""),StringComparer.Ordinal))
            {treeBody.Write(Encoding.ASCII.GetBytes((entry.Directory?"40000 ":"100644 ")+entry.Name+"\0"));treeBody.Write(Convert.FromHexString(entry.Id));}
            var expected=Encoding.ASCII.GetBytes("tree "+treeBody.Length+"\0").Concat(treeBody.ToArray()).ToArray();
            var treeId=Convert.ToHexString(SHA1.HashData(expected)).ToLowerInvariant();
            if(!ReadObject(treeId).AsSpan().SequenceEqual(expected))throw WfpNative.Contract("GitCommittedTreeMismatch");return treeId;
        }
        var expectedTree=VerifyTree("");
        var commit=ReadObject(report.CommitId!);var zero=Array.IndexOf(commit,(byte)0);
        if(zero is <1 or >32 || !Encoding.ASCII.GetString(commit,0,zero).Equals("commit "+(commit.Length-zero-1),StringComparison.Ordinal))throw WfpNative.Contract("GitCommitObjectRefused");
        var body=Encoding.UTF8.GetString(commit,zero+1,commit.Length-zero-1);
        if(body.Length<46 || !body.StartsWith("tree ",StringComparison.Ordinal) || body[45]!='\n')throw WfpNative.Contract("GitCommitTreeMissing");
        var stamp=new DateTimeOffset(2026,10,28,0,0,0,TimeSpan.Zero).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var identity="CPC Qualification <offline@invalid.example> "+stamp+" +0000\n";
        if(body!="tree "+body.Substring(5,40)+"\nauthor "+identity+"committer "+identity+"\nControlled offline qualification\n")
            throw WfpNative.Contract("GitCommitIdentityOrMetadataMismatch");
        if(body.Substring(5,40)!=expectedTree)throw WfpNative.Contract("GitCommitWorkspaceTreeMismatch");
        using var refParent=WindowsPathSeal.LockDirectory(WindowsPathSeal.Child(workspace,"git-project/.git/refs/heads"),PathPolicy.Source);
        using var reference=new FileStream(WindowsPathSeal.Open(WindowsPathSeal.Child(refParent.Path,"qualification"),false,true),FileAccess.Read,128,false);
        if(reference.Length!=41)throw WfpNative.Contract("GitBranchRefBounds");var data=new byte[41];reference.ReadExactly(data);
        if(Encoding.ASCII.GetString(data)!=report.CommitId+"\n")throw WfpNative.Contract("GitBranchRefMismatch");
    }
}
