using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal sealed record GitWorkflowObservation(string PlanSHA256,string BranchName,string CommitId,string TreeId,string CommitMessage,
    string AuthorName,string AuthorEmail,long CommitUnixTime,int FileCount,int AddedLines,int DeletedLines,int BinaryFileCount,
    bool CleanAfterCommit,bool ObjectIntegrityObserved);
internal sealed record GitToolchainReport(bool InputHashMatched,bool InitAddCommitObserved,string? CommitId,
    bool PrivateFixtureReadRefused,int? DenialExit,bool AllPackagesFixtureReadRefused,int? AllPackagesDenialExit,string? FailureStage,string? FailureType,int? FailureCode)
{
    [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]
    public GitWorkflowObservation? Workflow {get;init;}
}

// Personal-machine deployment assumption, like the current FlClash path.
// Only these reviewed installed Git bytes are allowed; an update requires new
// qualification. No host Git configuration, credentials, hooks or remote URL
// is imported. Git always executes inside the existing confined child/Job.
internal sealed class SessionGitToolchain : IDisposable
{
    internal const string IndependentInitScope="FIXED_INDEPENDENT_GIT_INIT_FULL_QUARANTINE";
    internal const string IndependentCommitScope="FIXED_INDEPENDENT_GIT_TRACKED_COMMIT_FULL_QUARANTINE";
    internal enum Operation { None,Init,TrackedCommit }
    internal static string Scope(Operation operation)=>operation==Operation.TrackedCommit?IndependentCommitScope:IndependentInitScope;
    private const string CommitMessage="Controlled offline qualification";
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
    internal static string ImageSHA256=>Assets[0].Hash;
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
        value.PrivateFixtureReadRefused && value.DenialExit==128 && value.AllPackagesFixtureReadRefused && value.AllPackagesDenialExit==128 &&
        value.FailureStage is null && value.FailureType is null && value.FailureCode is null &&
        (value.Workflow is null || value.Workflow is {BranchName:"main",CommitMessage.Length:>0,AuthorName:WorkspaceGitPlan.AuthorName,
            AuthorEmail:WorkspaceGitPlan.AuthorEmail,CommitUnixTime:>=0,FileCount:>0 and <=WorkspaceBundle.MaxFiles,
            AddedLines:>=0,DeletedLines:>=0,BinaryFileCount:>=0,CleanAfterCommit:true,ObjectIntegrityObserved:true} &&
            WorkspaceBundle.IsHash(value.Workflow.PlanSHA256) && IsObjectId(value.Workflow.TreeId) &&
            value.Workflow.CommitId==value.CommitId);
    internal static bool QualifiedForPlan(ResourceProbePlan plan,GitToolchainReport value)
    {
        var project=WorkspaceBundle.Parse(plan.ProjectBundle);
        if(!Qualified(value))return false;
        if(project.GitPlan is not { } workflow)return value.Workflow is null;
        var observed=value.Workflow;
        return observed is not null &&
            observed.PlanSHA256==WorkspaceBundle.GitPlanHash(workflow) &&
            observed.BranchName==workflow.BranchName &&
            observed.CommitId==value.CommitId &&
            observed.CommitMessage==workflow.CommitMessage &&
            observed.AuthorName==WorkspaceGitPlan.AuthorName &&
            observed.AuthorEmail==WorkspaceGitPlan.AuthorEmail &&
            observed.CommitUnixTime==workflow.CommitUnixTime &&
            observed.FileCount==project.Files.Length &&
            observed.CleanAfterCommit && observed.ObjectIntegrityObserved;
    }
    private static bool IsObjectId(string? value)=>value?.Length==40 && value.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f');
    internal static string BlobId(byte[] input)=>Convert.ToHexString(SHA1.HashData(Encoding.ASCII.GetBytes("blob "+input.Length+"\0").Concat(input).ToArray())).ToLowerInvariant();
    internal static GitToolchainReport RunChild(ResourceProbePlan plan,string workspace)
    {
        bool hashMatched=false,committed=false,denied=false,allPackagesDenied=false;string? commit=null;int? denialExit=null,allPackagesExit=null;var stage="VERIFY_GIT_INPUTS";
        try
        {
            if(plan.GitAssetSetSHA256!=AssetSetSHA256)throw WfpNative.Contract("GitResourcePlanMismatch");
            foreach(var asset in Assets)
            {
                // The manager holds the ancestry and each complete asset.
                // This side performs ordinary file I/O, no privileged metadata.
                using var file=File.OpenRead(WindowsPathSeal.Child(plan.GitDirectory,asset.Name));
                if(file.Length is <1 or >16*1024*1024 || Convert.ToHexString(SHA256.HashData(file))!=asset.Hash)throw WfpNative.Contract("ChildGitAssetChanged");
            }
            var selectedProject=WorkspaceBundle.Parse(plan.ProjectBundle);
            if(selectedProject.GitPlan is { } workflow)return RunWorkflowChild(plan,workspace,selectedProject,workflow);
            AssertGitControlReady(workspace,false);
            stage="HASH_INPUT_WITH_INSPECTED_GIT";
            using(var process=AtomicChild.StartInheritedTool(Start(workspace,plan.GitDirectory,"hash-object","--stdin")))
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
            var template=GitControlPath(workspace,"empty-git-template");
            var project=WorkspaceBundle.Parse(plan.ProjectBundle);
            foreach(var file in project.Files)
                if(!File.ReadAllBytes(WindowsPathSeal.Child(repo,file.Path)).AsSpan().SequenceEqual(file.Content))throw WfpNative.Contract("GitProjectInputChanged");
            stage="GIT_INIT";Require(Run(workspace,plan.GitDirectory,"init","--quiet","--initial-branch=qualification","--template="+template,repo));
            // Highest-precedence info attributes override project-controlled
            // transformations. Data processing preserves exact selected bytes,
            // independent of .gitattributes or .gitignore in the source bundle.
            var info=WindowsPathSeal.Child(repo,".git/info");Directory.CreateDirectory(info);
            File.WriteAllText(WindowsPathSeal.Child(info,"attributes"),"* -text -filter -ident -working-tree-encoding !diff !whitespace\n",new UTF8Encoding(false));
            // NUL pathspec input avoids Windows command-line length limits
            // for a real multi-file project. Validated ASCII names cannot
            // contain NUL or Git pathspec magic; no expansion is performed.
            var selection=WindowsPathSeal.Child(WindowsPathSeal.Child(repo,".git"),"cpc-selected-paths.bin");
            File.WriteAllBytes(selection,Encoding.ASCII.GetBytes(string.Join('\0',project.Files.Select(f=>f.Path))+"\0"));
            stage="GIT_ADD";Require(Run(workspace,plan.GitDirectory,"--literal-pathspecs","-C",repo,"add","--force","--pathspec-from-file="+selection,"--pathspec-file-nul"));
            stage="GIT_COMMIT";Require(Run(workspace,plan.GitDirectory,"-C",repo,"commit","--quiet","--no-gpg-sign","-m",CommitMessage));
            stage="READ_COMMIT";var head=Run(workspace,plan.GitDirectory,"-C",repo,"rev-parse","--verify","HEAD");Require(head);commit=head.Out.Trim();
            if(!IsObjectId(commit))throw WfpNative.Contract("GitHeadMissing");
            // The trusted owner verifies every committed blob and complete
            // tree below. Text-decoding `git show` cannot prove binary data.
            committed=true;
            stage="GIT_PRIVATE_FIXTURE_DENIAL";var negative=Run(workspace,plan.GitDirectory,"hash-object","--",plan.Fixture);denialExit=negative.Exit;
            denied=negative.Exit==128 && negative.Out.Length==0 && negative.Error.TrimEnd().EndsWith(": Permission denied",StringComparison.Ordinal);
            if(!denied)throw WfpNative.Contract("GitPrivateFixtureDenialNotConfirmed");
            stage="GIT_ALL_PACKAGES_FIXTURE_DENIAL";var aap=Run(workspace,plan.GitDirectory,"hash-object","--",WindowsPathSeal.Child(workspace,"all-packages-only.json"));allPackagesExit=aap.Exit;
            allPackagesDenied=aap.Exit==128 && aap.Out.Length==0 && aap.Error.TrimEnd().EndsWith(": Permission denied",StringComparison.Ordinal);
            if(!allPackagesDenied)throw WfpNative.Contract("GitAllPackagesFixtureDenialNotConfirmed");
            return new(hashMatched,committed,commit,denied,denialExit,allPackagesDenied,allPackagesExit,null,null,null);
        }
        catch(Exception ex){return new(hashMatched,committed,commit,denied,denialExit,allPackagesDenied,allPackagesExit,stage+(ex.Data["Stage"] is string nativeStage?"/"+nativeStage:""),ex.GetType().Name,ex is System.ComponentModel.Win32Exception native?native.NativeErrorCode:ex.HResult);}
    }
    private static GitToolchainReport RunWorkflowChild(ResourceProbePlan plan,string workspace,WorkspaceBundle project,WorkspaceGitPlan workflow)
    {
        bool hashMatched=false,committed=false,denied=false,allPackagesDenied=false;string? commitId=null;
        int? denialExit=null,allPackagesExit=null;var stage="VERIFY_GIT_WORKFLOW_INPUT";
        try
        {
            AssertGitControlReady(workspace,true);
            var commands=WorkflowCommands(plan,workspace,workflow);
            stage="HASH_INPUT_WITH_INSPECTED_GIT";
            using(var process=AtomicChild.StartInheritedTool(StartWorkflow(workspace,plan.GitDirectory,workflow,commands[0])))
            {
                var stdout=ReadBounded(process.StandardOutput,4096);var stderr=ReadBounded(process.StandardError,4096);
                Signal(workspace,"git-ready",plan.Nonce);var clock=Stopwatch.StartNew();
                while(!File.Exists(WindowsPathSeal.Child(workspace,"git-go.signal")))
                {
                    if(process.HasExited){RecordResult(workspace,Finish(process,stdout,stderr));throw WfpNative.Contract("GitExitedBeforeInputAdmission");}
                    if(clock.ElapsedMilliseconds>=8000)throw WfpNative.Contract("GitInspectionGateExpired");Thread.Sleep(20);
                }
                if(File.ReadAllText(WindowsPathSeal.Child(workspace,"git-go.txt"))!=plan.Nonce)throw WfpNative.Contract("GitGateBindingMismatch");
                process.StandardInput.Write(Encoding.UTF8.GetString(plan.Input));process.StandardInput.Close();
                var result=Finish(process,stdout,stderr);RecordResult(workspace,result);Require(result);
                hashMatched=result.Exit==0 && result.Out.Trim()==BlobId(plan.Input) && result.Error.Length==0;
                if(!hashMatched)throw WfpNative.Contract("GitInputHashMismatch");
            }
            var repo=WindowsPathSeal.Child(workspace,"git-project");
            foreach(var file in project.Files)
                if(!File.ReadAllBytes(WindowsPathSeal.Child(repo,file.Path)).AsSpan().SequenceEqual(file.Content))
                    throw WfpNative.Contract("GitProjectInputChanged");
            if(!SelectedPathspecMatches(workspace,project))throw WfpNative.Contract("GitPathspecInputMismatch");
            stage="GIT_INIT";RequireWorkflow(RunWorkflow(workspace,plan.GitDirectory,workflow,commands[1]));
            stage="GIT_PREPARE_ATTRIBUTES";
            var info=WindowsPathSeal.Child(repo,".git/info");Directory.CreateDirectory(info);
            File.WriteAllText(WindowsPathSeal.Child(info,"attributes"),"* -text -filter -ident -working-tree-encoding !diff !whitespace\n",new UTF8Encoding(false));
            stage="GIT_ADD";RequireWorkflow(RunWorkflow(workspace,plan.GitDirectory,workflow,commands[2]));
            stage="GIT_DIFF_CHECK";var check=RunWorkflow(workspace,plan.GitDirectory,workflow,commands[3]);RequireWorkflow(check);
            if(check.Out.Length!=0)throw WfpNative.Contract("GitWhitespaceCheckOutputUnexpected");
            stage="GIT_DIFF_NUMSTAT";var numstat=RunWorkflow(workspace,plan.GitDirectory,workflow,commands[4]);RequireWorkflow(numstat);
            var metrics=ParseNumstat(numstat.Out,project);
            stage="GIT_COMMIT";var commit=RunWorkflow(workspace,plan.GitDirectory,workflow,commands[5]);RequireWorkflow(commit);
            if(commit.Out.Length!=0)throw WfpNative.Contract("GitCommitOutputUnexpected");
            stage="GIT_LOG";var log=RunWorkflow(workspace,plan.GitDirectory,workflow,commands[6]);RequireWorkflow(log);
            var fields=log.Out.TrimEnd('\r','\n').Split('\0');
            if(fields.Length!=6 || !IsObjectId(fields[0]) || !IsObjectId(fields[1]) ||
                fields[2]!=WorkspaceGitPlan.AuthorName || fields[3]!=WorkspaceGitPlan.AuthorEmail ||
                !long.TryParse(fields[4],System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out var commitTime) ||
                commitTime!=workflow.CommitUnixTime || fields[5]!=workflow.CommitMessage)
                throw WfpNative.Contract("GitWorkflowCommitMetadataMismatch");
            commitId=fields[0];var treeId=fields[1];committed=true;
            stage="GIT_STATUS_AFTER_COMMIT";var after=RunWorkflow(workspace,plan.GitDirectory,workflow,commands[7]);RequireWorkflow(after);
            var clean=after.Out.Length==0;
            if(!clean)throw WfpNative.Contract("GitWorkflowWorktreeNotClean");
            stage="GIT_OBJECT_INTEGRITY";var fsck=RunWorkflow(workspace,plan.GitDirectory,workflow,commands[8]);RequireWorkflow(fsck);
            if(fsck.Out.Length!=0 || fsck.Error.Length!=0)throw WfpNative.Contract("GitObjectIntegrityOutputUnexpected");
            stage="GIT_PRIVATE_FIXTURE_DENIAL";var negative=RunWorkflow(workspace,plan.GitDirectory,workflow,commands[9]);denialExit=negative.Exit;
            denied=negative.Exit==128 && negative.Out.Length==0 && negative.Error.TrimEnd().EndsWith(": Permission denied",StringComparison.Ordinal);
            if(!denied)throw WfpNative.Contract("GitPrivateFixtureDenialNotConfirmed");
            stage="GIT_ALL_PACKAGES_FIXTURE_DENIAL";var aap=RunWorkflow(workspace,plan.GitDirectory,workflow,commands[10]);allPackagesExit=aap.Exit;
            allPackagesDenied=aap.Exit==128 && aap.Out.Length==0 && aap.Error.TrimEnd().EndsWith(": Permission denied",StringComparison.Ordinal);
            if(!allPackagesDenied)throw WfpNative.Contract("GitAllPackagesFixtureDenialNotConfirmed");
            var observation=new GitWorkflowObservation(WorkspaceBundle.GitPlanHash(workflow),workflow.BranchName,commitId,treeId,
                workflow.CommitMessage,WorkspaceGitPlan.AuthorName,WorkspaceGitPlan.AuthorEmail,commitTime,project.Files.Length,
                metrics.AddedLines,metrics.DeletedLines,metrics.BinaryFiles,clean,true);
            return new(hashMatched,committed,commitId,denied,denialExit,allPackagesDenied,allPackagesExit,null,null,null){Workflow=observation};
        }
        catch(Exception ex)
        {
            return new(hashMatched,committed,commitId,denied,denialExit,allPackagesDenied,allPackagesExit,
                stage+(ex.Data["Stage"] is string nativeStage?"/"+nativeStage:""),ex.GetType().Name,
                ex is System.ComponentModel.Win32Exception native?native.NativeErrorCode:ex.HResult);
        }
    }
    private static (int AddedLines,int DeletedLines,int BinaryFiles) ParseNumstat(string output,WorkspaceBundle project)
    {
        var records=output.Split('\0',StringSplitOptions.RemoveEmptyEntries);
        if(records.Length!=project.Files.Length)throw WfpNative.Contract("GitNumstatInventoryMismatch");
        var expected=project.Files.Select(f=>f.Path).ToHashSet(StringComparer.Ordinal);
        int added=0,deleted=0,binary=0;
        foreach(var record in records)
        {
            var first=record.IndexOf('\t');var second=first<0?-1:record.IndexOf('\t',first+1);
            if(first<1 || second<=first+1 || second==record.Length-1)throw WfpNative.Contract("GitNumstatRecordMalformed");
            var add=record[..first];var remove=record[(first+1)..second];var path=record[(second+1)..];
            if(!expected.Remove(path))throw WfpNative.Contract("GitNumstatPathMismatch");
            if(add=="-" && remove=="-"){binary++;continue;}
            if(!int.TryParse(add,System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out var a) ||
                !int.TryParse(remove,System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out var d) ||
                a<0 || d<0 || added>100000000-a || deleted>100000000-d)throw WfpNative.Contract("GitNumstatCountBounds");
            added+=a;deleted+=d;
        }
        if(expected.Count!=0)throw WfpNative.Contract("GitNumstatFilesMissing");
        return(added,deleted,binary);
    }
    private static (int Exit,string Out,string Error) RunWorkflow(string workspace,string directory,WorkspaceGitPlan workflow,params string[] args)
    {
        using var process=AtomicChild.StartInheritedTool(StartWorkflow(workspace,directory,workflow,args));process.StandardInput.Close();
        var result=Finish(process,ReadBounded(process.StandardOutput,256*1024),ReadBounded(process.StandardError,64*1024));
        RecordResult(workspace,result);return result;
    }
    private static async Task<string> ReadBounded(StreamReader reader,int maximum)
    {
        var text=new StringBuilder();var buffer=new char[4096];
        while(true)
        {
            var count=await reader.ReadAsync(buffer.AsMemory());
            if(count==0)return text.ToString();
            if(text.Length+count>maximum)throw WfpNative.Contract("GitWorkflowOutputBounds");
            text.Append(buffer,0,count);
        }
    }
    private static void RequireWorkflow((int Exit,string Out,string Error) result)
    {if(result.Exit!=0 || result.Error.Length!=0)throw WfpNative.Contract("GitWorkflowCommandFailed");}
    private static void Signal(string workspace,string stem,string nonce)
    {
        File.WriteAllText(WindowsPathSeal.Child(workspace,stem+".txt"),nonce,new UTF8Encoding(false));
        File.WriteAllText(WindowsPathSeal.Child(workspace,stem+".signal"),"");
    }
    internal static ProcessStartInfo Start(string workspace,string directory,params string[] arguments)
    {
        var start=new ProcessStartInfo(WindowsPathSeal.Child(directory,"git.exe")){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=workspace,
            RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardInputEncoding=new UTF8Encoding(false),StandardOutputEncoding=new UTF8Encoding(false),StandardErrorEncoding=new UTF8Encoding(false)};
        start.Environment.Clear();
        foreach(var name in new[]{"SystemRoot","windir","SystemDrive","PROCESSOR_ARCHITECTURE"})
        {var value=Environment.GetEnvironmentVariable(name);if(value is not null)start.Environment[name]=value;}
        foreach(var name in new[]{"TEMP","TMP","HOME","USERPROFILE","LOCALAPPDATA","XDG_CONFIG_HOME"})start.Environment[name]=workspace;
        start.Environment["PATH"]=directory+";"+Environment.SystemDirectory;
        start.Environment["GIT_EXEC_PATH"]=directory;start.Environment["GIT_CONFIG_NOSYSTEM"]="1";start.Environment["GIT_ATTR_NOSYSTEM"]="1";
        start.Environment["GIT_CONFIG_GLOBAL"]=GitControlPath(workspace,"empty-git-config");start.Environment["GIT_CONFIG_COUNT"]="0";
        start.Environment["GIT_CEILING_DIRECTORIES"]=workspace;start.Environment["GIT_DISCOVERY_ACROSS_FILESYSTEM"]="0";
        start.Environment["GIT_TERMINAL_PROMPT"]="0";start.Environment["GCM_INTERACTIVE"]="never";start.Environment["GIT_NO_LAZY_FETCH"]="1";
        foreach(var name in new[]{"GIT_AUTHOR_NAME","GIT_COMMITTER_NAME"})start.Environment[name]="CPC Qualification";
        foreach(var name in new[]{"GIT_AUTHOR_EMAIL","GIT_COMMITTER_EMAIL"})start.Environment[name]="offline@invalid.example";
        foreach(var name in new[]{"GIT_AUTHOR_DATE","GIT_COMMITTER_DATE"})start.Environment[name]="2026-10-28T00:00:00+00:00";
        start.Environment["LC_ALL"]="C";start.Environment["LANG"]="C";
        foreach(var arg in new[]{"--no-pager","-c","credential.helper=","-c","protocol.allow=never","-c","core.autocrlf=false","-c","core.whitespace=cr-at-eol","-c","core.filemode=false",
            "-c","core.fsmonitor=false","-c","maintenance.auto=false","-c","gc.auto=0","-c","commit.gpgsign=false","-c","i18n.commitEncoding=UTF-8",
            "-c","core.hooksPath="+GitControlPath(workspace,"empty-git-hooks"),"-c","safe.directory="+WindowsPathSeal.Child(workspace,"git-project")}.Concat(arguments))start.ArgumentList.Add(arg);
        return start;
    }
    internal static ProcessStartInfo StartWorkflow(string workspace,string directory,WorkspaceGitPlan workflow,params string[] arguments)
    {
        workflow.Validate();var start=Start(workspace,directory,arguments);
        foreach(var name in new[]{"GIT_AUTHOR_NAME","GIT_COMMITTER_NAME"})start.Environment[name]=WorkspaceGitPlan.AuthorName;
        foreach(var name in new[]{"GIT_AUTHOR_EMAIL","GIT_COMMITTER_EMAIL"})start.Environment[name]=WorkspaceGitPlan.AuthorEmail;
        foreach(var name in new[]{"GIT_AUTHOR_DATE","GIT_COMMITTER_DATE"})start.Environment[name]=workflow.CommitDateUtc;
        return start;
    }
    internal static string GitControlDirectory(string workspace)=>WindowsPathSeal.Child(workspace,"git-control");
    internal static string GitControlPath(string workspace,string leaf)
    {
        if(leaf is not ("empty-git-config" or "empty-git-hooks" or "empty-git-template" or "git-selected-paths.bin"))
            throw new InvalidDataException("Fixed Git control leaf required");
        return WindowsPathSeal.Child(GitControlDirectory(workspace),leaf);
    }
    internal static void AssertGitControlReady(string workspace,bool hasPathspec)
    {
        var root=GitControlDirectory(workspace);
        using(var held=WindowsPathSeal.Open(root,true,false))
        {
            var actual=WindowsPathSeal.EnumerateNames(held,root,8);
            var expected=hasPathspec
                ?new[]{"empty-git-config","empty-git-hooks","empty-git-template","git-selected-paths.bin"}
                :new[]{"empty-git-config","empty-git-hooks","empty-git-template"};
            if(actual.Length!=expected.Length || actual.Any(name=>!expected.Contains(name,StringComparer.Ordinal)))
                throw WfpNative.Contract("GitControlInventoryMismatch");
        }
        foreach(var leaf in new[]{"empty-git-hooks","empty-git-template"})
        {
            var path=GitControlPath(workspace,leaf);
            using var directory=WindowsPathSeal.Open(path,true,false);
            if(WindowsPathSeal.EnumerateNames(directory,path,1).Length!=0)
                throw WfpNative.Contract("GitControlDirectoryNotEmpty");
        }
        var config=GitControlPath(workspace,"empty-git-config");
        using(var file=new FileStream(WindowsPathSeal.Open(config,false,true),FileAccess.Read,64,false))
            if(file.Length!=0)throw WfpNative.Contract("GitGlobalConfigNotEmpty");
        if(hasPathspec)
        {
            using var file=new FileStream(WindowsPathSeal.Open(GitControlPath(workspace,"git-selected-paths.bin"),false,true),FileAccess.Read,128*1024,false);
            if(file.Length is <1 or >128*1024)throw WfpNative.Contract("GitPathspecBounds");
        }
    }
    internal static string[][] WorkflowCommands(ResourceProbePlan plan,string workspace,WorkspaceGitPlan workflow)
    {
        workflow.Validate();var repo=WindowsPathSeal.Child(workspace,"git-project");
        var template=GitControlPath(workspace,"empty-git-template");
        var selection=GitControlPath(workspace,"git-selected-paths.bin");
        return new[]{
            new[]{"hash-object","--stdin"},
            new[]{"init","--quiet","--initial-branch=main","--object-format=sha1","--template="+template,repo},
            new[]{"--literal-pathspecs","-C",repo,"add","--force","--pathspec-from-file="+selection,"--pathspec-file-nul"},
            new[]{"-C",repo,"diff","--cached","--check","--no-ext-diff","--no-textconv","--no-color"},
            new[]{"-C",repo,"diff","--cached","--numstat","-z","--no-ext-diff","--no-textconv","--no-color"},
            new[]{"-C",repo,"commit","--quiet","--no-gpg-sign","-m",workflow.CommitMessage},
            new[]{"-C",repo,"log","-1","--format=%H%x00%T%x00%an%x00%ae%x00%at%x00%s","HEAD"},
            new[]{"-C",repo,"status","--porcelain=v2","-z","--untracked-files=all"},
            new[]{"-C",repo,"fsck","--full","--strict","--no-reflogs","--no-progress"},
            new[]{"hash-object","--",plan.Fixture},
            new[]{"hash-object","--",WindowsPathSeal.Child(workspace,"all-packages-only.json")}
        };
    }
    internal static bool SelectedPathspecMatches(string workspace,WorkspaceBundle project)
    {
        var path=GitControlPath(workspace,"git-selected-paths.bin");
        var expected=Encoding.ASCII.GetBytes(string.Join('\0',project.Files.Select(f=>f.Path))+"\0");
        using var file=new FileStream(WindowsPathSeal.OpenReadUnderWriteLease(path),FileAccess.Read,4096,false);
        if(file.Length!=expected.Length)return false;
        var actual=new byte[expected.Length];file.ReadExactly(actual);return actual.AsSpan().SequenceEqual(expected);
    }
    internal static bool WorkflowCommandAllowed(ResourceProbePlan plan,string workspace,string[] tail)
    {
        var project=WorkspaceBundle.Parse(plan.ProjectBundle);var workflow=project.GitPlan;
        if(workflow is null)return false;
        AssertGitControlReady(workspace,true);
        var commands=WorkflowCommands(plan,workspace,workflow);
        if(!commands.Any(command=>command.SequenceEqual(tail)))return false;
        return !commands[2].SequenceEqual(tail) || SelectedPathspecMatches(workspace,project);
    }
    internal static bool WorkflowSequenceMatches(ResourceProbePlan plan,string workspace,int sequence,string[] arguments)
    {
        var project=WorkspaceBundle.Parse(plan.ProjectBundle);var workflow=project.GitPlan;
        if(workflow is null)return true;
        var prefix=StartWorkflow(workspace,plan.GitDirectory,workflow).ArgumentList.ToArray();
        if(arguments.Length<prefix.Length || !arguments.Take(prefix.Length).SequenceEqual(prefix))return false;
        var tail=arguments.Skip(prefix.Length).ToArray();var commands=WorkflowCommands(plan,workspace,workflow);
        return sequence>=1 && sequence<=commands.Length && commands[sequence-1].SequenceEqual(tail) &&
            WorkflowCommandAllowed(plan,workspace,tail);
    }
    internal static ProcessStartInfo StartIndependentInit(string workspace) =>
        Start(workspace,DirectoryPath,"init","--quiet","--template=","--initial-branch=cpc-offline","git-project");

    internal static ProcessStartInfo StartIndependentCommit(string workspace) =>
        Start(workspace,DirectoryPath,"-C",WindowsPathSeal.Child(workspace,"git-project"),"commit","--quiet","--no-gpg-sign","-a","-m",CommitMessage);

    private static WorkspaceBundle IndependentCommitFiles()=>WorkspaceBundle.Create(new (string,byte[])[]{
        ("note.txt","edited by the fixed qualification fixture\n"u8.ToArray()),
        ("sample/payload.bin",new byte[]{0,13,10,0xff,0x80,1})
    });

    internal static void PrepareIndependentCommit(string workspace)
    {
        var repository=WindowsPathSeal.Child(workspace,"git-project");
        var metadata=WindowsPathSeal.Child(repository,".git");
        Directory.CreateDirectory(WindowsPathSeal.Child(metadata,"refs/heads"));
        WriteNew(WindowsPathSeal.Child(metadata,"HEAD"),"ref: refs/heads/qualification\n"u8);
        WriteNew(WindowsPathSeal.Child(metadata,"config"),
            "[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n\tlogallrefupdates = false\n"u8);

        // Git index v2 with deliberately stale stat data. Both paths start
        // tracked at the same baseline blob, then commit -a must stage the
        // different worktree bytes. This fixture needs only one Git process.
        var baseline="baseline\n"u8.ToArray();
        var baselineId=BlobId(baseline);
        var objectDirectory=Directory.CreateDirectory(WindowsPathSeal.Child(metadata,"objects/"+baselineId[..2])).FullName;
        using(var output=new FileStream(WindowsPathSeal.Child(objectDirectory,baselineId[2..]),FileMode.CreateNew,FileAccess.Write,FileShare.None))
        using(var encoder=new ZLibStream(output,CompressionLevel.Fastest))
        {
            encoder.Write(Encoding.ASCII.GetBytes("blob "+baseline.Length+"\0"));
            encoder.Write(baseline);
        }

        var files=IndependentCommitFiles().Files;
        using var index=new MemoryStream();
        index.Write("DIRC"u8);
        Span<byte> integer=stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(integer,2);
        index.Write(integer);
        BinaryPrimitives.WriteInt32BigEndian(integer,files.Length);
        index.Write(integer);
        Span<byte> entry=stackalloc byte[62];
        entry.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(entry[24..],0x81a4); // regular file, mode 0644
        BinaryPrimitives.WriteInt32BigEndian(entry[36..],baseline.Length);
        Convert.FromHexString(baselineId).CopyTo(entry[40..]);
        foreach(var file in files)
        {
            var path=WindowsPathSeal.Child(repository,file.Path);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            WriteNew(path,file.Content);
            var name=Encoding.ASCII.GetBytes(file.Path);
            BinaryPrimitives.WriteUInt16BigEndian(entry[60..],checked((ushort)name.Length));
            index.Write(entry);
            index.Write(name);
            index.Write(new byte[8-(entry.Length+name.Length)%8]);
        }
        index.Write(SHA1.HashData(index.GetBuffer().AsSpan(0,checked((int)index.Length))));
        WriteNew(WindowsPathSeal.Child(metadata,"index"),index.ToArray());
    }

    private static void WriteNew(string path,ReadOnlySpan<byte> bytes)
    {
        using var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None);
        output.Write(bytes);
    }

    internal static bool IndependentCommitObserved(string workspace)
    {
        using var repository=WindowsPathSeal.LockDirectory(WindowsPathSeal.Child(workspace,"git-project/.git"),PathPolicy.Source);
        using var head=new FileStream(WindowsPathSeal.Open(WindowsPathSeal.Child(repository.Path,"HEAD"),false,true),FileAccess.Read);
        ReadOnlySpan<byte> expected="ref: refs/heads/qualification\n"u8;
        if(head.Length!=expected.Length)return false;
        Span<byte> content=stackalloc byte[expected.Length];
        head.ReadExactly(content);
        if(!expected.SequenceEqual(content))return false;
        AssertCommit(workspace,IndependentCommitFiles(),ReadQualificationRef(workspace));
        repository.AssertHeld();
        return true;
    }

    internal static bool IndependentInitObserved(string workspace)
    {
        using var repository=WindowsPathSeal.LockDirectory(WindowsPathSeal.Child(workspace,"git-project/.git"),PathPolicy.Source);
        using var objects=WindowsPathSeal.LockDirectory(WindowsPathSeal.Child(repository.Path,"objects"),PathPolicy.Source);
        using var refs=WindowsPathSeal.LockDirectory(WindowsPathSeal.Child(repository.Path,"refs/heads"),PathPolicy.Source);
        using var head=new FileStream(WindowsPathSeal.Open(WindowsPathSeal.Child(repository.Path,"HEAD"),false,true),FileAccess.Read);
        ReadOnlySpan<byte> expected="ref: refs/heads/cpc-offline\n"u8;
        if(head.Length!=expected.Length)return false;
        Span<byte> content=stackalloc byte[expected.Length];
        head.ReadExactly(content);
        repository.AssertHeld();objects.AssertHeld();refs.AssertHeld();
        return expected.SequenceEqual(content);
    }
    private static (int Exit,string Out,string Error) Run(string workspace,string directory,params string[] args)
    {
        using var process=AtomicChild.StartInheritedTool(Start(workspace,directory,args));process.StandardInput.Close();
        var result=Finish(process,SessionResources.ReadBounded(process.StandardOutput),SessionResources.ReadBounded(process.StandardError));
        RecordResult(workspace,result);return result;
    }
    private static void RecordResult(string workspace,(int Exit,string Out,string Error) result)=>
        File.WriteAllText(WindowsPathSeal.Child(workspace,"git-last-result.json"),JsonSerializer.Serialize(new {
            ExitCode=result.Exit,Stdout=result.Out[..Math.Min(result.Out.Length,8192)],Stderr=result.Error[..Math.Min(result.Error.Length,8192)],
            StdoutLength=result.Out.Length,StderrLength=result.Error.Length,Truncated=result.Out.Length>8192 || result.Error.Length>8192}),new UTF8Encoding(false));
    private static (int Exit,string Out,string Error) Finish(AtomicChild.InheritedTool process,Task<string> stdout,Task<string> stderr)
    {
        if(!process.WaitForExit(8000))throw WfpNative.Contract("FixedGitDeadlineExpired");
        return(process.ExitCode,stdout.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult(),stderr.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult());
    }
    private static void Require((int Exit,string Out,string Error) result)
    {if(result.Exit!=0 || result.Error.Length!=0)throw WfpNative.Contract("FixedGitCommandFailed");}
    internal static WorkspaceGitReceipt? AssertRepository(string workspace,ResourceProbePlan plan,GitToolchainReport report)
    {
        if(!QualifiedForPlan(plan,report))throw WfpNative.Contract("GitToolchainReportRefused");
        var project=WorkspaceBundle.Parse(plan.ProjectBundle);
        if(project.GitPlan is { } workflow)
        {
            var observed=report.Workflow??throw WfpNative.Contract("GitWorkflowObservationMissing");
            if(observed.PlanSHA256!=WorkspaceBundle.GitPlanHash(workflow) || observed.BranchName!=workflow.BranchName ||
                observed.CommitId!=report.CommitId || observed.CommitMessage!=workflow.CommitMessage ||
                observed.AuthorName!=WorkspaceGitPlan.AuthorName || observed.AuthorEmail!=WorkspaceGitPlan.AuthorEmail ||
                observed.CommitUnixTime!=workflow.CommitUnixTime || observed.FileCount!=project.Files.Length ||
                !observed.CleanAfterCommit || !observed.ObjectIntegrityObserved)
                throw WfpNative.Contract("GitWorkflowObservationBindingMismatch");
            var verifiedTree=AssertCommit(workspace,project,report.CommitId!,workflow);
            if(observed.TreeId!=verifiedTree || ReadHead(workspace)!="ref: refs/heads/"+workflow.BranchName+"\n" ||
                ReadBranchRef(workspace,workflow.BranchName)!=report.CommitId)throw WfpNative.Contract("GitWorkflowBranchRefMismatch");
            var receipt=new WorkspaceGitReceipt(1,observed.PlanSHA256,observed.BranchName,observed.CommitId,observed.TreeId,
                observed.CommitMessage,observed.AuthorName,observed.AuthorEmail,observed.CommitUnixTime,observed.FileCount,
                observed.AddedLines,observed.DeletedLines,observed.BinaryFileCount,true,true);
            receipt.Validate();return receipt;
        }
        if(report.Workflow is not null)throw WfpNative.Contract("UnexpectedGitWorkflowObservation");
        AssertCommit(workspace,project,report.CommitId!);
        if(ReadQualificationRef(workspace)!=report.CommitId)throw WfpNative.Contract("GitBranchRefMismatch");
        return null;
    }

    private static string AssertCommit(string workspace,WorkspaceBundle project,string commitId,WorkspaceGitPlan? workflow=null)
    {
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
        var commit=ReadObject(commitId);var zero=Array.IndexOf(commit,(byte)0);
        if(zero is <1 or >32 || !Encoding.ASCII.GetString(commit,0,zero).Equals("commit "+(commit.Length-zero-1),StringComparison.Ordinal))throw WfpNative.Contract("GitCommitObjectRefused");
        var body=Encoding.UTF8.GetString(commit,zero+1,commit.Length-zero-1);
        if(body.Length<46 || !body.StartsWith("tree ",StringComparison.Ordinal) || body[45]!='\n')throw WfpNative.Contract("GitCommitTreeMissing");
        var stamp=(workflow?.CommitUnixTime??new DateTimeOffset(2026,10,28,0,0,0,TimeSpan.Zero).ToUnixTimeSeconds()).ToString(System.Globalization.CultureInfo.InvariantCulture);
        var author=workflow is null?"CPC Qualification":WorkspaceGitPlan.AuthorName;
        var email=workflow is null?"offline@invalid.example":WorkspaceGitPlan.AuthorEmail;
        var message=workflow?.CommitMessage??CommitMessage;
        var identity=author+" <"+email+"> "+stamp+" +0000\n";
        if(body!="tree "+body.Substring(5,40)+"\nauthor "+identity+"committer "+identity+"\n"+message+"\n")
            throw WfpNative.Contract("GitCommitIdentityOrMetadataMismatch");
        if(body.Substring(5,40)!=expectedTree)throw WfpNative.Contract("GitCommitWorkspaceTreeMismatch");
        return expectedTree;
    }

    private static string ReadQualificationRef(string workspace)=>ReadBranchRef(workspace,"qualification");
    private static string ReadBranchRef(string workspace,string branch)
    {
        if(branch is not ("qualification" or "main"))throw WfpNative.Contract("GitBranchNameRefused");
        using var refParent=WindowsPathSeal.LockDirectory(WindowsPathSeal.Child(workspace,"git-project/.git/refs/heads"),PathPolicy.Source);
        using var reference=new FileStream(WindowsPathSeal.Open(WindowsPathSeal.Child(refParent.Path,branch),false,true),FileAccess.Read,128,false);
        if(reference.Length!=41)throw WfpNative.Contract("GitBranchRefBounds");var data=new byte[41];reference.ReadExactly(data);
        var id=Encoding.ASCII.GetString(data,0,40);
        if(data[40]!='\n' || !IsObjectId(id))throw WfpNative.Contract("GitBranchRefMismatch");
        return id;
    }
    private static string ReadHead(string workspace)
    {
        using var head=new FileStream(WindowsPathSeal.Open(WindowsPathSeal.Child(workspace,"git-project/.git/HEAD"),false,true),FileAccess.Read,128,false);
        if(head.Length is <1 or >64)throw WfpNative.Contract("GitHeadBounds");
        using var reader=new StreamReader(head,Encoding.ASCII,false,128,true);return reader.ReadToEnd();
    }
}
