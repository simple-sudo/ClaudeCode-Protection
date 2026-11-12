using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

// Personal-machine deployment assumption, like the current FlClash path.
// Only these reviewed installed Git bytes are allowed; an update requires new
// qualification. No host Git configuration, credentials, hooks or remote URL
// is imported. Git always executes inside the existing confined child/Job.
internal sealed partial class SessionGitToolchain : IDisposable
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
        if(observed is null)return false;
        var metrics=ExpectedWorkflowMetrics(project);
        return observed.PlanSHA256==WorkspaceBundle.GitPlanHash(workflow) &&
            observed.BranchName==workflow.BranchName &&
            observed.CommitId==value.CommitId &&
            observed.CommitMessage==workflow.CommitMessage &&
            observed.AuthorName==WorkspaceGitPlan.AuthorName &&
            observed.AuthorEmail==WorkspaceGitPlan.AuthorEmail &&
            observed.CommitUnixTime==workflow.CommitUnixTime &&
            observed.FileCount==project.Files.Length &&
            observed.AddedLines==metrics.AddedLines &&
            observed.DeletedLines==metrics.DeletedLines &&
            observed.BinaryFileCount==metrics.BinaryFiles &&
            observed.CleanAfterCommit && observed.ObjectIntegrityObserved;
    }
    private static (int AddedLines,int DeletedLines,int BinaryFiles) ExpectedWorkflowMetrics(WorkspaceBundle project)
    {
        // The pinned Git diff implementation probes the first 8000 bytes for
        // NUL before classifying a blob as binary. With the trusted info
        // attributes disabling text/filters, every selected path is an
        // addition from an empty baseline and therefore has zero deletions.
        const int binaryProbeBytes=8000;
        int added=0,binary=0;
        foreach(var file in project.Files)
        {
            var content=file.Content;
            if(content.AsSpan(0,Math.Min(content.Length,binaryProbeBytes)).IndexOf((byte)0)>=0)
            {binary++;continue;}
            var lines=0;
            foreach(var valueByte in content)if(valueByte==(byte)'\n')lines++;
            if(content.Length>0 && content[^1]!=(byte)'\n')lines++;
            added=checked(added+lines);
        }
        return(added,0,binary);
    }
    private static bool IsObjectId(string? value)=>value?.Length==40 && value.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f');
    internal static string BlobId(byte[] input)=>Convert.ToHexString(SHA1.HashData(Encoding.ASCII.GetBytes("blob "+input.Length+"\0").Concat(input).ToArray())).ToLowerInvariant();
    
}
