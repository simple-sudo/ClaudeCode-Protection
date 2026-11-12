using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal sealed partial class SessionGitToolchain
{
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
