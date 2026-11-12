using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

// The workspace belongs to the freshly created installation profile. No host
// directory ACL is widened, adopted, recursively copied or deleted. It is task
// data, not a trust anchor. All executable inputs remain outside the workspace.
internal sealed partial class SessionResources : IDisposable
{

    private readonly ProtectedState state;
    private readonly PathLease folder;
    private readonly PathLease? gitProjectDirectory,gitControlDirectory;
    private readonly string? gitPackageSid;
    private readonly FileStream input,allPackagesFixture;
    private readonly SessionPowerShellToolchain? tool;
    private readonly SessionGitToolchain? git;
    private readonly FileStream? projectInput;
    private readonly FileStream? gitPathspec;
    private readonly WorkspaceBundle? workspaceBundle;
    private readonly HostPrivacyProbe? privacy;
    private WorkspaceGitReceipt? gitReceipt;
    internal ResourceProbePlan Plan {get;}
    internal string Workspace=>folder.Path;
    private SessionResources(ProtectedState state,PathLease folder,PathLease? gitProjectDirectory,PathLease? gitControlDirectory,
        string? gitPackageSid,FileStream input,SessionPowerShellToolchain? tool,ResourceProbePlan plan,
        SessionGitToolchain? git,FileStream? projectInput,FileStream? gitPathspec,FileStream allPackagesFixture,
        HostPrivacyProbe? privacy,WorkspaceBundle? workspaceBundle)
    {
        this.state=state;this.folder=folder;this.gitProjectDirectory=gitProjectDirectory;this.gitControlDirectory=gitControlDirectory;
        this.gitPackageSid=gitPackageSid;this.input=input;this.tool=tool;Plan=plan;this.git=git;
        this.projectInput=projectInput;this.gitPathspec=gitPathspec;this.allPackagesFixture=allPackagesFixture;
        this.privacy=privacy;this.workspaceBundle=workspaceBundle;
    }
    internal static SessionResources Create(ProtectedState state,VerifiedVersion version,InstallationProfileLease profile,string nonce,ResourceExecutionIntent intent,byte[]? workspaceInput)
    {
        state.AssertHeld();version.AssertHeld(state);
        ArgumentNullException.ThrowIfNull(intent);intent.AssertInput(workspaceInput);
        using var sid=new InstallationPackageSid(state);profile.AssertPackage(sid);
        if(intent.CallerProject && !intent.DevelopProject)throw WfpNative.Contract("ExplicitCallerCodeTaskRequired");
        if(intent.DevelopProject && (!intent.IncludeGit || workspaceInput is null || !intent.CallerProject && WorkspaceBundle.Hash(workspaceInput)!=BundledProjectDevelopment.BaselineHash))throw WfpNative.Contract("ExplicitBundledProjectTaskRequired");
        var callerTask=intent.CallerProject?CSharpProjectTask.Parse(workspaceInput!):null;
        var tool=workspaceInput is null || intent.DevelopProject?SessionPowerShellToolchain.Open():null;
        PathLease? directory=null,gitProjectDirectory=null,gitControlDirectory=null;
        string? gitPackageSid=null;
        FileStream? input=null,projectInput=null,gitPathspec=null,allPackagesFixture=null;SessionGitToolchain? git=null;
        HostPrivacyProbe? privacy=null;
        try
        {
            var hash=version.Package.Files.Single(f=>f.Asset.Id=="broker-exe").SHA256;
            if(intent.IncludeGit)git=SessionGitToolchain.Open();
            if(intent.DevelopProject)privacy=HostPrivacyProbe.Capture(nonce,state.InstallationId,version.Package.Release);
            var plan=new ResourceProbePlan(intent.DevelopProject?(intent.CallerProject?6:5):3,Identifiers.Hex32(nonce),state.InstallationId,version.Package.Release,Environment.ProcessId,hash,
                intent.IncludeGit?SessionGitToolchain.AssetSetSHA256:null,workspaceInput is null?null:WorkspaceBundle.Hash(workspaceInput),
                WindowsPathSeal.Canonical(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles))){DevelopProject=intent.DevelopProject,HostPrivacySHA256=privacy?.SHA256,CallerProjectKind=callerTask?.Definition.Kind};plan.Validate();
            if(!string.Equals(plan.ExpectedChildImage,Environment.ProcessPath,StringComparison.OrdinalIgnoreCase) || intent.IncludeGit && plan.Workspace("")!=SessionTaskWorkspace.PathFor(nonce))
                throw WfpNative.Contract("ResourceRuntimePathsDifferFromInstalledOwner");
            WorkspaceBundle? project=null;
            if(workspaceInput is not null)
            {
                project=WorkspaceBundle.Parse(workspaceInput);
                if(project.BaseSHA256 is not null || project.Files.Length==0)throw WfpNative.Contract("NonemptyWorkspaceBaselineRequired");
                // Preflight all destination paths before creating profile/task data.
                var taskRoot=SessionTaskWorkspace.PathFor(nonce);
                _=WindowsPathSeal.Child(taskRoot,"git-project");_=WindowsPathSeal.Child(taskRoot,"git-control");
                foreach(var file in project.Files)_=WindowsPathSeal.Child(WindowsPathSeal.Child(taskRoot,"git-project"),file.Path);
            }
            var path=plan.Workspace(sid.Value);
            using var identity=WindowsIdentity.GetCurrent();
            var owner=identity.User?.Value??throw WfpNative.Contract("WorkspaceHumanOwnerMissing");
            if(intent.IncludeGit)
            {
                directory=CreateOwnedTaskDirectory(state,profile,nonce);
                gitPackageSid=sid.Value;
                gitProjectDirectory=GitWorkspaceDescriptor.Create(directory,"git-project",sid.Value,true);
                gitControlDirectory=GitWorkspaceDescriptor.Create(directory,"git-control",sid.Value,false);
            }
            else
            {
                using var parent=WindowsPathSeal.LockDirectory(profile.WorkspaceRoot(),PathPolicy.Source);
                directory=CreateWorkspace(path,owner,sid.Value,false);
            }
            privacy?.Publish(path);
            var inputPath=WindowsPathSeal.Child(path,"input.txt");
            using(var seeded=new FileStream(inputPath,FileMode.CreateNew,FileAccess.Write,FileShare.None)){seeded.Write(plan.Input);seeded.Flush(true);}
            input=new FileStream(WindowsPathSeal.Open(inputPath,false,true),FileAccess.Read,4096,false);
            if(input.Length!=plan.Input.Length || Convert.ToHexString(SHA256.HashData(input))!=Convert.ToHexString(SHA256.HashData(plan.Input)))
                throw WfpNative.Contract("FreshWorkspaceInputChanged");
            input.Position=0;
            allPackagesFixture=CreateAllPackagesFixture(WindowsPathSeal.Child(path,"all-packages-only.json"),identity.User!.Value,plan.Input);
            if(intent.IncludeGit)
            {
                if(workspaceInput is not null)
                {
                    var dataPath=WindowsPathSeal.Child(path,"project-input.json");
                    using(var seeded=new FileStream(dataPath,FileMode.CreateNew,FileAccess.Write,FileShare.None)){seeded.Write(workspaceInput);seeded.Flush(true);}
                    projectInput=new FileStream(WindowsPathSeal.Open(dataPath,false,true),FileAccess.Read);
                    if(WorkspaceBundle.Hash(plan.ProjectBundle)!=plan.WorkspaceInputSHA256)throw WfpNative.Contract("WorkspaceDataPublishChanged");
                }
                var control=gitControlDirectory?.Path??throw WfpNative.Contract("GitControlDirectoryMissing");
                var projectRoot=gitProjectDirectory?.Path??throw WfpNative.Contract("GitProjectDirectoryMissing");
                using(var empty=new FileStream(WindowsPathSeal.Child(control,"empty-git-config"),FileMode.CreateNew,FileAccess.Write,FileShare.None)){empty.Flush(true);}
                Directory.CreateDirectory(WindowsPathSeal.Child(control,"empty-git-template"));
                Directory.CreateDirectory(WindowsPathSeal.Child(control,"empty-git-hooks"));
                WorkspaceFiles.MaterializeContentsNew(projectRoot,plan.ProjectBundle);
                if(project is {GitPlan:not null} gitProject)
                {
                    var selectedPathspec=WindowsPathSeal.Child(control,"git-selected-paths.bin");
                    gitPathspec=new FileStream(selectedPathspec,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.Read);
                    var names=Encoding.ASCII.GetBytes(string.Join('\0',gitProject.Files.Select(f=>f.Path))+"\0");
                    gitPathspec.Write(names);gitPathspec.Flush(true);gitPathspec.Position=0;
                    if(gitPathspec.Length is <1 or >128*1024)throw WfpNative.Contract("GitPathspecLeaseBounds");
                }
                if(workspaceInput is null)state.WriteNew("workspace-input-"+nonce+".json",plan.ProjectBundle);
                else state.StoreWorkspaceData(nonce,false,workspaceInput);
            }
            state.WriteNew("resource-fixture-"+nonce+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,Nonce=nonce,
                Value="CONTROLLED_NON_SECRET_FIXTURE",Scope="PRIVATE_STATE_ACCESS_DENIAL_CONTROL"}));
            // An existing, readable positive host control prevents absence from
            // being mistaken for a restricted child's access-denied result.
            _=state.Read("resource-fixture-"+nonce+".json",4096);
            return new(state,directory,gitProjectDirectory,gitControlDirectory,gitPackageSid,
                input,tool,plan,git,projectInput,gitPathspec,allPackagesFixture,privacy,project);
        }
        catch(Exception error)
        {
            var cleanup=Release(privacy,allPackagesFixture,projectInput,gitPathspec,git,gitControlDirectory,gitProjectDirectory,input,directory,tool);
            if(cleanup.Count!=0){cleanup.Insert(0,error);throw new AggregateException(cleanup);}
            throw;
        }
    }
    internal void AssertHeld()
    {
        state.AssertHeld();folder.AssertHeld();
        privacy?.AssertHeld();
        if(input.SafeFileHandle.IsClosed)throw WfpNative.Contract("SessionResourceLeaseLost");
        WindowsPathSeal.VerifyObject(input.SafeFileHandle,WindowsPathSeal.Child(Workspace,"input.txt"),false);
        if(Plan.RequiresCompilerTool)
        {
            if(tool is null)throw WfpNative.Contract("PowerShellAssetLeaseRequired");
            tool.AssertHeld();if(Plan.RequiresPowerShell)PowerShellPolicySnapshot.AssertActuallyAbsent();
        }
        git?.AssertHeld();
        if((git is null)!=(gitProjectDirectory is null) || (git is null)!=(gitControlDirectory is null) ||
            (git is null)!=(gitPackageSid is null))
            throw WfpNative.Contract("GitWorkspaceLeasePresenceMismatch");
        if(gitProjectDirectory is not null)
        {
            gitProjectDirectory.AssertHeld();gitControlDirectory!.AssertHeld();
            GitWorkspaceDescriptor.AssertPath(gitProjectDirectory.Path,gitPackageSid!,true);
            GitWorkspaceDescriptor.AssertPath(gitControlDirectory.Path,gitPackageSid!,false);
            SessionGitToolchain.AssertGitControlReady(Workspace,gitPathspec is not null);
        }
        if((workspaceBundle?.GitPlan is not null)!=(gitPathspec is not null))throw WfpNative.Contract("GitPathspecLeasePresenceMismatch");
        if(gitPathspec is not null)
        {
            if(gitPathspec.SafeFileHandle.IsClosed)throw WfpNative.Contract("GitPathspecLeaseLost");
            WindowsPathSeal.VerifyObject(gitPathspec.SafeFileHandle,SessionGitToolchain.GitControlPath(Workspace,"git-selected-paths.bin"),false);
            if(!SessionGitToolchain.SelectedPathspecMatches(Workspace,workspaceBundle!))
                throw WfpNative.Contract("GitPathspecLeaseContentMismatch");
        }
        if(allPackagesFixture.SafeFileHandle.IsClosed)throw WfpNative.Contract("AllPackagesFixtureLeaseLost");
        WindowsPathSeal.VerifyObject(allPackagesFixture.SafeFileHandle,WindowsPathSeal.Child(Workspace,"all-packages-only.json"),false);
        using(var human=WindowsIdentity.GetCurrent())AssertAllPackagesFixture(allPackagesFixture.SafeFileHandle,human.User!.Value);
        if(Plan.WorkspaceInputSHA256 is not null)
        {
            if(projectInput is null || projectInput.SafeFileHandle.IsClosed)throw WfpNative.Contract("WorkspaceDataLeaseLost");
            WindowsPathSeal.VerifyObject(projectInput.SafeFileHandle,WindowsPathSeal.Child(Workspace,"project-input.json"),false);
        }
        else if(projectInput is not null)throw WfpNative.Contract("UnexpectedWorkspaceDataLease");
    }
    internal void AssertOutput(ResourceChildReport observed)
    {
        AssertHeld();
        foreach(var name in Plan.RequiresCompilerTool?new[]{"root-output.txt","tool-output.txt"}:new[]{"root-output.txt"})
        {
            using var handle=WindowsPathSeal.Open(WindowsPathSeal.Child(Workspace,name),false,true);
            using var output=new FileStream(handle,FileAccess.Read,4096,false);
            if(output.Length!=Plan.Input.Length || Convert.ToHexString(SHA256.HashData(output))!=Convert.ToHexString(SHA256.HashData(Plan.Input)))
                throw WfpNative.Contract("SessionWorkspaceOutputMismatch");
        }
        if(Plan.RequiresPowerShell)
        {
            using(var built=new FileStream(WindowsPathSeal.Open(WindowsPathSeal.Child(Workspace,"owned-build-result.txt"),false,true),FileAccess.Read,4096,false))
            {
                var bytes=new byte[2];if(built.Length!=2)throw WfpNative.Contract("OwnedCompilationResultBounds");built.ReadExactly(bytes);
                if(!bytes.AsSpan().SequenceEqual("12"u8))throw WfpNative.Contract("OwnedCompilationResultMismatch");
            }
            using(var assembly=new FileStream(WindowsPathSeal.Open(WindowsPathSeal.Child(Workspace,"owned-build.dll"),false,true),FileAccess.Read,4096,false))
                if(assembly.Length is <512 or >1024*1024)throw WfpNative.Contract("OwnedCompilationArtifactBounds");
        }
        if(git is not null)gitReceipt=SessionGitToolchain.AssertRepository(Workspace,Plan,observed.Git??throw WfpNative.Contract("GitOutputEvidenceMissing"));
    }
    internal HostPrivacySummary ReadClosedHostPrivacy(int rootPid,int? toolPid)
        =>(privacy??throw WfpNative.Contract("HostPrivacyOwnerMissing")).ReadClosed(Workspace,rootPid,toolPid);
    internal bool ProjectExecutionReleased=>privacy?.ExecutionReleased==true;
    internal bool ProjectProbeSealed=>privacy?.ProbeSealed==true;
    internal void SealRootHostPrivacyBeforeGit(int rootPid)
        =>(privacy??throw WfpNative.Contract("HostPrivacyOwnerMissing")).SealRootBeforeGit(Workspace,rootPid);
    internal void BeforeOwnedToolCreation(string kind)
    {
        if(!Plan.DevelopProject)return;
        if(kind=="project-probe")(privacy??throw WfpNative.Contract("HostPrivacyOwnerMissing")).AuthorizeProbeCreation();
        else if(kind=="project")(privacy??throw WfpNative.Contract("HostPrivacyOwnerMissing")).AuthorizeToolCreation(Workspace);
        else if(kind=="git")(privacy??throw WfpNative.Contract("HostPrivacyOwnerMissing")).AssertGitCreationAllowed();
        else throw WfpNative.Contract("ExplicitProjectToolKindRequired");
    }
    internal void ReleaseProjectExecution(int toolPid,Action assertCurrentOwner)
    {
        AssertHeld();var owner=privacy??throw WfpNative.Contract("HostPrivacyOwnerMissing");
        owner.SealToolBeforeExecution(Workspace,toolPid);
        owner.ReleaseExecution(Workspace,assertCurrentOwner);
        Release("project-execution-go");
    }
    internal void SealProjectProbeBeforeExit(int pid)
    {
        AssertHeld();(privacy??throw WfpNative.Contract("HostPrivacyOwnerMissing")).SealProbeBeforeExit(Workspace,pid);
        Release("probe-exit-go");
    }
    internal void PreserveGitFailure()
    {
        foreach(var (leaf,prefix) in new[]{("git-last-result.json","resource-git-error-"),("tool-last-result.json","resource-tool-error-")})
            PreserveFixedFailure(leaf,prefix);
    }
    private void PreserveFixedFailure(string leaf,string prefix)
    {
        var path=WindowsPathSeal.Child(Workspace,leaf);
        try
        {
            using var file=new FileStream(WindowsPathSeal.Open(path,false,true),FileAccess.Read,4096,false);
            if(file.Length is <1 or >32768)throw WfpNative.Contract("GitFailureRecordBounds");
            var bytes=new byte[checked((int)file.Length)];file.ReadExactly(bytes);
            // Private failure evidence only; never parsed into admission or
            // returned as a user-supplied authorization/configuration record.
            state.WriteNew(prefix+Plan.Nonce+".json",bytes);
        }
        catch(ExactPathAbsentException ex)when(string.Equals(ex.FailedPath,path,StringComparison.OrdinalIgnoreCase)){}
    }
    internal string? PreserveClosedWorkspaceResult(JobSnapshot zero,Action? assertCaller)
    {
        AssertHeld();if(git is null)return null;
        if(!zero.ObservedZero)throw WfpNative.Contract("WorkspaceExportRequiresClosedJobZero");
        var baseline=Plan.WorkspaceInputSHA256 is null?state.Read("workspace-input-"+Plan.Nonce+".json"):state.ReadWorkspaceData(Plan.Nonce,false);
        if(!baseline.Bytes.AsSpan().SequenceEqual(Plan.ProjectBundle))throw WfpNative.Contract("WorkspaceExportBaselineChanged");
        var callerProject=Plan.CallerProjectKind is null?null:CSharpProjectTask.Parse(baseline.Bytes);
        var original=callerProject?.Baseline??WorkspaceBundle.Parse(baseline.Bytes);
        var limits=original.Files.ToDictionary(f=>f.Path,_=>WorkspaceBundle.MaxFileBytes,StringComparer.Ordinal);
        if(callerProject is not null)
        {
            foreach(var path in CSharpProjectTask.Outputs.Take(3))limits.Add(path,WorkspaceBundle.MaxFileBytes);
            foreach(var path in CSharpProjectTask.Outputs.Skip(3))limits.Add(path,CSharpProjectTask.MaxConsoleBytes);
            foreach(var output in callerProject.GeneratedFiles)limits.Add(output.Path,output.MaxBytes);
        }
        else if(Plan.DevelopProject)
            foreach(var path in BundledProjectDevelopment.OutputPaths)limits.Add(path,WorkspaceBundle.MaxFileBytes);
        var bytes=WorkspaceFiles.SnapshotSelectedResult(Workspace,"git-project",baseline.Bytes,limits);
        if(gitReceipt is not null)bytes=WorkspaceBundle.AttachGitReceipt(bytes,baseline.Bytes,gitReceipt);
        if(callerProject is not null)callerProject.VerifyResult(bytes);
        else if(Plan.DevelopProject)BundledProjectDevelopment.VerifyResult(bytes);
        else if(gitReceipt is null && WorkspaceBundle.Compare(baseline.Bytes,bytes).Length!=0)
            throw WfpNative.Contract("FixedGitWorkspaceUnexpectedChanges");
        // Current fixed sample fits the existing private journal size. Future
        // large project output needs owned data storage, not a widened ledger.
        assertCaller?.Invoke();
        return Plan.WorkspaceInputSHA256 is null?state.WriteNew("workspace-result-"+Plan.Nonce+".json",bytes):state.StoreWorkspaceData(Plan.Nonce,true,bytes);
    }
    internal bool ToolReady()=>Plan.RequiresCompilerTool && Ready("tool-ready");
    internal bool ProjectPrivacyReady()=>Plan.DevelopProject && Ready("project-privacy-ready");
    internal bool ProjectProbeReady()=>Plan.DevelopProject && Ready("probe-ready");
    internal bool ProjectProbePrivacyReady()=>Plan.DevelopProject && Ready("probe-privacy-ready");
    internal void ReleaseInspectedProbe()=>Release("probe-go");
    internal bool GitReady()=>git is not null && Ready("git-ready");
    private bool Ready(string stem)
    {
        AssertHeld();var path=WindowsPathSeal.Child(Workspace,stem+".txt");
        // The signal carries no authority: it only follows close of the data
        // file. Identity still comes from held process/token/Job inspection.
        if(!File.Exists(WindowsPathSeal.Child(Workspace,stem+".signal")))return false;
        try
        {
            using var handle=WindowsPathSeal.Open(path,false,true);
            using var file=new FileStream(handle,FileAccess.Read,64,false);
            if(file.Length!=32 || Convert.ToHexString(SHA256.HashData(file))!=Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(Plan.Nonce))))
                throw WfpNative.Contract("ResourceToolReadyBindingMismatch");
            return true;
        }
        catch(ExactPathAbsentException ex)when(string.Equals(ex.FailedPath,path,StringComparison.OrdinalIgnoreCase)){return false;}
    }
    internal void ReleaseInspectedTool()=>Release("tool-go");
    internal void ReleaseInspectedGit()
    {if(git is null)throw WfpNative.Contract("GitResourceGrantMissing");Release("git-go");}
    private void Release(string stem)
    {
        AssertHeld();
        using(var output=new FileStream(WindowsPathSeal.Child(Workspace,stem+".txt"),FileMode.CreateNew,FileAccess.Write,FileShare.None))
        {output.Write(Encoding.ASCII.GetBytes(Plan.Nonce));output.Flush(true);}
        using var signal=new FileStream(WindowsPathSeal.Child(Workspace,stem+".signal"),FileMode.CreateNew,FileAccess.Write,FileShare.Read);
        signal.Flush(true);
    }

    public void Dispose()
    {
        var failures=Release(privacy,allPackagesFixture,projectInput,gitPathspec,git,gitControlDirectory,gitProjectDirectory,input,folder,tool);
        if(failures.Count!=0)throw new AggregateException(failures);
    }
    // A failed release does not suppress the remaining owned releases or the
    // original preparation error. Journal recovery still belongs to the owner.
    private static List<Exception> Release(params IDisposable?[] held)
    {
        var failures=new List<Exception>();
        foreach(var item in held)
            try{item?.Dispose();}catch(Exception error){failures.Add(error);}
        return failures;
    }
}
