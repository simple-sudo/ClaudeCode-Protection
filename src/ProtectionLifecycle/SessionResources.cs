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
    private readonly SessionWorkspaceLease workspace;
    private readonly SessionPowerShellToolchain? tool;
    private readonly HostPrivacyProbe? privacy;
    internal ResourceProbePlan Plan {get;}
    internal string Workspace=>workspace.Workspace;
    private SessionResources(ProtectedState state,SessionWorkspaceLease workspace,SessionPowerShellToolchain? tool,ResourceProbePlan plan,HostPrivacyProbe? privacy)
    {this.state=state;this.workspace=workspace;this.tool=tool;Plan=plan;this.privacy=privacy;}
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
        HostPrivacyProbe? privacy=null;SessionWorkspaceLease? workspaceLease=null;
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
            allPackagesFixture=SessionWorkspaceLease.CreateAllPackagesFixture(WindowsPathSeal.Child(path,"all-packages-only.json"),identity.User!.Value,plan.Input);
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
            workspaceLease=new SessionWorkspaceLease(state,plan,directory??throw WfpNative.Contract("SessionWorkspaceDirectoryMissing"),
                gitProjectDirectory,gitControlDirectory,gitPackageSid,input??throw WfpNative.Contract("SessionWorkspaceInputMissing"),
                git,projectInput,gitPathspec,allPackagesFixture??throw WfpNative.Contract("AllPackagesFixtureMissing"),project);
            // Ownership of every workspace path/stream and the Git lease moves
            // exactly once into SessionWorkspaceLease.
            directory=null;gitProjectDirectory=null;gitControlDirectory=null;input=null;projectInput=null;gitPathspec=null;allPackagesFixture=null;git=null;
            var result=new SessionResources(state,workspaceLease,tool,plan,privacy);
            workspaceLease=null;tool=null;privacy=null;
            return result;
        }
        catch(Exception error)
        {
            List<Exception> cleanup;
            if(workspaceLease is null)
                cleanup=Release(privacy,allPackagesFixture,projectInput,gitPathspec,git,gitControlDirectory,gitProjectDirectory,input,directory,tool);
            else
            {
                cleanup=Release(privacy);
                workspaceLease.ReleaseInto(cleanup);
                cleanup.AddRange(Release(tool));
            }
            if(cleanup.Count!=0){cleanup.Insert(0,error);throw new AggregateException(cleanup);}
            throw;
        }
    }
    internal void AssertHeld()
    {
        state.AssertHeld();workspace.AssertFolderHeld();
        privacy?.AssertHeld();
        workspace.AssertInputHeld();
        if(Plan.RequiresCompilerTool)
        {
            if(tool is null)throw WfpNative.Contract("PowerShellAssetLeaseRequired");
            tool.AssertHeld();if(Plan.RequiresPowerShell)PowerShellPolicySnapshot.AssertActuallyAbsent();
        }
        workspace.AssertRemainingHeld();
    }
    internal void AssertOutput(ResourceChildReport observed)
    {AssertHeld();workspace.AssertOutput(observed);}
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
    internal void PreserveGitFailure()=>workspace.PreserveGitFailure();
    internal string? PreserveClosedWorkspaceResult(JobSnapshot zero,Action? assertCaller)
    {AssertHeld();return workspace.PreserveClosedWorkspaceResult(zero,assertCaller);}
    internal bool ToolReady()=>Plan.RequiresCompilerTool && Ready("tool-ready");
    internal bool ProjectPrivacyReady()=>Plan.DevelopProject && Ready("project-privacy-ready");
    internal bool ProjectProbeReady()=>Plan.DevelopProject && Ready("probe-ready");
    internal bool ProjectProbePrivacyReady()=>Plan.DevelopProject && Ready("probe-privacy-ready");
    internal void ReleaseInspectedProbe()=>Release("probe-go");
    internal bool GitReady()=>workspace.HasGit && Ready("git-ready");
    private bool Ready(string stem){AssertHeld();return workspace.Ready(stem);}
    internal void ReleaseInspectedTool()=>Release("tool-go");
    internal void ReleaseInspectedGit()
    {if(!workspace.HasGit)throw WfpNative.Contract("GitResourceGrantMissing");Release("git-go");}
    private void Release(string stem){AssertHeld();workspace.Release(stem);}
    public void Dispose()
    {
        var failures=Release(privacy);
        workspace.ReleaseInto(failures);
        failures.AddRange(Release(tool));
        if(failures.Count!=0)throw new AggregateException(failures);
    }
    private static List<Exception> Release(params IDisposable?[] held)
    {
        var failures=new List<Exception>();
        foreach(var item in held)
            try{item?.Dispose();}catch(Exception error){failures.Add(error);}
        return failures;
    }
}
