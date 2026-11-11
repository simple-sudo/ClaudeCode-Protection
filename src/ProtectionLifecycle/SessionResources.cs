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

// Fixed offline tool program plus optional pinned project bytes. This is
// never an executable/path/script grant or formal development admission.
internal sealed record ResourceProbePlan(int SchemaVersion,string Nonce,string InstallationId,string Release,int BrokerPid,string ToolSHA256,string? GitAssetSetSHA256,string? WorkspaceInputSHA256,string ProgramFilesRoot)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    public bool DevelopProject {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? HostPrivacySHA256 {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? CallerProjectKind {get;init;}
    internal static ResourceProbePlan Parse(string raw)
    {
        if(raw.Length>1024)throw WfpNative.Contract("ResourcePlanBoundsRefused");
        using var json=JsonDocument.Parse(raw);var fields=new[]{"SchemaVersion","Nonce","InstallationId","Release","BrokerPid","ToolSHA256","GitAssetSetSHA256","WorkspaceInputSHA256","ProgramFilesRoot"};
        var schema=json.RootElement.GetProperty("SchemaVersion").GetInt32();
        StrictJson.Fields(json.RootElement,schema==6?fields.Concat(new[]{"DevelopProject","HostPrivacySHA256","CallerProjectKind"}).ToArray():schema==5?fields.Concat(new[]{"DevelopProject","HostPrivacySHA256"}).ToArray():fields);
        var plan=JsonSerializer.Deserialize<ResourceProbePlan>(raw)??throw WfpNative.Contract("ResourcePlanMissing");plan.Validate();return plan;
    }
    internal void Validate()
    {
        if(SchemaVersion!=(DevelopProject?(CallerProjectKind is null?5:6):3) || BrokerPid<=0 || WindowsPathSeal.Canonical(ProgramFilesRoot)!=ProgramFilesRoot ||
            CallerProjectKind is not null && (!DevelopProject || !CSharpProjectTask.IsKind(CallerProjectKind)) ||
            (DevelopProject?!WorkspaceBundle.IsHash(HostPrivacySHA256):HostPrivacySHA256 is not null))throw WfpNative.Contract("ResourceQualificationPlanRefused");
        _=Identifiers.Hex32(Nonce);_=Identifiers.Hex32(InstallationId);_=Identifiers.Hex32(Release);_=Identifiers.Hash(ToolSHA256);
        if(GitAssetSetSHA256 is not null && GitAssetSetSHA256!=SessionGitToolchain.AssetSetSHA256)throw WfpNative.Contract("GitAssetSetNotReviewed");
        if(WorkspaceInputSHA256 is not null && (GitAssetSetSHA256 is null || !WorkspaceBundle.IsHash(WorkspaceInputSHA256)))throw WfpNative.Contract("WorkspaceDataPlanRefused");
        if(DevelopProject && (GitAssetSetSHA256!=SessionGitToolchain.AssetSetSHA256 ||
            (CallerProjectKind is null?WorkspaceInputSHA256!=BundledProjectDevelopment.BaselineHash:!WorkspaceBundle.IsHash(WorkspaceInputSHA256))))throw WfpNative.Contract(CallerProjectKind is null?"FixedDevelopmentProjectPlanRequired":"ExplicitCallerProjectPlanRequired");
    }
    // Paths are resolved by the trusted owner outside LPAC. These are internal
    // runtime facts, never a privileged host-path operation or CLI parameter.
    internal string ExpectedChildImage=>WindowsPathSeal.Child(ProgramFilesRoot,"ClaudeCodeProtection/versions/"+Release+"/bin/admin/ProtectionBroker.exe");
    internal string Fixture=>WindowsPathSeal.Child(ProgramFilesRoot,"ClaudeCodeProtection-State/resource-fixture-"+Nonce+".json");
    internal string GitDirectory=>WindowsPathSeal.Child(ProgramFilesRoot,"Git/mingw64/bin");
    internal string PowerShellDirectory=>SessionPowerShellToolchain.DirectoryFor(ProgramFilesRoot);
    internal string PowerShellToolPath=>SessionPowerShellToolchain.ToolFor(ProgramFilesRoot);
    internal string PowerShellLaunchImage=>ExpectedChildImage;
    // Explicit workspace bytes authorize fixed Git data processing only.
    // General tool qualification must still prove PowerShell and compilation.
    internal static (bool PowerShell,bool Compiler) ToolRequirements(bool developProject,bool hasWorkspaceInput)
    {
        var powerShell=!developProject && !hasWorkspaceInput;
        return (powerShell,powerShell || developProject);
    }
    internal bool RequiresPowerShell=>ToolRequirements(DevelopProject,WorkspaceInputSHA256 is not null).PowerShell;
    internal bool RequiresCompilerTool=>ToolRequirements(DevelopProject,WorkspaceInputSHA256 is not null).Compiler;
    internal string Workspace(string sid)=>GitAssetSetSHA256 is null?WindowsPathSeal.Child(SessionResources.ProfileFolder(sid),"workspace-"+Nonce):WindowsPathSeal.Child(ProgramFilesRoot,"ClaudeCodeProtection-Task-"+Nonce);
    internal byte[] Input=>Encoding.UTF8.GetBytes("CPC-RESOURCE:"+Nonce);
    // Same data transfer contract as daily workspace-pack, without importing
    // a caller-selected workload into this fixed qualification entry point.
    internal byte[] FixedProjectBundle=>WorkspaceBundle.Create(new[]{("payload.txt",Input),
        ("src/message.txt",Encoding.UTF8.GetBytes("Project input "+Nonce+"\n")),
        ("README.md",Encoding.UTF8.GetBytes("Offline workspace transfer\n"))}).Serialize();
    internal byte[] ProjectBundle
    {
        get
        {
            if(WorkspaceInputSHA256 is null)return FixedProjectBundle;
            using var file=File.OpenRead(WindowsPathSeal.Child(Workspace(""),"project-input.json"));
            if(file.Length is <1 or >WorkspaceBundle.MaxBundleBytes)throw WfpNative.Contract("WorkspaceDataLengthRefused");
            var bytes=new byte[checked((int)file.Length)];file.ReadExactly(bytes);
            if(WorkspaceBundle.Hash(bytes)!=WorkspaceInputSHA256)throw WfpNative.Contract("WorkspaceDataDigestChanged");
            _=WorkspaceBundle.Parse(bytes);return bytes;
        }
    }
}
internal sealed record ResourceAccessCase(string Role,string Status,int? Error);
internal sealed record ResourceChildReport(int SchemaVersion,int Pid,string Nonce,bool WorkspaceWriteReadMatched,int? ToolExit,
    ResourceAccessCase[] Cases,string? FailureType,int? FailureCode,string? FailureStage,string? ToolDiagnostic,GitToolchainReport? Git,ToolCreationEvidence? CreationEvidence=null,bool OwnedCompilationObserved=false,
    [property:System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] ProjectTaskFailure? ProjectFailure=null);

// The workspace belongs to the freshly created installation profile. No host
// directory ACL is widened, adopted, recursively copied or deleted. It is task
// data, not a trust anchor. All executable inputs remain outside the workspace.
internal sealed class SessionResources : IDisposable
{
    private readonly ProtectedState state;
    private readonly PathLease folder;
    private readonly PathLease? gitProjectDirectory,gitControlDirectory;
    private readonly string? gitOwnerSid,gitPackageSid;
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
        string? gitOwnerSid,string? gitPackageSid,FileStream input,SessionPowerShellToolchain? tool,ResourceProbePlan plan,
        SessionGitToolchain? git,FileStream? projectInput,FileStream? gitPathspec,FileStream allPackagesFixture,
        HostPrivacyProbe? privacy,WorkspaceBundle? workspaceBundle)
    {
        this.state=state;this.folder=folder;this.gitProjectDirectory=gitProjectDirectory;this.gitControlDirectory=gitControlDirectory;
        this.gitOwnerSid=gitOwnerSid;this.gitPackageSid=gitPackageSid;this.input=input;this.tool=tool;Plan=plan;this.git=git;
        this.projectInput=projectInput;this.gitPathspec=gitPathspec;this.allPackagesFixture=allPackagesFixture;
        this.privacy=privacy;this.workspaceBundle=workspaceBundle;
    }
    internal static SessionResources Create(ProtectedState state,VerifiedVersion version,InstallationProfileLease profile,string nonce,bool includeGit=false,byte[]? workspaceInput=null,bool developProject=false,bool callerProject=false)
    {
        state.AssertHeld();version.AssertHeld(state);
        using var sid=new InstallationPackageSid(state);profile.AssertPackage(sid);
        if(callerProject && !developProject)throw WfpNative.Contract("ExplicitCallerCodeTaskRequired");
        if(developProject && (!includeGit || workspaceInput is null || !callerProject && WorkspaceBundle.Hash(workspaceInput)!=BundledProjectDevelopment.BaselineHash))throw WfpNative.Contract("ExplicitBundledProjectTaskRequired");
        var callerTask=callerProject?CSharpProjectTask.Parse(workspaceInput!):null;
        var tool=workspaceInput is null || developProject?SessionPowerShellToolchain.Open():null;
        PathLease? directory=null,gitProjectDirectory=null,gitControlDirectory=null;
        string? gitOwnerSid=null,gitPackageSid=null;
        FileStream? input=null,projectInput=null,gitPathspec=null,allPackagesFixture=null;SessionGitToolchain? git=null;
        HostPrivacyProbe? privacy=null;
        try
        {
            var hash=version.Package.Files.Single(f=>f.Asset.Id=="broker-exe").SHA256;
            if(includeGit)git=SessionGitToolchain.Open();
            if(developProject)privacy=HostPrivacyProbe.Capture(nonce,state.InstallationId,version.Package.Release);
            var plan=new ResourceProbePlan(developProject?(callerProject?6:5):3,Identifiers.Hex32(nonce),state.InstallationId,version.Package.Release,Environment.ProcessId,hash,
                includeGit?SessionGitToolchain.AssetSetSHA256:null,workspaceInput is null?null:WorkspaceBundle.Hash(workspaceInput),
                WindowsPathSeal.Canonical(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles))){DevelopProject=developProject,HostPrivacySHA256=privacy?.SHA256,CallerProjectKind=callerTask?.Definition.Kind};plan.Validate();
            if(!string.Equals(plan.ExpectedChildImage,Environment.ProcessPath,StringComparison.OrdinalIgnoreCase) || includeGit && plan.Workspace("")!=SessionTaskWorkspace.PathFor(nonce))
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
            if(includeGit)
            {
                directory=CreateOwnedTaskDirectory(state,profile,nonce);
                gitOwnerSid=owner;gitPackageSid=sid.Value;
                gitProjectDirectory=GitWorkspaceDescriptor.Create(directory,"git-project",owner,sid.Value,true);
                gitControlDirectory=GitWorkspaceDescriptor.Create(directory,"git-control",owner,sid.Value,false);
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
            if(includeGit)
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
            return new(state,directory,gitProjectDirectory,gitControlDirectory,gitOwnerSid,gitPackageSid,
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
            (git is null)!=(gitOwnerSid is null) || (git is null)!=(gitPackageSid is null))
            throw WfpNative.Contract("GitWorkspaceLeasePresenceMismatch");
        if(gitProjectDirectory is not null)
        {
            gitProjectDirectory.AssertHeld();gitControlDirectory!.AssertHeld();
            GitWorkspaceDescriptor.AssertPath(gitProjectDirectory.Path,gitOwnerSid!,gitPackageSid!,true);
            GitWorkspaceDescriptor.AssertPath(gitControlDirectory.Path,gitOwnerSid!,gitPackageSid!,false);
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
        else if(WorkspaceBundle.Compare(baseline.Bytes,bytes).Length!=0)throw WfpNative.Contract("FixedGitWorkspaceUnexpectedChanges");
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
    internal static string ToolPath=>SessionPowerShellToolchain.ToolFor(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
    internal static SafeFileHandle OpenExecutableForProbe(string path)=>CreateFile(path,0xa0000000,1,IntPtr.Zero,3,0x80,IntPtr.Zero);
    internal static string ProfileFolder(string sid)
    {
        var status=GetAppContainerFolderPath(sid,out var pointer);
        try
        {
            if(status!=0)throw new WfpFailure("GetOwnedProfileFolder",unchecked((uint)status));
            return WindowsPathSeal.Canonical(Marshal.PtrToStringUni(pointer)??throw WfpNative.Contract("ProfileFolderMissing"));
        }
        finally{if(pointer!=IntPtr.Zero)Marshal.FreeCoTaskMem(pointer);}
    }
    internal static int RunChild(string packageSid)
    {
        var raw=Environment.GetEnvironmentVariable("CPC_RESOURCE_PLAN");if(raw is null || raw.Length>1024)throw WfpNative.Contract("ResourcePlanBoundsRefused");
        var plan=ResourceProbePlan.Parse(raw);
        using var sid=InstallationPackageSid.FromInstallationId(plan.InstallationId);
        if(sid.Value!=packageSid || Environment.GetEnvironmentVariable("CPC_NETWORK_PLAN") is not null ||
            Environment.GetEnvironmentVariable("CPC_GPU_PLAN") is not null || Environment.GetEnvironmentVariable("CPC_SESSION_ID") is not null ||
            !string.Equals(Environment.ProcessPath,plan.ExpectedChildImage,StringComparison.OrdinalIgnoreCase))throw WfpNative.Contract("ResourceChildPlanIdentityMismatch");
        var workspace=plan.Workspace(packageSid);var cases=new List<ResourceAccessCase>();bool matched=false,compiled=false;int? toolExit=null;string? failure=null;
        string stage="READ_WORKSPACE_INPUT";int? failureCode=null;string? failureStage=null;string? toolDiagnostic=null;GitToolchainReport? gitReport=null;ToolCreationEvidence? creationEvidence=null;ProjectTaskFailure? projectFailure=null;
        try
        {
            // The trusted owner holds and checks this complete ancestry and
            // input object. File-system/volume security metadata queries are
            // management work; the restricted tool needs ordinary file I/O.
            // The owner independently verifies both actual output identities.
            var input=ReadSmall(WindowsPathSeal.Child(workspace,"input.txt"));
            if(!input.AsSpan().SequenceEqual(plan.Input))throw WfpNative.Contract("ResourceInputMismatch");
            var result=WindowsPathSeal.Child(workspace,"root-output.txt");
            stage="WRITE_AND_READ_WORKSPACE_OUTPUT";
            using(var output=new FileStream(result,FileMode.CreateNew,FileAccess.Write,FileShare.None)){output.Write(input);output.Flush(true);}
            matched=ReadSmall(result).AsSpan().SequenceEqual(input);
            stage="DENY_PRIVATE_STATE_AND_BROKER_HANDLE";
            foreach(var access in new[]{FileAccess.Read,FileAccess.Write})
            {
                try{using var opened=new FileStream(plan.Fixture,FileMode.Open,access,FileShare.ReadWrite);cases.Add(new("private-state-"+access,"OPENED",null));}
                catch(UnauthorizedAccessException){cases.Add(new("private-state-"+access,"ACCESS_DENIED",5));}
                catch(Exception ex){cases.Add(new("private-state-"+access,"UNKNOWN",ex.HResult));}
            }
            try{using var opened=File.OpenRead(WindowsPathSeal.Child(workspace,"all-packages-only.json"));cases.Add(new("all-packages-only-Read","OPENED",null));}
            catch(UnauthorizedAccessException){cases.Add(new("all-packages-only-Read","ACCESS_DENIED",5));}
            catch(Exception ex){cases.Add(new("all-packages-only-Read","UNKNOWN",ex.HResult));}
            using(var broker=OpenProcess(0x10,false,checked((uint)plan.BrokerPid)))
            {
                var error=Marshal.GetLastWin32Error();cases.Add(new("broker-vm-read-open",!broker.IsInvalid?"OPENED":error==5?"ACCESS_DENIED":"UNKNOWN",broker.IsInvalid?error:null));
            }
            var etwQuery=SessionEtwProviderAccess.RestrictedQueryCode();
            cases.Add(new("etw-provider-security-query",etwQuery==5?"ACCESS_DENIED":"QUERY_NOT_DENIED",unchecked((int)etwQuery)));
            // The fixed OS tool executes no user profile, module, supplied
            // script or network request. It uses the same workspace and must
            // independently fail to read the protected non-secret fixture.
            // Readiness is coordination, not evidence of identity. The owner
            // verifies held process handles/tokens/Job before releasing this
            // compiled script. Planned startup/exit need not be atomic Job
            // membership snapshots; all traffic remains quarantined.
            stage="VERIFY_FIXED_TOOL_BYTES";
            using(var tool=File.OpenRead(plan.PowerShellLaunchImage))
                if(Convert.ToHexString(SHA256.HashData(tool))!=plan.ToolSHA256)throw WfpNative.Contract("FixedToolBytesChanged");
            if(plan.DevelopProject)
            {
                stage="DENY_NAMED_HOST_RESOURCES";
                if(!HostPrivacyProbe.RunRestricted(plan,workspace,"root"))throw WfpNative.Contract("NamedHostResourceReadOpenNotDenied");
                stage="PROJECT_GIT_BASELINE";gitReport=SessionGitToolchain.RunChild(plan,workspace);
                if(!SessionGitToolchain.Qualified(gitReport))throw WfpNative.Contract("FixedGitToolchainNotQualified");
                stage="START_FIXED_PRIVACY_PROBE";
                using(var probe=AtomicChild.StartInheritedTool(BundledProjectDevelopment.ProbeStart(plan,workspace)))
                {
                    probe.StandardInput.Close();var probeOut=new ToolOutputCapture(probe.StandardOutput);var probeError=new ToolOutputCapture(probe.StandardError);
                    stage="WAIT_FIXED_PRIVACY_PROBE";
                    if(!probe.WaitForExit(10000))throw new TimeoutException("Fixed privacy probe deadline");
                    if(probe.ExitCode!=0 || probeOut.Completion.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult().Length!=0 ||
                        probeError.Completion.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult().Length!=0)
                        throw WfpNative.Contract("FixedPrivacyProbeNotConfirmed");
                }
                stage="START_PROJECT_COMPILER";
                using var project=AtomicChild.StartInheritedTool(BundledProjectDevelopment.Start(plan,workspace));creationEvidence=project.CreationEvidence;project.StandardInput.Close();
                var output=new ToolOutputCapture(project.StandardOutput);var errors=new ToolOutputCapture(project.StandardError);
                stage="WAIT_PROJECT_COMPILER";
                if(!project.WaitForExit(10000))throw new TimeoutException("Fixed development task deadline");
                toolExit=project.ExitCode;var stdout=output.Completion.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult();var stderr=errors.Completion.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult();
                if(toolExit!=0 || stdout.Length!=0 || stderr.Length!=0)
                {
                    if(toolExit!=0 && plan.CallerProjectKind is not null)
                        projectFailure=ProjectFailureContract.ReadToolError(stdout,stderr,CSharpProjectTask.Parse(plan.ProjectBundle).Definition.Sources.Length);
                    toolDiagnostic=ToolOutputCapture.Classify(stdout,stderr);SaveToolFailure(workspace,stdout,stderr,"EXITED_UNEXPECTED_OUTPUT");throw WfpNative.Contract("ProjectDevelopmentNotConfirmed");
                }
                compiled=true;
            }
            if(plan.RequiresPowerShell)
            {
                var start=PowerShellStart(plan,workspace);
                stage="START_FIXED_POWERSHELL";
                using var process=AtomicChild.StartInheritedTool(start);creationEvidence=process.CreationEvidence;process.StandardInput.Close();
                var outputCapture=new ToolOutputCapture(process.StandardOutput);var errorCapture=new ToolOutputCapture(process.StandardError);
                var stdout=outputCapture.Completion;var stderr=errorCapture.Completion;
                stage="WAIT_FIXED_POWERSHELL";
                if(!process.WaitForExit(10000))
                {
                    var partialOut=outputCapture.Snapshot();var partialError=errorCapture.Snapshot();
                    toolDiagnostic=ToolOutputCapture.Classify(partialOut,partialError);
                    SaveToolFailure(workspace,partialOut,partialError,"TIMEOUT_PARTIAL_PIPE_SNAPSHOT");
                    throw new TimeoutException("Fixed offline tool deadline");
                }
                toolExit=process.ExitCode;
                var toolOut=stdout.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult();
                var toolError=stderr.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult();
                if(toolOut.Length!=0 || toolError.Length!=0)
                {
                    var diagnostic=toolError.Trim();
                    toolDiagnostic=System.Text.RegularExpressions.Regex.IsMatch(diagnostic,
                        @"\ACPC_TOOL_FAILURE\|(READY|WAIT_OWNER|READ_OWNER_GATE|WORKSPACE_IO|DENY_PRIVATE_FIXTURE|COMPILE_OWNED_SAMPLE)\|[A-Za-z0-9.]{1,80}\|-?[0-9]{1,12}\z")?
                        diagnostic:ToolOutputCapture.Classify(toolOut,toolError);
                    SaveToolFailure(workspace,toolOut,toolError,"EXITED_UNEXPECTED_OUTPUT");
                    throw WfpNative.Contract("FixedToolUnexpectedOutput");
                }
                stage="VERIFY_OWNED_COMPILATION_RESULT";
                if(toolExit!=0 || !ReadSmall(WindowsPathSeal.Child(workspace,"owned-build-result.txt")).AsSpan().SequenceEqual("12"u8))
                    throw WfpNative.Contract("OwnedCompilationResultNotConfirmed");
                compiled=true;
            }
            if(plan.GitAssetSetSHA256 is not null && !plan.DevelopProject)
            {stage="FIXED_OFFLINE_GIT_TOOLCHAIN";gitReport=SessionGitToolchain.RunChild(plan,workspace);if(!SessionGitToolchain.Qualified(gitReport))throw WfpNative.Contract("FixedGitToolchainNotQualified");}
        }
        catch(Exception ex)
        {
            failure=ex.GetType().Name;failureCode=ex is System.ComponentModel.Win32Exception native?native.NativeErrorCode:ex.HResult;
            if(ex.Data["ToolCreationEvidence"] is ToolCreationEvidence observedCreation)creationEvidence=observedCreation;
            if(stage=="START_FIXED_POWERSHELL" && ex is System.ComponentModel.Win32Exception)
            {
                // Process.Start can fail while creating/duplicating redirected
                // pipes BEFORE CreateProcess. Keep only known framework method
                // labels; no raw stack, path, arguments or exception message.
                stage+="/"+ToolStartFailurePhase(ex);
            }
            failureStage=stage+(ex.Data["Stage"] is string nativeStage?"/"+nativeStage:"");
        }
        var report=new ResourceChildReport(1,Environment.ProcessId,plan.Nonce,matched,toolExit,cases.ToArray(),failure,failureCode,failureStage,toolDiagnostic,gitReport,creationEvidence,compiled,projectFailure);
        Console.WriteLine(JsonSerializer.Serialize(report));return Qualified(report,plan.RequiresCompilerTool)?0:3;
    }
    internal static ProcessStartInfo PowerShellStart(ResourceProbePlan plan,string workspace)
    {
            if(!plan.RequiresPowerShell)throw WfpNative.Contract("WorkspaceDataCannotRequestPowerShell");
            const string script="$ErrorActionPreference='Stop';$stage='READY';try{[IO.File]::WriteAllText('tool-ready.txt',$env:CPC_RESOURCE_NONCE);[IO.File]::WriteAllText('tool-ready.signal','');$stage='WAIT_OWNER';$until=[DateTime]::UtcNow.AddSeconds(8);while(![IO.File]::Exists('tool-go.signal')){if([DateTime]::UtcNow -ge $until){exit 24};[Threading.Thread]::Sleep(20)};$stage='READ_OWNER_GATE';if([IO.File]::ReadAllText('tool-go.txt') -cne $env:CPC_RESOURCE_NONCE){exit 25};$stage='WORKSPACE_IO';$v=[IO.File]::ReadAllText('input.txt');[IO.File]::WriteAllText('tool-output.txt',$v);$stage='COMPILE_OWNED_SAMPLE';[void][Reflection.Assembly]::LoadFrom([IO.Path]::Combine($PSHOME,'Microsoft.CodeAnalysis.dll'));[void][Reflection.Assembly]::LoadFrom([IO.Path]::Combine($PSHOME,'Microsoft.CodeAnalysis.CSharp.dll'));$tree=[Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree]::ParseText('public static class CpcOwnedBuildProbe{public static int Sum(int a,int b){return checked(a+b);}}');$refs=[Collections.Generic.List[Microsoft.CodeAnalysis.MetadataReference]]::new();foreach($reference in [IO.Directory]::GetFiles([IO.Path]::Combine($PSHOME,'ref'),'*.dll')){$refs.Add([Microsoft.CodeAnalysis.MetadataReference]::CreateFromFile($reference))};$options=[Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions]::new([Microsoft.CodeAnalysis.OutputKind]::DynamicallyLinkedLibrary);$compilation=[Microsoft.CodeAnalysis.CSharp.CSharpCompilation]::Create('CpcOwnedBuildProbe',[Microsoft.CodeAnalysis.SyntaxTree[]]@($tree),$refs.ToArray(),$options);$output=[IO.File]::Create('owned-build.dll');try{$emitted=$compilation.Emit($output)}finally{$output.Dispose()};if(!$emitted.Success){exit 28};Add-Type -Path ([IO.Path]::GetFullPath('owned-build.dll')) -ErrorAction Stop;if([CpcOwnedBuildProbe]::Sum(7,5) -ne 12){exit 27};[IO.File]::WriteAllText('owned-build-result.txt','12');$stage='DENY_PRIVATE_FIXTURE';foreach($fixture in @($env:CPC_DENIAL_FIXTURE,$env:CPC_LPAC_FIXTURE)){$denied=$false;try{$f=[IO.File]::OpenRead($fixture);$f.Dispose()}catch{if($_.Exception -is [UnauthorizedAccessException] -or $_.Exception.InnerException -is [UnauthorizedAccessException]){$denied=$true}else{exit 22}};if(!$denied){exit 23}};exit 0}catch{$e=$_.Exception.GetBaseException();[Console]::Error.WriteLine('CPC_TOOL_FAILURE|'+$stage+'|'+$e.GetType().Name+'|'+$e.HResult);exit 26}";
            var start=new ProcessStartInfo(plan.PowerShellLaunchImage){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=workspace,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
            start.Environment.Clear();
            foreach(var name in new[]{"SystemRoot","windir","SystemDrive","PROCESSOR_ARCHITECTURE"})
            {var value=Environment.GetEnvironmentVariable(name);if(value is not null)start.Environment[name]=value;}
            foreach(var name in new[]{"TEMP","TMP","LOCALAPPDATA","USERPROFILE"})start.Environment[name]=workspace;
            start.Environment["PATH"]=Environment.SystemDirectory;
            start.Environment["PSModulePath"]=WindowsPathSeal.Child(plan.PowerShellDirectory,"Modules");
            start.Environment["POWERSHELL_TELEMETRY_OPTOUT"]="1";
            start.Environment["POWERSHELL_UPDATECHECK"]="Off";
            start.Environment["PSModuleAnalysisCachePath"]=WindowsPathSeal.Child(workspace,"powershell-analysis-cache");
            start.Environment["DOTNET_ROOT"]=WindowsPathSeal.Child(plan.ProgramFilesRoot,"dotnet");
            start.Environment["CPC_DENIAL_FIXTURE"]=plan.Fixture;
            start.Environment["CPC_LPAC_FIXTURE"]=WindowsPathSeal.Child(workspace,"all-packages-only.json");
            start.Environment["CPC_RESOURCE_NONCE"]=plan.Nonce;
            start.Environment["CPC_RESOURCE_PLAN"]=JsonSerializer.Serialize(plan);
            start.Environment["CPC_POWERSHELL_POLICY_NONCE"]=plan.Nonce;
            start.ArgumentList.Add("resource-powershell");
            foreach(var arg in new[]{"-NoLogo","-NoProfile","-NonInteractive","-Command",script})start.ArgumentList.Add(arg);
        return start;
    }
    private static string ToolStartFailurePhase(Exception error)
    {
        if(error.Data["Stage"] is string native)
        {
            if(native is "InheritedToolCreateProcess" or "OwnedToolCreateProcess")return "CREATE_PROCESS";
            if(native is "InheritedToolInputPipe" or "InheritedToolOutputPipe" or "InheritedToolErrorPipe")return "CREATE_REDIRECT_PIPE";
            if(native=="InheritedToolParentHandleSeal")return "DUPLICATE_REDIRECT_HANDLE";
        }
        var methods=new StackTrace(error,false).GetFrames()?.Select(f=>f.GetMethod()).Where(m=>m?.DeclaringType==typeof(Process)).Select(m=>m!.Name).ToArray()??Array.Empty<string>();
        return methods.Contains("CreatePipeWithSecurityAttributes")?"CREATE_REDIRECT_PIPE":methods.Contains("CreatePipe")?"DUPLICATE_REDIRECT_HANDLE":
            methods.Contains("StartWithCreateProcess")?"CREATE_PROCESS":"START_UNCLASSIFIED";
    }
    internal static bool Qualified(ResourceChildReport report,bool requirePowerShell=true)=>report.SchemaVersion==1 && report.WorkspaceWriteReadMatched &&
        (requirePowerShell?report.ToolExit==0 && report.OwnedCompilationObserved:report.ToolExit is null && !report.OwnedCompilationObserved && report.Git is not null) &&
        report.FailureType is null && report.FailureCode is null && report.FailureStage is null && report.ToolDiagnostic is null && report.ProjectFailure is null &&
        (report.Git is null || SessionGitToolchain.Qualified(report.Git)) && report.Cases.Length==5 && report.Cases.Select(c=>c.Role).SequenceEqual(new[]{"private-state-Read","private-state-Write","all-packages-only-Read","broker-vm-read-open","etw-provider-security-query"}) &&
        report.Cases.All(c=>c.Status=="ACCESS_DENIED" && c.Error==5);
    private static void SaveToolFailure(string workspace,string stdout,string stderr,string status)
    {
        if(stdout.Length>4096 || stderr.Length>4096)throw WfpNative.Contract("ToolFailureSnapshotBounds");
        var bytes=JsonSerializer.SerializeToUtf8Bytes(new{SchemaVersion=1,Status=status,Stdout=stdout[..Math.Min(stdout.Length,2048)],
            Stderr=stderr[..Math.Min(stderr.Length,2048)],Truncated=stdout.Length>2048 || stderr.Length>2048});
        using var file=new FileStream(WindowsPathSeal.Child(workspace,"tool-last-result.json"),FileMode.CreateNew,FileAccess.Write,FileShare.None);
        file.Write(bytes);file.Flush(true);
    }
    internal static async Task<string> ReadBounded(StreamReader reader)
    {
        var data=new char[4097];var total=0;
        while(total<data.Length){var count=await reader.ReadAsync(data.AsMemory(total));if(count==0)return new string(data,0,total);total+=count;}
        throw WfpNative.Contract("ResourceReportTooLarge");
    }
    private static byte[] ReadSmall(string path)
    {
        using var file=File.OpenRead(path);if(file.Length is <1 or >1024)throw WfpNative.Contract("ResourceFixtureBounds");
        var data=new byte[checked((int)file.Length)];file.ReadExactly(data);return data;
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
    private static string AllPackagesFixtureSddl(string human)=>"O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x00120089;;;"+new SecurityIdentifier(human).Value+")(A;;0x00120089;;;S-1-15-2-1)";
    private static FileStream CreateAllPackagesFixture(string path,string human,byte[] content)
    {
        // Non-secret, tool-owned positive control. It deliberately grants AAP
        // read but neither the package nor ALL_RESTRICTED_APPLICATION_PACKAGES.
        // Never change an existing host object to obtain this comparison.
        if(!ConvertStringSecurityDescriptorToSecurityDescriptor(AllPackagesFixtureSddl(human),1,out var descriptor,out _))
            throw new WfpFailure("CreateAllPackagesFixtureDescriptor",unchecked((uint)Marshal.GetLastWin32Error()));
        try
        {
            var security=new KernelJobSeal.SecurityAttributes{Length=Marshal.SizeOf<KernelJobSeal.SecurityAttributes>(),Descriptor=descriptor};
            var handle=CreateFixtureFile(path,0xC0000000,1,ref security,1,0x00200080,IntPtr.Zero);
            if(handle.IsInvalid){var error=Marshal.GetLastWin32Error();handle.Dispose();throw new WfpFailure("CreateFreshAllPackagesFixture",unchecked((uint)error));}
            using(var file=new FileStream(handle,FileAccess.ReadWrite)){file.Write(content);file.Flush(true);}
        }
        finally{LocalFree(descriptor);}
        var held=new FileStream(WindowsPathSeal.Open(path,false,true),FileAccess.Read);
        try
        {
            AssertAllPackagesFixture(held.SafeFileHandle,human);
            if(held.Length!=content.Length || Convert.ToHexString(SHA256.HashData(held))!=Convert.ToHexString(SHA256.HashData(content)))throw WfpNative.Contract("AllPackagesFixtureContentChanged");
            held.Position=0;return held;
        }
        catch{held.Dispose();throw;}
    }
    private static void AssertAllPackagesFixture(SafeFileHandle handle,string human)
    {
        var status=GetSecurityInfo(handle,1,1|2|4,out _,out _,out _,out _,out var descriptor);
        if(status!=0)throw new WfpFailure("ReadAllPackagesFixtureAcl",status);
        try
        {
            var size=GetSecurityDescriptorLength(descriptor);if(size is <20 or >65536)throw WfpNative.Contract("AllPackagesFixtureDescriptorBounds");
            var bytes=new byte[size];Marshal.Copy(descriptor,bytes,0,bytes.Length);var actual=new RawSecurityDescriptor(bytes,0);
            var expected=new RawSecurityDescriptor(AllPackagesFixtureSddl(human));
            if(actual.Owner!=expected.Owner || actual.Group!=expected.Group || (actual.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 || actual.DiscretionaryAcl is null)
                throw WfpNative.Contract("AllPackagesFixtureOwnerOrProtectionChanged");
            var left=new byte[actual.DiscretionaryAcl.BinaryLength];actual.DiscretionaryAcl.GetBinaryForm(left,0);
            var right=new byte[expected.DiscretionaryAcl!.BinaryLength];expected.DiscretionaryAcl.GetBinaryForm(right,0);
            if(!left.AsSpan().SequenceEqual(right))throw WfpNative.Contract("AllPackagesFixtureExactAclChanged");
        }
        finally{if(descriptor!=IntPtr.Zero)LocalFree(descriptor);}
    }
    internal static PathLease CreateOwnedTaskDirectory(ProtectedState state,InstallationProfileLease profile,string session)
    {
        state.AssertHeld();
        using var sid=new InstallationPackageSid(state);profile.AssertPackage(sid);
        using var identity=WindowsIdentity.GetCurrent();
        var owner=identity.User?.Value??throw WfpNative.Contract("WorkspaceHumanOwnerMissing");
        using var parent=WindowsPathSeal.LockDirectory(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),PathPolicy.CreationParent);
        profile.PlanTaskWorkspace(session);
        var directory=CreateWorkspace(SessionTaskWorkspace.PathFor(session),owner,sid.Value,true);
        try{profile.RecordTaskWorkspace(session,directory);return directory;}
        catch{directory.Dispose();throw;}
    }
    internal static PathLease CreateWorkspace(string path,string owner,string package,bool mutable)
    {
        using var grant=new WorkspaceDescriptor(owner,package,mutable);
        var attributes=grant.Attributes;
        if(!CreateDirectory(path,ref attributes))throw new WfpFailure("CreateFreshSessionWorkspace",unchecked((uint)Marshal.GetLastWin32Error()));
        var directory=WindowsPathSeal.LockDirectory(path,PathPolicy.Source);
        try{grant.ApplyLowLabelAndVerify(path);return directory;}
        catch{directory.Dispose();throw;}
    }
    internal static void AssertMutableWorkspace(SafeFileHandle handle,string human,string package)
    {using var expected=new WorkspaceDescriptor(human,package,true);expected.AssertApplied(handle);}
    // Windows' profile-root access does not guarantee that a directory created
    // by the elevated Broker inherits a usable package grant. Define both
    // halves of the AppContainer access check at creation, then set only the
    // low mandatory label using WRITE_OWNER, before any child exists. Passing
    // a whole SACL at creation needlessly requires SeSecurityPrivilege.
    // This is ONLY the new nonce workspace; existing host ACLs are untouched.
    private sealed class WorkspaceDescriptor : IDisposable
    {
        private IntPtr descriptor,label;
        private readonly RawSecurityDescriptor expected;
        internal WorkspaceDescriptor(string humanSid,string packageSid,bool mutable)
        {
            _=new SecurityIdentifier(humanSid);_=new SecurityIdentifier(packageSid);
            // Git needs atomic lock-file replacement. DELETE is confined to
            // this freshly created task tree; no DELETE_CHILD/WRITE_DAC/OWNER
            // or existing host directory grant is added. Held input/root
            // handles still prohibit replacement of the owner's trust inputs.
            var mask=mutable?"0x001301bf":"0x001201bf";
            var text="O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;"+mask+";;;"+humanSid+")(A;OICI;"+mask+";;;"+packageSid+")";
            expected=new RawSecurityDescriptor(text+"S:(ML;OICI;NW;;;LW)");
            if(!ConvertStringSecurityDescriptorToSecurityDescriptor(text,1,out descriptor,out _))
                throw new WfpFailure("CreateWorkspaceDescriptor",unchecked((uint)Marshal.GetLastWin32Error()));
            if(!ConvertStringSecurityDescriptorToSecurityDescriptor("S:(ML;OICI;NW;;;LW)",1,out label,out _))
            {var error=Marshal.GetLastWin32Error();Dispose();throw new WfpFailure("CreateWorkspaceLowLabel",unchecked((uint)error));}
        }
        internal KernelJobSeal.SecurityAttributes Attributes=>new(){Length=Marshal.SizeOf<KernelJobSeal.SecurityAttributes>(),Descriptor=descriptor,Inherit=0};
        internal void ApplyLowLabelAndVerify(string path)
        {
            using var handle=CreateFile(path,0x000a0080,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero); // WRITE_OWNER, READ_CONTROL, attributes; no data write.
            if(handle.IsInvalid)throw new WfpFailure("OpenNewWorkspaceForLowLabel",unchecked((uint)Marshal.GetLastWin32Error()));
            WindowsPathSeal.VerifyObject(handle,path,true);
            if(!GetSecurityDescriptorSacl(label,out var present,out var sacl,out _) || !present || sacl==IntPtr.Zero)
                throw WfpNative.Contract("WorkspaceLowLabelDescriptorMissing");
            var status=SetSecurityInfo(handle,1,16,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,sacl); // LABEL only, never SACL_SECURITY_INFORMATION.
            if(status!=0)throw new WfpFailure("SetNewWorkspaceLowLabel",status);
            AssertApplied(handle);
        }
        internal void AssertApplied(SafeFileHandle handle)
        {
            var status=GetSecurityInfo(handle,1,1|4|16,out _,out _,out _,out _,out var value);
            if(status!=0)throw new WfpFailure("ReadWorkspaceGrant",status);
            try
            {
                if(value==IntPtr.Zero)throw WfpNative.Contract("WorkspaceDescriptorMissing");
                var size=GetSecurityDescriptorLength(value);if(size is <20 or >65536)throw WfpNative.Contract("WorkspaceDescriptorBounds");
                var bytes=new byte[checked((int)size)];Marshal.Copy(value,bytes,0,bytes.Length);var actual=new RawSecurityDescriptor(bytes,0);
                if(actual.Owner?.Value!=expected.Owner?.Value || (actual.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 ||
                    !Same(actual.DiscretionaryAcl,expected.DiscretionaryAcl) || !Same(actual.SystemAcl,expected.SystemAcl))
                    throw WfpNative.Contract("WorkspaceGrantOrLowIntegrityMismatch");
            }
            finally{if(value!=IntPtr.Zero)LocalFree(value);}
        }
        private static bool Same(RawAcl? left,RawAcl? right)
        {
            if(left is null || right is null || left.Count!=right.Count)return false;
            for(var i=0;i<left.Count;i++)
            {
                var a=new byte[left[i].BinaryLength];left[i].GetBinaryForm(a,0);
                var b=new byte[right[i].BinaryLength];right[i].GetBinaryForm(b,0);
                if(!a.AsSpan().SequenceEqual(b))return false;
            }
            return true;
        }
        public void Dispose(){if(descriptor!=IntPtr.Zero){LocalFree(descriptor);descriptor=IntPtr.Zero;}if(label!=IntPtr.Zero){LocalFree(label);label=IntPtr.Zero;}}
    }
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] private static extern int GetAppContainerFolderPath(string sid,out IntPtr path);
    [DllImport("kernel32.dll",EntryPoint="CreateDirectoryW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateDirectory(string path,ref KernelJobSeal.SecurityAttributes attributes);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFixtureFile(string path,uint access,uint share,ref KernelJobSeal.SecurityAttributes attributes,uint disposition,uint flags,IntPtr template);
    [DllImport("advapi32.dll",EntryPoint="ConvertStringSecurityDescriptorToSecurityDescriptorW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint length);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityInfo(SafeFileHandle handle,int type,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetSecurityDescriptorSacl(IntPtr descriptor,[MarshalAs(UnmanagedType.Bool)] out bool present,out IntPtr sacl,[MarshalAs(UnmanagedType.Bool)] out bool defaulted);
    [DllImport("advapi32.dll")] private static extern uint SetSecurityInfo(SafeFileHandle handle,int type,uint information,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr attributes,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr value);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)] bool inherit,uint pid);
}
