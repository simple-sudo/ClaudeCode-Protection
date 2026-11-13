using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

// The sole owner of task-workspace paths, open file handles, Git workspace
// directories, the Git toolchain lease, and the result receipt. SessionResources
// coordinates this lease with the independent PowerShell and HostPrivacy leases.
internal sealed class SessionWorkspaceLease : IDisposable
{
    private readonly ProtectedState state;
    private PathLease? folder;
    private PathLease? gitProjectDirectory,gitControlDirectory;
    private string? gitPackageSid,ownerSid;
    private FileStream? input,allPackagesFixture;
    private SessionGitToolchain? git;
    private FileStream? projectInput;
    private FileStream? gitPathspec;
    private WorkspaceBundle? workspaceBundle;
    private WorkspaceGitReceipt? gitReceipt;
    private ResourceProbePlan? plan;
    private bool initialized,disposed;
    internal ResourceProbePlan Plan=>plan??throw WfpNative.Contract("SessionWorkspacePlanMissing");
    internal string Workspace=>(folder??throw WfpNative.Contract("SessionWorkspaceDirectoryMissing")).Path;
    internal bool HasGit=>git is not null;

    private SessionWorkspaceLease(ProtectedState state){this.state=state;}

    // Git's fixed asset lease is acquired before HostPrivacy capture, matching
    // the original resource preparation order. This lease owns it immediately.
    internal static SessionWorkspaceLease Begin(ProtectedState state,bool includeGit)
    {
        ArgumentNullException.ThrowIfNull(state);state.AssertHeld();
        var lease=new SessionWorkspaceLease(state);
        if(includeGit)lease.git=SessionGitToolchain.Open();
        return lease;
    }

    // Prepare creates and holds only the workspace directory ancestry. The
    // caller publishes the HostPrivacy plan after this point, before Populate
    // creates any task data, preserving the original sequencing contract.
    internal void Prepare(InstallationProfileLease profile,ResourceProbePlan plan,byte[]? workspaceInput)
    {
        if(disposed || this.plan is not null || folder is not null)throw WfpNative.Contract("SessionWorkspacePrepareRepeated");
        state.AssertHeld();ArgumentNullException.ThrowIfNull(profile);ArgumentNullException.ThrowIfNull(plan);
        plan.Validate();
        if((plan.GitAssetSetSHA256 is not null)!=(git is not null) ||
            (workspaceInput is null)!=(plan.WorkspaceInputSHA256 is null) ||
            workspaceInput is not null && WorkspaceBundle.Hash(workspaceInput)!=plan.WorkspaceInputSHA256)
            throw WfpNative.Contract("SessionWorkspacePlanOwnershipMismatch");
        using var sid=new InstallationPackageSid(state);profile.AssertPackage(sid);
        if(workspaceInput is not null)
        {
            var parsedProject=WorkspaceBundle.Parse(workspaceInput);
            if(parsedProject.BaseSHA256 is not null || parsedProject.Files.Length==0)
                throw WfpNative.Contract("NonemptyWorkspaceBaselineRequired");
            workspaceBundle=parsedProject;
            // Preflight every destination before creating profile/task data.
            var taskRoot=SessionTaskWorkspace.PathFor(plan.Nonce);
            _=WindowsPathSeal.Child(taskRoot,"git-project");_=WindowsPathSeal.Child(taskRoot,"git-control");
            foreach(var file in parsedProject.Files)
                _=WindowsPathSeal.Child(WindowsPathSeal.Child(taskRoot,"git-project"),file.Path);
        }
        if(git is not null && plan.Workspace("")!=SessionTaskWorkspace.PathFor(plan.Nonce))
            throw WfpNative.Contract("ResourceRuntimePathsDifferFromInstalledOwner");
        this.plan=plan;
        var path=plan.Workspace(sid.Value);
        using var identity=WindowsIdentity.GetCurrent();
        ownerSid=identity.User?.Value??throw WfpNative.Contract("WorkspaceHumanOwnerMissing");
        if(git is not null)
        {
            var taskFolder=SessionWorkspaceDirectory.CreateOwnedTaskDirectory(state,profile,plan.Nonce);
            folder=taskFolder;
            gitPackageSid=sid.Value;
            gitProjectDirectory=GitWorkspaceDescriptor.Create(taskFolder,"git-project",sid.Value,true);
            gitControlDirectory=GitWorkspaceDescriptor.Create(taskFolder,"git-control",sid.Value,false);
        }
        else
        {
            using var parent=WindowsPathSeal.LockDirectory(profile.WorkspaceRoot(),PathPolicy.Source);
            folder=SessionWorkspaceDirectory.CreateWorkspace(path,owner,sid.Value,false);
        }
    }

    // Populate writes the input/control fixtures only after the trusted caller
    // has published any HostPrivacy plan into the held workspace directory.
    internal void Populate(byte[]? workspaceInput)
    {
        if(disposed || initialized || plan is null || folder is null)
            throw WfpNative.Contract("SessionWorkspacePopulateUnavailable");
        state.AssertHeld();
        if((workspaceInput is null)!=(Plan.WorkspaceInputSHA256 is null) ||
            workspaceInput is not null && WorkspaceBundle.Hash(workspaceInput)!=Plan.WorkspaceInputSHA256)
            throw WfpNative.Contract("SessionWorkspaceInputBindingMismatch");
        var path=Workspace;
        var owner=ownerSid??throw WfpNative.Contract("WorkspaceHumanOwnerMissing");
        var inputPath=WindowsPathSeal.Child(path,"input.txt");
        using(var seeded=new FileStream(inputPath,FileMode.CreateNew,FileAccess.Write,FileShare.None))
        {seeded.Write(Plan.Input);seeded.Flush(true);}
        var openedInput=new FileStream(WindowsPathSeal.Open(inputPath,false,true),FileAccess.Read,4096,false);
        input=openedInput;
        if(openedInput.Length!=Plan.Input.Length || Convert.ToHexString(SHA256.HashData(openedInput))!=Convert.ToHexString(SHA256.HashData(Plan.Input)))
            throw WfpNative.Contract("FreshWorkspaceInputChanged");
        openedInput.Position=0;
        allPackagesFixture=CreateAllPackagesFixture(WindowsPathSeal.Child(path,"all-packages-only.json"),owner,Plan.Input);
        if(git is not null)
        {
            if(workspaceInput is not null)
            {
                var dataPath=WindowsPathSeal.Child(path,"project-input.json");
                using(var seeded=new FileStream(dataPath,FileMode.CreateNew,FileAccess.Write,FileShare.None))
                {seeded.Write(workspaceInput);seeded.Flush(true);}
                var openedProjectInput=new FileStream(WindowsPathSeal.Open(dataPath,false,true),FileAccess.Read);
                projectInput=openedProjectInput;
                if(WorkspaceBundle.Hash(Plan.ProjectBundle)!=Plan.WorkspaceInputSHA256)
                    throw WfpNative.Contract("WorkspaceDataPublishChanged");
            }
            var control=gitControlDirectory?.Path??throw WfpNative.Contract("GitControlDirectoryMissing");
            var projectRoot=gitProjectDirectory?.Path??throw WfpNative.Contract("GitProjectDirectoryMissing");
            using(var empty=new FileStream(WindowsPathSeal.Child(control,"empty-git-config"),FileMode.CreateNew,FileAccess.Write,FileShare.None))
            {empty.Flush(true);}
            Directory.CreateDirectory(WindowsPathSeal.Child(control,"empty-git-template"));
            Directory.CreateDirectory(WindowsPathSeal.Child(control,"empty-git-hooks"));
            WorkspaceFiles.MaterializeContentsNew(projectRoot,Plan.ProjectBundle);
            if(workspaceBundle is {GitPlan:not null} gitProject)
            {
                var selectedPathspec=WindowsPathSeal.Child(control,"git-selected-paths.bin");
                var openedPathspec=new FileStream(selectedPathspec,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.Read);
                gitPathspec=openedPathspec;
                var names=Encoding.ASCII.GetBytes(string.Join('\0',gitProject.Files.Select(f=>f.Path))+"\0");
                openedPathspec.Write(names);openedPathspec.Flush(true);openedPathspec.Position=0;
                if(openedPathspec.Length is <1 or >128*1024)throw WfpNative.Contract("GitPathspecLeaseBounds");
            }
            if(workspaceInput is null)state.WriteNew("workspace-input-"+Plan.Nonce+".json",Plan.ProjectBundle);
            else state.StoreWorkspaceData(Plan.Nonce,false,workspaceInput);
        }
        initialized=true;
    }

    // SessionResources interleaves these checks with its PowerShell and
    // HostPrivacy leases to preserve the established validation order.
    private void EnsureInitialized()
    {
        if(disposed)throw new ObjectDisposedException(nameof(SessionWorkspaceLease));
        if(!initialized)throw WfpNative.Contract("SessionWorkspaceLeaseNotInitialized");
    }
    internal void AssertFolderHeld(){EnsureInitialized();(folder??throw WfpNative.Contract("SessionWorkspaceDirectoryMissing")).AssertHeld();}
    internal void AssertInputHeld()
    {
        EnsureInitialized();
        var held=input??throw WfpNative.Contract("SessionResourceLeaseLost");
        if(held.SafeFileHandle.IsClosed)throw WfpNative.Contract("SessionResourceLeaseLost");
        WindowsPathSeal.VerifyObject(held.SafeFileHandle,WindowsPathSeal.Child(Workspace,"input.txt"),false);
    }
    internal void AssertRemainingHeld()
    {
        EnsureInitialized();
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
        var fixture=allPackagesFixture??throw WfpNative.Contract("AllPackagesFixtureLeaseLost");
        if(fixture.SafeFileHandle.IsClosed)throw WfpNative.Contract("AllPackagesFixtureLeaseLost");
        WindowsPathSeal.VerifyObject(fixture.SafeFileHandle,WindowsPathSeal.Child(Workspace,"all-packages-only.json"),false);
        using(var human=WindowsIdentity.GetCurrent())AssertAllPackagesFixture(fixture.SafeFileHandle,human.User!.Value);
        if(Plan.WorkspaceInputSHA256 is not null)
        {
            var data=projectInput??throw WfpNative.Contract("WorkspaceDataLeaseLost");
            if(data.SafeFileHandle.IsClosed)throw WfpNative.Contract("WorkspaceDataLeaseLost");
            WindowsPathSeal.VerifyObject(data.SafeFileHandle,WindowsPathSeal.Child(Workspace,"project-input.json"),false);
        }
        else if(projectInput is not null)throw WfpNative.Contract("UnexpectedWorkspaceDataLease");
    }

    internal void AssertOutput(ResourceChildReport observed)
    {
        EnsureInitialized();
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

    internal void PreserveGitFailure()
    {
        EnsureInitialized();
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
        EnsureInitialized();
        if(git is null)return null;
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

    internal bool Ready(string stem)
    {
        EnsureInitialized();
        var path=WindowsPathSeal.Child(Workspace,stem+".txt");
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
    internal void Release(string stem)
    {
        EnsureInitialized();
        using(var output=new FileStream(WindowsPathSeal.Child(Workspace,stem+".txt"),FileMode.CreateNew,FileAccess.Write,FileShare.None))
        {output.Write(Encoding.ASCII.GetBytes(Plan.Nonce));output.Flush(true);}
        using var signal=new FileStream(WindowsPathSeal.Child(Workspace,stem+".signal"),FileMode.CreateNew,FileAccess.Write,FileShare.Read);
        signal.Flush(true);
    }

    internal void ReleaseInto(List<Exception> failures)
    {
        ArgumentNullException.ThrowIfNull(failures);
        if(disposed)return;
        disposed=true;
        var held=new IDisposable?[]{allPackagesFixture,projectInput,gitPathspec,git,gitControlDirectory,gitProjectDirectory,input,folder};
        allPackagesFixture=null;projectInput=null;gitPathspec=null;git=null;
        gitControlDirectory=null;gitProjectDirectory=null;input=null;folder=null;
        foreach(var item in held)
            try{item?.Dispose();}catch(Exception error){failures.Add(error);}
    }
    public void Dispose()
    {
        var failures=new List<Exception>();ReleaseInto(failures);
        if(failures.Count!=0)throw new AggregateException(failures);
    }

    private static string AllPackagesFixtureSddl(string human)
        =>"O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x00120089;;;"+new SecurityIdentifier(human).Value+")(A;;0x00120089;;;S-1-15-2-1)";
    internal static FileStream CreateAllPackagesFixture(string path,string human,byte[] content)
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

    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern SafeFileHandle CreateFixtureFile(string path,uint access,uint share,ref KernelJobSeal.SecurityAttributes attributes,uint disposition,uint flags,IntPtr template);
    [DllImport("advapi32.dll",EntryPoint="ConvertStringSecurityDescriptorToSecurityDescriptorW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint length);
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(SafeFileHandle handle,int type,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr value);
}
