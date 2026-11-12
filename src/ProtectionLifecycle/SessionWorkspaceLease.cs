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
    private readonly PathLease folder;
    private readonly PathLease? gitProjectDirectory,gitControlDirectory;
    private readonly string? gitPackageSid;
    private readonly FileStream input,allPackagesFixture;
    private readonly SessionGitToolchain? git;
    private readonly FileStream? projectInput;
    private readonly FileStream? gitPathspec;
    private readonly WorkspaceBundle? workspaceBundle;
    private WorkspaceGitReceipt? gitReceipt;
    internal ResourceProbePlan Plan {get;}
    internal string Workspace=>folder.Path;
    internal bool HasGit=>git is not null;

    internal SessionWorkspaceLease(ProtectedState state,ResourceProbePlan plan,PathLease folder,
        PathLease? gitProjectDirectory,PathLease? gitControlDirectory,string? gitPackageSid,
        FileStream input,SessionGitToolchain? git,FileStream? projectInput,FileStream? gitPathspec,
        FileStream allPackagesFixture,WorkspaceBundle? workspaceBundle)
    {
        this.state=state;Plan=plan;this.folder=folder;this.gitProjectDirectory=gitProjectDirectory;
        this.gitControlDirectory=gitControlDirectory;this.gitPackageSid=gitPackageSid;this.input=input;
        this.git=git;this.projectInput=projectInput;this.gitPathspec=gitPathspec;
        this.allPackagesFixture=allPackagesFixture;this.workspaceBundle=workspaceBundle;
    }

    // SessionResources interleaves these checks with its PowerShell and
    // HostPrivacy leases to preserve the established validation order.
    internal void AssertFolderHeld()=>folder.AssertHeld();
    internal void AssertInputHeld()
    {
        if(input.SafeFileHandle.IsClosed)throw WfpNative.Contract("SessionResourceLeaseLost");
        WindowsPathSeal.VerifyObject(input.SafeFileHandle,WindowsPathSeal.Child(Workspace,"input.txt"),false);
    }
    internal void AssertRemainingHeld()
    {
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
        using(var output=new FileStream(WindowsPathSeal.Child(Workspace,stem+".txt"),FileMode.CreateNew,FileAccess.Write,FileShare.None))
        {output.Write(Encoding.ASCII.GetBytes(Plan.Nonce));output.Flush(true);}
        using var signal=new FileStream(WindowsPathSeal.Child(Workspace,stem+".signal"),FileMode.CreateNew,FileAccess.Write,FileShare.Read);
        signal.Flush(true);
    }

    internal void ReleaseInto(List<Exception> failures)
    {
        ArgumentNullException.ThrowIfNull(failures);
        foreach(var item in new IDisposable?[]{allPackagesFixture,projectInput,gitPathspec,git,gitControlDirectory,gitProjectDirectory,input,folder})
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
