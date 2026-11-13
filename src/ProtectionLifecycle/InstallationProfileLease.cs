using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;

namespace ProtectionLifecycle;

// A fresh, exact current-user profile lease. Existing profiles are never
// adopted/deleted. Deletion requires this process's successful creation and a
// subsequent owned-Job zero observation once process creation was attempted.
internal sealed class InstallationProfileLease : IDisposable
{
    private readonly ProtectedState state;
    private readonly string name,id;
    private ProfileStorageReceipt? storage;
    private string? jobId;
    private bool mayDelete=true,disposed;
    private InstallationProfileLease(ProtectedState state,string name,string id){this.state=state;this.name=name;this.id=id;}
    internal static InstallationProfileLease Create(ProtectedState state,bool control=false)
    {
        state.AssertHeld();SessionProfileRecovery.AssertNoPending(state);
        using var expected=control?InstallationPackageSid.ForNetworkControl(state):new InstallationPackageSid(state);var id=Guid.NewGuid().ToString("N");
        if(expected.Name.Length>64)throw WfpNative.Contract("AppContainerProfileNameExceedsWindowsLimit");
        using var parent=SessionProfileRecovery.PrepareFreshStorage(expected.Name);
        state.WriteNew("profile-intent-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=2,state.InstallationId,ProfileId=id,Control=control,
            Name=expected.Name,Sid=expected.Value,Status="FRESH_PROFILE_CREATION_PLANNED",ExistingProfileAdoptionAllowed=false,AtUtc=DateTime.UtcNow.ToString("o")}));
        var status=CreateAppContainerProfile(expected.Name,"ClaudeCodeProtection synthetic session","Finite tool-owned no-network admission qualification",IntPtr.Zero,0,out var sid);
        try
        {
            if(status!=0)throw new WfpFailure("CreateFreshInstallationAppContainerProfile",unchecked((uint)status));
            var owner=new InstallationProfileLease(state,expected.Name,id);
            try
            {
                if(sid==IntPtr.Zero || !WfpNative.IsValidSid(sid) || new SecurityIdentifier(sid).Value!=expected.Value)throw WfpNative.Contract("CreatedProfileSidMismatch");
                owner.storage=SessionProfileRecovery.RecordCreated(state,expected,id,control,parent);
                return owner;
            }
            catch(Exception failure)
            {if(owner.storage is not null)try{owner.Dispose();}catch(Exception cleanup){throw new AggregateException("Profile creation qualification and exact cleanup failed",failure,cleanup);}throw;}
        }
        finally{if(sid!=IntPtr.Zero)FreeSid(sid);}
    }
    internal void BeforeProcessCreation(string boundJobId)
    {
        state.AssertHeld();if(disposed || jobId is not null || storage is null)throw WfpNative.Contract("ProfileCreationBindingUnavailable");
        var bound=OwnedJobIntent.Read(state,Identifiers.Hex32(boundJobId));
        state.WriteNew("profile-job-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,ProfileId=id,
            CreatedSHA256=state.Read("profile-created-"+id+".json",8192).SHA256,bound.JobId}));
        jobId=bound.JobId;mayDelete=false;
    }
    internal bool ProcessCreationAttempted=>jobId is not null;
    internal void PlanTaskWorkspace(string sessionId)
    {
        if(disposed || jobId is not null || storage is null)throw WfpNative.Contract("TaskWorkspacePreparationUnavailable");
        SessionTaskWorkspace.Plan(state,storage,sessionId);
    }
    internal void RecordTaskWorkspace(string sessionId,PathLease workspace)
    {
        if(disposed || jobId is not null || storage is null)throw WfpNative.Contract("TaskWorkspaceCreationUnavailable");
        SessionTaskWorkspace.RecordCreated(state,storage,sessionId,workspace);
    }
    internal void AssertPackage(InstallationPackageSid package)
    {state.AssertHeld();if(disposed || package.Name!=name)throw WfpNative.Contract("ProfileAndAtomicPackageDiffer");}
    internal string WorkspaceRoot()
    {
        state.AssertHeld();if(disposed)throw new ObjectDisposedException(nameof(InstallationProfileLease));
        using var package=new InstallationPackageSid(state);AssertPackage(package);
        return SessionWorkspaceDirectory.ProfileFolder(package.Value);
    }
    internal void AfterOwnedJobZero(JobSnapshot snapshot)
    {
        state.AssertHeld();if(snapshot.JobId!=jobId || !snapshot.ExpectedLimits || !snapshot.ObservedZero ||
            AtomicJobCompletion.ReadClosed(state,OwnedJobIntent.Read(state,snapshot.JobId)) is null)
            throw WfpNative.Contract("ProfileCleanupRequiresOwnedClosedJobZero");
        mayDelete=true;
    }
    // Controlled interruption AFTER durable closed-admission/zero, not a
    // controller crash and never a permission to leave a live child running.
    internal void DeferCleanupForRecovery()
    {
        state.AssertHeld();if(disposed || !mayDelete || jobId is null || storage is null)throw WfpNative.Contract("ProfileRecoveryCheckpointUnavailable");
        SessionProfileRecovery.WriteCleanupIntent(state,storage);disposed=true;
    }
    public void Dispose()
    {
        if(disposed)return;disposed=true;state.AssertHeld();
        if(!mayDelete)throw WfpNative.Contract("ProfileCleanupBlockedWithoutOwnedJobZero");
        if(storage is null)throw WfpNative.Contract("CreatedProfileStorageUnconfirmed");
        SessionProfileRecovery.Cleanup(state,storage);
    }
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] private static extern int CreateAppContainerProfile(string name,string display,string description,IntPtr capabilities,uint count,out IntPtr sid);
    [DllImport("advapi32.dll")] private static extern IntPtr FreeSid(IntPtr sid);
}
