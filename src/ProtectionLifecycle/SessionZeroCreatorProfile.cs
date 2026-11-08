using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ProtectionLifecycle;

// The creator runs under LocalService. This profile cannot be entered in the
// human owner's recovery ledger or adopted after an interrupted creation.
internal sealed class SessionZeroCreatorProfile : IDisposable
{
    private const uint NotFound=0x80070002;
    private readonly PathLease parent;
    private readonly string storage,identity;
    private bool cleanupAttempted;
    internal InstallationPackageSid Package {get;}

    private SessionZeroCreatorProfile(InstallationPackageSid package,PathLease parent,string storage,string identity)
    {Package=package;this.parent=parent;this.storage=storage;this.identity=identity;}

    internal static SessionZeroCreatorProfile Create(SessionZeroCreatorClient client)
    {
        _=SessionZeroCreatorClient.VerifyCurrentService(SessionZeroCreatorChannel.NameForJob(client.Request.JobId));
        var windows=Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var local=Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if(string.IsNullOrEmpty(windows) || !string.Equals(local,WindowsPathSeal.Child(windows,"ServiceProfiles/LocalService/AppData/Local"),StringComparison.OrdinalIgnoreCase))
            throw WfpNative.Contract("CreatorProfileRootNotLocalService");
        var package=InstallationPackageSid.FromInstallationId(client.Request.InstallationId);
        PathLease? parent=null;
        try
        {
            parent=SessionProfileRecovery.PrepareFreshStorage(package.Name);
            AssertMappingAbsent(package.Value);
            var storage=WindowsPathSeal.Child(parent.Path,package.Name);
            var status=CreateAppContainerProfile(package.Name,"ClaudeCodeProtection offline qualification",
                "Fixed LocalService offline Broker workload",IntPtr.Zero,0,out var created);
            try
            {
                if(status!=0)throw new WfpFailure("CreateLocalServiceProfile",unchecked((uint)status));
                if(created==IntPtr.Zero || !WfpNative.IsValidSid(created) || new SecurityIdentifier(created).Value!=package.Value)
                    throw WfpNative.Contract("CreatorProfileSidMismatch");
                AssertMapping(package.Value,storage);
                using var root=WindowsPathSeal.Open(storage,true,false);
                return new(package,parent,storage,WindowsPathSeal.Identity(root));
            }
            finally{if(created!=IntPtr.Zero)FreeSid(created);}
        }
        catch{parent?.Dispose();package.Dispose();throw;} // Partial or unknown creation is preserved.
    }

    internal void CleanupAfterOwnerStop()
    {
        if(cleanupAttempted)throw WfpNative.Contract("CreatorProfileCleanupAlreadyAttempted");
        cleanupAttempted=true;
        parent.AssertHeld();
        AssertMapping(Package.Value,storage);
        if(!SessionProfileRecovery.InspectExactStorage(storage,identity))throw WfpNative.Contract("CreatorProfileStorageDisappearedBeforeCleanup");
        var status=DeleteAppContainerProfile(Package.Name);
        if(status!=0)throw new WfpFailure("DeleteExactLocalServiceProfile",unchecked((uint)status));
        if(SessionProfileRecovery.InspectExactStorage(storage,identity))throw WfpNative.Contract("CreatorProfileStorageRemains");
        AssertMappingAbsent(Package.Value);
    }

    internal static bool MatchesStorage(string storage,string mapped)=>string.Equals(mapped,storage,StringComparison.OrdinalIgnoreCase) ||
        string.Equals(mapped,WindowsPathSeal.Child(storage,"AC"),StringComparison.OrdinalIgnoreCase);
    private static void AssertMapping(string sid,string storage)
    {
        if(!MatchesStorage(storage,SessionResources.ProfileFolder(sid)))throw WfpNative.Contract("CreatorProfileMappingDiffers");
    }
    private static void AssertMappingAbsent(string sid)
    {
        try{_=SessionResources.ProfileFolder(sid);}
        catch(WfpFailure error) when(error.Status==NotFound){return;}
        throw WfpNative.Contract("CreatorProfileMappingPresent");
    }
    public void Dispose(){parent.Dispose();Package.Dispose();}
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    private static extern int CreateAppContainerProfile(string name,string display,string description,IntPtr capabilities,uint count,out IntPtr sid);
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] private static extern int DeleteAppContainerProfile(string name);
    [DllImport("advapi32.dll")] private static extern IntPtr FreeSid(IntPtr sid);
}
