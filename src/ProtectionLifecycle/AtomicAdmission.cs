using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

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
        return SessionResources.ProfileFolder(package.Value);
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

// A completed one-shot admission cannot accept another process. Recovery may
// use its durable zero-members proof; arbitrary missing Jobs remain UNKNOWN.
internal sealed record AtomicJobCompletion(int SchemaVersion,string InstallationId,string JobId,string Release,string ManifestSHA256,
    string AdmissionSHA256,string Status,JobSnapshot Snapshot)
{
    internal static AtomicJobCompletion? ReadClosed(ProtectedState state,OwnedJobIntent intent)
    {
        state.AssertHeld();var raw=state.ReadOptional("job-completed-"+intent.JobId+".json");if(raw is null)return null;
        using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=5});var r=doc.RootElement;
        StrictJson.Fields(r,"SchemaVersion","InstallationId","JobId","Release","ManifestSHA256","AdmissionSHA256","Status","Snapshot");
        StrictJson.Fields(r.GetProperty("Snapshot"),"JobId","LimitFlags","ActiveBefore","ActiveAfter","ProcessIds","AtUtc");
        var result=JsonSerializer.Deserialize<AtomicJobCompletion>(raw.Bytes)??throw WfpNative.Contract("MissingAtomicCompletion");
        if(result.SchemaVersion!=1 || result.InstallationId!=state.InstallationId || result.JobId!=intent.JobId || result.Release!=intent.Release ||
            result.ManifestSHA256!=intent.ManifestSHA256 || result.Status!="ADMISSION_CLOSED_MEMBERS_ZERO_OBSERVED" || result.Snapshot is null ||
            result.Snapshot.JobId!=intent.JobId || !result.Snapshot.ExpectedLimits || !result.Snapshot.ObservedZero)
            throw WfpNative.Contract("AtomicCompletionOwnershipOrZeroMismatch");
        var admission=state.Read("job-admission-"+intent.JobId+".json",8192);
        if(admission.SHA256!=Identifiers.Hash(result.AdmissionSHA256))throw WfpNative.Contract("AtomicCompletionAdmissionHashMismatch");
        using var data=JsonDocument.Parse(admission.Bytes);var a=data.RootElement;
        StrictJson.Fields(a,"SchemaVersion","InstallationId","JobId","Release","ManifestSHA256","Binding","Reusable");
        if(a.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(a,"InstallationId")!=state.InstallationId || StrictJson.Text(a,"JobId")!=intent.JobId ||
            StrictJson.Text(a,"Release")!=intent.Release || StrictJson.Text(a,"ManifestSHA256")!=intent.ManifestSHA256 ||
            StrictJson.Text(a,"Binding")!="ATOMIC_JOB_LIST_AT_CREATION" || a.GetProperty("Reusable").GetBoolean())throw WfpNative.Contract("AtomicAdmissionProofMismatch");
        return result;
    }
}

internal sealed record AdmissionToken(bool IsAppContainer,string? PackageSid,int CapabilityCount,string IntegritySid,bool LpacAccessCheckObserved,uint ApplicationPackageAccessMask)
{
    // Held native observation, not caller JSON. Preserve the existing public
    // evidence schema while retaining exact SIDs/attributes for owner checks.
    [System.Text.Json.Serialization.JsonIgnore]
    internal TokenCapabilitySnapshot? Capabilities {get;init;}
}
internal sealed record ResourceBootstrapFailure(int SchemaVersion,string Scope,string Phase,string Type,int Code,string? NativeStage);
internal sealed record OwnedMemberInspection(uint Pid,bool MembershipConfirmed,long? CreatedFileTime,string? ImagePath,AdmissionToken? Token,WfpErrorEvidence[] Failures);

// No supplied executable/arguments/PID/token. First consumer is the installed
// broker's own finite canary. Production Claude admission remains deferred.
internal sealed partial class AtomicChild : IDisposable
{
    private readonly ProtectedState state;
    private readonly VerifiedVersion version;
    private readonly OwnedKernelJob job;
    private readonly SafeProcessHandle process;
    private readonly SafeWaitHandle thread;
    private readonly string image,packageSid;
    private readonly NetworkProbePlan? network;
    private readonly bool gpuWorkload;
    private readonly bool schannelWorkload;
    private readonly ProtectedSession.Preparation? sessionPreparation;
    private readonly ProtectedSession.ResourceQualification? resourceQualification;
    private ProtectedSession.Admission? sessionAdmission;
    private bool resumed,disposed;
    internal bool ResumeAttempted {get;private set;}
    internal string? DefaultDaclPreparationSHA256 {get;private set;}
    internal uint Pid {get;}
    internal string ExpectedPackageSid=>packageSid;
    internal string ExpectedImagePath=>image;
    internal bool RequiresLpac=>sessionPreparation is not null || resourceQualification is not null || gpuWorkload || schannelWorkload;
    private LpacCapabilityProfile CapabilityProfile=>sessionPreparation?.CapabilityProfile??FixedCapabilities(schannelWorkload);
    private static LpacCapabilityProfile FixedCapabilities(bool schannel)=>schannel?
        LpacCapabilityProfile.InternetClientQualification:LpacCapabilityProfile.None;
    internal long ExpectedCreatedFileTime
    {
        get
        {
            if(disposed || !GetProcessTimes(process,out var created,out _,out _,out _))throw Error("ReadHeldPrimaryCreationTime");
            return created;
        }
    }
    internal bool IsRunning=>!disposed && WaitForSingleObject(process,0)==0x102;
    // Candidate primitive only; no current creation/qualification path calls
    // it. A separately reviewed fixed owner operation must select it before
    // resume. It can alter only this held child's future-object default ACL.
    internal void PrepareOwnDefaultDaclBeforeResume()
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);
        if(sessionPreparation is null || !sessionPreparation.IsGatewayQualification ||
            !job.AtomicAdmissionReserved || ResumeAttempted || DefaultDaclPreparationSHA256 is not null)
            throw WfpNative.Contract("DefaultDaclRequiresOriginalSuspendedGatewayChild");
        sessionPreparation.AssertCurrent();AssertSuspendedIdentity();
        KernelJobSeal.SessionObjectDescriptor.AssertSeal(process);KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread);
        var before=ReadToken(process);
        if(!before.IsAppContainer || !before.LpacAccessCheckObserved || before.ApplicationPackageAccessMask!=2 ||
            before.PackageSid!=packageSid || before.CapabilityCount!=0 || before.IntegritySid!="S-1-16-4096")
            throw WfpNative.Contract("DefaultDaclRequiresExactLpacIdentity");
        if(!OpenProcessToken(process,0x88,out var token))throw Error("OpenOwnChildDefaultDaclToken");
        using(token)
        using(var human=WindowsIdentity.GetCurrent(TokenAccessLevels.Query))
        {
            var user=ReadDefaultDaclTokenData(token,1,(pointer,length)=>
            {
                if(length<IntPtr.Size)throw WfpNative.Contract("DefaultDaclUserPointerBounds");
                var sid=Marshal.ReadIntPtr(pointer);var offset=sid.ToInt64()-pointer.ToInt64();
                if(offset<0 || offset>length-8 || Marshal.ReadByte(sid)!=1 || Marshal.ReadByte(sid,1)>15 ||
                    8+4*Marshal.ReadByte(sid,1)>length-offset)throw WfpNative.Contract("DefaultDaclUserSidBounds");
                return new SecurityIdentifier(sid).Value;
            });
            if(user!=human.User?.Value)throw WfpNative.Contract("DefaultDaclActualOwnerUserMismatch");
            var original=ReadOwnDefaultDacl(token);
            var prepared=OwnedObjectDefaultDaclPolicy.AddExactOwnerAce(original,user,packageSid);
            var intent=state.WriteNew("atomic-default-dacl-intent-"+job.JobId+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,state.InstallationId,SessionId=sessionPreparation.SessionId,job.JobId,Pid,
                CreatedFileTime=ExpectedCreatedFileTime,version.Package.Release,version.Package.ManifestHash,UserSid=user,PackageSid=packageSid,
                OriginalAcl=Convert.ToBase64String(original),PreparedAcl=Convert.ToBase64String(prepared),
                Scope="ONE_HELD_SUSPENDED_LPAC_CHILD_FUTURE_OBJECTS_ONLY",HostObjectAclModified=false,PrivilegesOrCapabilitiesModified=false
            }));
            var acl=Marshal.AllocHGlobal(prepared.Length);var information=IntPtr.Zero;
            try
            {
                Marshal.Copy(prepared,0,acl,prepared.Length);information=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(information,acl);
                if(!SetTokenInformation(token,6,information,(uint)IntPtr.Size))throw Error("SetOwnSuspendedChildDefaultDacl");
            }
            finally{if(information!=IntPtr.Zero)Marshal.FreeHGlobal(information);Marshal.FreeHGlobal(acl);}
            if(!OwnedObjectDefaultDaclPolicy.IsExactOwnerAddition(ReadOwnDefaultDacl(token),original,user,packageSid) || ReadToken(process)!=before)
                throw WfpNative.Contract("DefaultDaclReadbackOrLpacIdentityChanged");
            AssertSuspendedIdentity();KernelJobSeal.SessionObjectDescriptor.AssertSeal(process);KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread);
            DefaultDaclPreparationSHA256=state.WriteNew("atomic-default-dacl-prepared-"+job.JobId+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,state.InstallationId,SessionId=sessionPreparation.SessionId,job.JobId,Pid,IntentSHA256=intent,
                BeforeSHA256=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(original)),
                AfterSHA256=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(prepared)),
                LpacIdentityUnchanged=true,ExistingProcessAndThreadSealsUnchanged=true,FutureObjectsOnly=true
            }));
        }
    }
    private static byte[] ReadOwnDefaultDacl(SafeAccessTokenHandle token)=>ReadDefaultDaclTokenData(token,6,(pointer,length)=>
    {
        if(length<IntPtr.Size)throw WfpNative.Contract("DefaultDaclPointerBounds");
        var acl=Marshal.ReadIntPtr(pointer);var offset=acl.ToInt64()-pointer.ToInt64();
        if(offset<0 || offset>length-8)throw WfpNative.Contract("DefaultDaclBufferBounds");
        var size=unchecked((ushort)Marshal.ReadInt16(acl,2));
        if(size is <8 or >2048 || size>length-offset)throw WfpNative.Contract("DefaultDaclAclBounds");
        var bytes=new byte[size];Marshal.Copy(acl,bytes,0,size);return bytes;
    });
    private static T ReadDefaultDaclTokenData<T>(SafeAccessTokenHandle token,int kind,Func<IntPtr,int,T> consume)
    {
        if(GetTokenInformation(token,kind,IntPtr.Zero,0,out var length) || Marshal.GetLastWin32Error()!=122 || length is <4 or >65536)
            throw WfpNative.Contract("DefaultDaclTokenSizeUnavailable");
        var pointer=Marshal.AllocHGlobal(length);
        try
        {
            if(!GetTokenInformation(token,kind,pointer,length,out var used))throw Error("ReadOwnDefaultDaclTokenData");
            if(used<4 || used>length)throw WfpNative.Contract("DefaultDaclTokenReadBounds");
            return consume(pointer,used);
        }
        finally{Marshal.FreeHGlobal(pointer);}
    }
    internal void AssertSuspendedSessionIdentity(ProtectedSession.Preparation exactPreparation)
    {
        if(!ReferenceEquals(sessionPreparation,exactPreparation))throw WfpNative.Contract("ForeignSuspendedSessionRoot");
        AssertSuspendedIdentity();
    }
    internal void AssertSuspendedResourceIdentity(ProtectedSession.ResourceQualification permit)
    {
        if(!ReferenceEquals(resourceQualification,permit))throw WfpNative.Contract("ForeignResourceQualificationRoot");
        AssertSuspendedIdentity();
    }
    private void AssertSuspendedIdentity()
    {
        if(disposed || resumed || !IsRunning)throw WfpNative.Contract("LiveSuspendedSessionRootRequired");
        var snapshot=job.Observe();
        if(!snapshot.ExpectedLimits || snapshot.ActiveBefore!=1 || snapshot.ActiveAfter!=1 || snapshot.ProcessIds.Length!=1 || snapshot.ProcessIds[0]!=Pid ||
            !job.ContainsProcess(process) || GetProcessId(process)!=Pid)throw WfpNative.Contract("SuspendedSessionRootJobMismatch");
        var path=new StringBuilder(32768);uint length=(uint)path.Capacity;
        if(!QueryFullProcessImageName(process,0,path,ref length))throw Error("ReadSuspendedSessionImage");
        var token=ReadToken(process);
        if(!string.Equals(WindowsPathSeal.Canonical(path.ToString()),image,StringComparison.OrdinalIgnoreCase) ||
            !token.IsAppContainer || !token.LpacAccessCheckObserved || token.PackageSid!=packageSid || !CapabilityProfile.Matches(token.CapabilityCount,token.Capabilities) || token.IntegritySid!="S-1-16-4096")
            throw WfpNative.Contract("SuspendedSessionRootImageOrTokenMismatch");
    }
    internal static SafeProcessHandle HoldSessionPeer(OwnedKernelJob job,string sid,int sourcePort,LpacCapabilityProfile? capabilities=null)
    {
        var process=OpenProcess(0x101000,false,ProxyChannelLease.SessionPeerOwner(sourcePort));
        try
        {
            if(process.IsInvalid)throw Error("OpenSessionGatewayPeer");
            AssertSessionPeer(job,process,sid,sourcePort,capabilities);return process;
        }
        catch{process.Dispose();throw;}
    }
    internal static void AssertSessionPeer(OwnedKernelJob job,SafeProcessHandle process,string sid,int sourcePort,LpacCapabilityProfile? capabilities=null)
    {
        if(process.IsClosed || process.IsInvalid || WaitForSingleObject(process,0)!=0x102 || !job.ContainsProcess(process) ||
            ProxyChannelLease.SessionPeerOwner(sourcePort)!=GetProcessId(process))throw WfpNative.Contract("SessionGatewayPeerJobOrLifetimeMismatch");
        var token=ReadToken(process);
        if(!token.IsAppContainer || !token.LpacAccessCheckObserved || token.PackageSid!=sid || !(capabilities??LpacCapabilityProfile.None).Matches(token.CapabilityCount,token.Capabilities) || token.IntegritySid!="S-1-16-4096")
            throw WfpNative.Contract("SessionGatewayPeerTokenMismatch");
    }
    internal static (uint Pid,long CreatedFileTime) SessionPeerIdentity(SafeProcessHandle process)
    {
        var pid=GetProcessId(process);
        if(pid==0 || !GetProcessTimes(process,out var created,out _,out _,out _))throw Error("SessionGatewayPeerIdentity");
        return(pid,created);
    }
    internal static void InspectMembers(OwnedKernelJob job,JobSnapshot snapshot,Action<OwnedMemberInspection[]> whileHeld)
    {
        if(snapshot.JobId!=job.JobId || snapshot.ProcessIds.Length>64)throw WfpNative.Contract("BoundedExactJobInspectionRequired");
        // Keep every successfully opened process object alive through the
        // caller's second Job snapshot and decision. A recycled numeric PID
        // must not stand in for an inspected member between those operations.
        var held=new List<SafeProcessHandle>();
        try
        {
        var members=snapshot.ProcessIds.Select(pid=>
        {
            long? created=null;string? image=null;AdmissionToken? token=null;bool member=false;Exception? failure=null;
            try
            {
                var process=OpenProcess(0x101000,false,pid);held.Add(process);if(process.IsInvalid)throw Error("InspectOwnedMemberOpen");
                member=job.ContainsProcess(process);if(!member)throw WfpNative.Contract("InspectedProcessNotInExactJob");
                if(WaitForSingleObject(process,0)!=0x102)throw WfpNative.Contract("InspectedMemberNotRunning");
                if(!GetProcessTimes(process,out var at,out _,out _,out _))throw Error("InspectOwnedMemberCreation");created=at;
                var path=new StringBuilder(32768);uint length=(uint)path.Capacity;if(!QueryFullProcessImageName(process,0,path,ref length))throw Error("InspectOwnedMemberImage");image=path.ToString();
                token=ReadToken(process);
            }
            catch(Exception ex){failure=ex;}
            return new OwnedMemberInspection(pid,member,created,image,token,failure is null?Array.Empty<WfpErrorEvidence>():WfpNative.Describe(failure));
        }).ToArray();
        whileHeld(members);
        }
        finally{foreach(var handle in held)handle.Dispose();}
    }
    private AtomicChild(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,ProcessInfo info,string image,string sid,NetworkProbePlan? network,bool gpuWorkload,ProtectedSession.Preparation? preparation,ProtectedSession.ResourceQualification? resources,bool schannelWorkload)
    {
        this.state=state;this.version=version;this.job=job;this.image=image;packageSid=sid;Pid=info.ProcessId;this.network=network;this.gpuWorkload=gpuWorkload;
        process=new(info.Process,true);thread=new(info.Thread,true);sessionPreparation=preparation;resourceQualification=resources;this.schannelWorkload=schannelWorkload;
    }
    internal static AtomicChild CreateCanary(FixedLayout layout,ProtectedState state,VerifiedVersion version,OwnedKernelJob job,InstallationProfileLease profile,
        NetworkProbePlan? network=null,IntPtr output=default,GpuProbePlan? gpu=null)
        =>CreateCore(layout,state,version,job,profile,network,output,gpu,null,null);
    internal static AtomicChild CreateSchannelQualification(FixedLayout layout,ProtectedState state,VerifiedVersion version,
        OwnedKernelJob job,InstallationProfileLease profile,string sessionId,IntPtr output)
        =>CreateCore(layout,state,version,job,profile,null,output,null,null,null,Identifiers.Hex32(sessionId));
    internal static AtomicChild CreateResourceQualification(FixedLayout layout,ProtectedState state,VerifiedVersion version,OwnedKernelJob job,
        InstallationProfileLease profile,ProtectedSession.ResourceQualification permit,IntPtr output)
    {
        var child=CreateCore(layout,state,version,job,profile,null,output,null,null,permit);
        try{permit.BindCreated(child);return child;}catch{child.Dispose();throw;}
    }
    internal static AtomicChild CreateSession(FixedLayout layout,ProtectedState state,VerifiedVersion version,OwnedKernelJob job,InstallationProfileLease profile,
        ProtectedSession.Preparation preparation,IntPtr report=default)
    {
        if(preparation.IsGatewayQualification!=(report!=IntPtr.Zero))throw WfpNative.Contract("FixedGatewayReportHandleRequiredExactly");
        var child=CreateCore(layout,state,version,job,profile,null,report,null,preparation,null);
        try{preparation.BindCreated(child);return child;}catch{child.Dispose();throw;}
    }
    private static AtomicChild CreateCore(FixedLayout layout,ProtectedState state,VerifiedVersion version,OwnedKernelJob job,InstallationProfileLease profile,
        NetworkProbePlan? network,IntPtr output,GpuProbePlan? gpu,ProtectedSession.Preparation? preparation,ProtectedSession.ResourceQualification? resources,
        string? schannelSession=null)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);
        preparation?.BeforeCreate(job,version);
        resources?.BeforeCreate(job,version);
        if(resources is not null && (preparation is not null || network is not null || gpu is not null))throw WfpNative.Contract("ResourceQualificationCannotBorrowOtherAuthority");
        if(preparation is not null && (network is not null || gpu is not null))throw WfpNative.Contract("SuspendedSessionCannotBorrowQualificationPlan");
        if(!Environment.Is64BitProcess || Marshal.SizeOf<StartupInfo>()!=104 || Marshal.SizeOf<StartupInfoEx>()!=112 || Marshal.SizeOf<SecurityCapabilities>()!=24)
            throw new PlatformNotSupportedException("Atomic admission requires the declared x64 layout");
        var schannel=schannelSession is not null;
        if(schannel && (preparation is not null || resources is not null || network is not null || gpu is not null))
            throw WfpNative.Contract("SchannelQualificationCannotBorrowOtherAuthority");
        var requireLpac=preparation is not null || resources is not null || gpu is not null || schannel;
        if(requireLpac && Marshal.SizeOf<KernelJobSeal.SecurityAttributes>()!=24)
            throw new PlatformNotSupportedException("Suspended session security attributes require the declared x64 layout");
        var image=WindowsPathSeal.Child(layout.Version(version.Package.Release),"bin/admin/ProtectionBroker.exe");
        network?.Validate();gpu?.Validate();if(network is not null && gpu is not null)throw WfpNative.Contract("OneFixedQualificationWorkloadRequired");
        var report=network is not null || gpu is not null || resources is not null || preparation?.IsGatewayQualification==true || schannel;if(report!=(output!=IntPtr.Zero))throw WfpNative.Contract("ReportHandleRequiredExactlyForQualificationWorkload");
        using var package=network?.Kind==NetworkProbeKind.Control?InstallationPackageSid.ForNetworkControl(state):new InstallationPackageSid(state);
        profile.AssertPackage(package);
        var jobHandle=job.ReserveAtomicAdmission(version);
        using var capabilityAttributes=(preparation?.CapabilityProfile??FixedCapabilities(schannel)).AllocateAttributes();
        IntPtr attributes=IntPtr.Zero,capabilities=IntPtr.Zero,jobList=IntPtr.Zero,environment=IntPtr.Zero,handles=IntPtr.Zero,packagesPolicy=IntPtr.Zero;
        bool initialized=false,handleHeld=false;
        try
        {
            jobHandle.DangerousAddRef(ref handleHeld);
            var count=(report?3:2)+(requireLpac?1:0);
            nuint size=0;_=InitializeProcThreadAttributeList(IntPtr.Zero,count,0,ref size);
            if(size is 0 or >65536)throw Error("AtomicAttributeListSize");
            attributes=Marshal.AllocHGlobal(checked((int)size));
            if(!InitializeProcThreadAttributeList(attributes,count,0,ref size))throw Error("AtomicInitializeAttributes");initialized=true;
            capabilities=Marshal.AllocHGlobal(Marshal.SizeOf<SecurityCapabilities>());
            Marshal.StructureToPtr(new SecurityCapabilities{Sid=package.Pointer,Capabilities=capabilityAttributes.Pointer,Count=capabilityAttributes.Count},capabilities,false);
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x20009,capabilities,(nuint)Marshal.SizeOf<SecurityCapabilities>(),IntPtr.Zero,IntPtr.Zero))throw Error("AtomicSetPackageAtCreation");
            if(requireLpac)
            {
                // PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY.
                // OPT_OUT is set at creation, while Job and package are bound.
                // No regular-AppContainer retry or caller override.
                packagesPolicy=Marshal.AllocHGlobal(sizeof(uint));Marshal.WriteInt32(packagesPolicy,1);
                if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x2000f,packagesPolicy,sizeof(uint),IntPtr.Zero,IntPtr.Zero))throw Error("AtomicRequireLpacAtCreation");
            }
            jobList=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(jobList,jobHandle.DangerousGetHandle());
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x2000d,jobList,(nuint)IntPtr.Size,IntPtr.Zero,IntPtr.Zero))throw Error("AtomicSetJobListAtCreation");
            if(report)
            {
                handles=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(handles,output);
                if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x20002,handles,(nuint)IntPtr.Size,IntPtr.Zero,IntPtr.Zero))throw Error("AtomicSetOnlyReportHandleInheritance");
            }
            var env=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            var inherited=!requireLpac?new[]{"SystemRoot","windir","SystemDrive","ProgramFiles","ProgramFiles(x86)","ProgramW6432","PROCESSOR_ARCHITECTURE","LOCALAPPDATA","USERPROFILE","TEMP","TMP"}:
                new[]{"SystemRoot","windir","SystemDrive","ProgramFiles","ProgramFiles(x86)","ProgramW6432","PROCESSOR_ARCHITECTURE"};
            foreach(var name in inherited)
            {var value=Environment.GetEnvironmentVariable(name);if(value is not null)env[name]=value;}
            env["PATH"]="C:\\Program Files\\dotnet;C:\\Windows\\System32;C:\\Windows";
            env["DOTNET_ROOT"]="C:\\Program Files\\dotnet";env["DOTNET_ROLL_FORWARD"]="LatestPatch";
            if(network is not null)env["CPC_NETWORK_PLAN"]=JsonSerializer.Serialize(network);
            if(gpu is not null)
            {
                SetPrivateRuntimeDirectories(env,profile.WorkspaceRoot());
                env["CPC_GPU_PLAN"]=JsonSerializer.Serialize(gpu);env["CUDA_CACHE_DISABLE"]="1";
            }
            if(resources is not null)
            {
                env["CPC_RESOURCE_PLAN"]=JsonSerializer.Serialize(resources.Plan);
                SetPrivateRuntimeDirectories(env,resources.Workspace);
            }
            if(schannel)
            {
                SetPrivateRuntimeDirectories(env,profile.WorkspaceRoot());
                env["CPC_SCHANNEL_SESSION"]=schannelSession!;
            }
            if(preparation is not null)
            {
                // Creation requires LOCALAPPDATA; use the original freshly
                // owned profile, never the host user profile or inherited temp.
                SetPrivateRuntimeDirectories(env,profile.WorkspaceRoot());
                env["CPC_SESSION_ID"]=preparation.SessionId;env["CPC_SESSION_SECRET"]=preparation.Gateway.Secret;
                if(preparation.IsGatewayQualification)
                {
                    // The fixed qualifier may resolve only the public definition
                    // selected by its original owner, not enumerate other zones.
                    var zone=preparation.PublicTimeZoneId??throw WfpNative.Contract("FixedPublicTimeZoneSelectionMissing");
                    env["CPC_PUBLIC_TIMEZONE_ID"]=zone;
                    var snapshot=preparation.PublicTimeZone??throw WfpNative.Contract("FixedPublicTimeZoneSnapshotMissing");
                    env["CPC_PUBLIC_TIMEZONE_SNAPSHOT"]=snapshot.Payload;
                    env["CPC_PUBLIC_TIMEZONE_SHA256"]=snapshot.SHA256;
                }
                var endpoint="http://"+preparation.SessionId+":"+preparation.Gateway.Secret+"@127.0.0.1:"+SessionProxy.Port;
                foreach(var name in new[]{"HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"})env[name]=endpoint;
                env["NO_PROXY"]="";
            }
            var environmentBlock=string.Join('\0',env.Select(p=>p.Key+"="+p.Value))+"\0\0";
            if(preparation?.IsGatewayQualification==true && environmentBlock.Length>32760)throw WfpNative.Contract("FixedGatewayEnvironmentBounds");
            environment=Marshal.StringToHGlobalUni(environmentBlock);
            var startup=new StartupInfoEx{Basic=new(){Size=Marshal.SizeOf<StartupInfoEx>()},Attributes=attributes};
            if(report){startup.Basic.Flags=0x100;startup.Basic.Output=output;startup.Basic.Error=output;}
            var command=new StringBuilder("\""+image+"\" "+(schannel?"schannel-acquisition-child":preparation?.ChildCommand??"admission-child"));
            // The OS binds BOTH identity and Job before returning a suspended
            // initial thread. Only the explicit qualification report handle
            // may be inherited; no breakaway permission is enabled.
            profile.BeforeProcessCreation(job.JobId);
            ProcessInfo info;
            if(requireLpac)
            {
                using var descriptor=new KernelJobSeal.SessionObjectDescriptor();
                var processAttributes=descriptor.Attributes;var threadAttributes=descriptor.Attributes;
                if(!CreateSealedProcess(image,command,ref processAttributes,ref threadAttributes,report,0x08080404,environment,resources?.Workspace??Path.GetDirectoryName(image)!,ref startup,out info))
                    throw Error("AtomicCreateSealedSuspendedSession");
            }
            else if(!CreateProcess(image,command,IntPtr.Zero,IntPtr.Zero,report,0x08080404,environment,Path.GetDirectoryName(image)!,ref startup,out info))
                throw Error("AtomicCreateSuspendedWithPackageAndJob");
            var child=new AtomicChild(state,version,job,info,image,package.Value,network,gpu is not null,preparation,resources,schannel);
            try
            {
                if(requireLpac){KernelJobSeal.SessionObjectDescriptor.AssertSeal(child.process);KernelJobSeal.SessionObjectDescriptor.AssertSeal(child.thread);}
                return child;
            }
            catch{child.Dispose();throw;}
        }
        finally
        {
            if(initialized)DeleteProcThreadAttributeList(attributes);
            if(attributes!=IntPtr.Zero)Marshal.FreeHGlobal(attributes);
            if(capabilities!=IntPtr.Zero)Marshal.FreeHGlobal(capabilities);
            if(jobList!=IntPtr.Zero)Marshal.FreeHGlobal(jobList);
            if(environment!=IntPtr.Zero)Marshal.FreeHGlobal(environment);
            if(handles!=IntPtr.Zero)Marshal.FreeHGlobal(handles);
            if(packagesPolicy!=IntPtr.Zero)Marshal.FreeHGlobal(packagesPolicy);
            if(handleHeld)jobHandle.DangerousRelease();
        }
    }
    internal object ResumeQuarantined(ProxyChannelLease? proxy=null,ProtectedSession.Admission? sessionPermit=null)
    {
        if(disposed || resumed)throw new InvalidOperationException("Canary resume is one-shot");
        if(sessionPreparation is not null)
        {
            if(sessionPermit is null || !sessionPermit.Matches(sessionPreparation))throw WfpNative.Contract("FullSessionPermitRequiredBeforeFirstInstruction");
            AssertSuspendedSessionIdentity(sessionPreparation);
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(process);KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread);
            sessionAdmission=sessionPermit;
        }
        else if(sessionPermit is not null)throw WfpNative.Contract("SessionPermitCannotAuthorizeLegacyCanary");
        if(resourceQualification is not null)
        {
            if(proxy is not null || sessionPermit is not null)throw WfpNative.Contract("OfflineResourceQualificationCannotUseNetworkPermit");
            AssertSuspendedResourceIdentity(resourceQualification);
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(process);KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread);
            resourceQualification.AssertCurrent();
        }
        if(gpuWorkload)
        {
            if(proxy is not null)throw WfpNative.Contract("GpuQualificationRequiresOfflineQuarantine");
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(process);
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread);
        }
        if(schannelWorkload)
        {
            if(proxy is not null || sessionPermit is not null)throw WfpNative.Contract("SchannelQualificationRequiresOfflineQuarantine");
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(process);
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread);
        }
        state.AssertHeld();version.AssertHeld(state);
        sessionAdmission?.AssertCurrent();
        var snapshot=job.Observe();
        if(!snapshot.ExpectedLimits || snapshot.ActiveBefore!=1 || snapshot.ActiveAfter!=1 || snapshot.ProcessIds.Length!=1 || snapshot.ProcessIds[0]!=Pid)
            throw WfpNative.Contract("AtomicJobMembershipBeforeResumeMismatch");
        if(!GetProcessTimes(process,out var created,out _,out _,out _))throw Error("AtomicReadCreationTime");
        var path=new StringBuilder(32768);uint length=(uint)path.Capacity;
        if(!QueryFullProcessImageName(process,0,path,ref length))throw Error("AtomicReadCreatedImage");
        if(!string.Equals(WindowsPathSeal.Canonical(path.ToString()),image,StringComparison.OrdinalIgnoreCase))throw WfpNative.Contract("AtomicCreatedImageMismatch");
        var token=ReadToken(process);
        if(!token.IsAppContainer || RequiresLpac && !token.LpacAccessCheckObserved || token.PackageSid!=packageSid || !CapabilityProfile.Matches(token.CapabilityCount,token.Capabilities) || token.IntegritySid!="S-1-16-4096")throw WfpNative.Contract("AtomicTokenBeforeResumeMismatch");
        var plans=FencePlan.ReadAll(state);if(plans.Count==0)throw WfpNative.Contract("AtomicResumeRequiresRegisteredFence");
        var observations=new List<FenceObservation>();
        var proxyOnly=network?.RequiresProxy==true;
        if(proxyOnly){if(proxy is null)throw WfpNative.Contract("NetworkProxyAdmissionNeedsLiveIdentityLease");proxy.AssertHealthy();}
        foreach(var plan in plans)
        {
            using var fence=PersistentFence.OpenExisting(state,plan.Data.FenceId);var observed=fence.Observe();
            if(sessionAdmission is not null)
            {
                sessionAdmission.Gateway.AssertHealthy();
                if(!fence.IsSessionChannel || !observed.IPv4ProxyOnlyObserved)throw WfpNative.Contract("SessionResumeRequiresGatewayFenceOnly");
            }
            else if(proxyOnly?!observed.IPv4ProxyOnlyObserved:!observed.FullQuarantineObserved)throw WfpNative.Contract("AtomicResumeRequiresCommittedExpectedFence");
            observations.Add(observed);
        }
        var proof=new {SchemaVersion=1,state.InstallationId,job.JobId,Pid,CreatedFileTime=created.ToString("X16"),Token=token,
            ExpectedCapabilitiesSHA256=CapabilityProfile.SHA256,ObservedCapabilities=token.Capabilities?.CopyEntries(),
            ImageSHA256=version.Package.Files.Single(f=>f.Asset.Id=="broker-exe").SHA256,Job=snapshot,Fences=observations,
            Binding="SECURITY_CAPABILITIES_AND_JOB_LIST_AT_CREATION",Status="BEFORE_FIRST_RESUME",NetworkBehaviorQualified=false,
            SessionBindingSHA256=sessionAdmission?.BindingSHA256,
            Scope=sessionAdmission is not null?"AUTHENTICATED_SESSION_GATEWAY":network?.Kind==NetworkProbeKind.Control?"UNFENCED_OWNED_LOOPBACK_CONTROL":proxyOnly?"COMPILED_IPV4_PROXY_ONLY":gpuWorkload?"FIXED_CUDA_FULL_QUARANTINE":schannelWorkload?"FIXED_SCHANNEL_FULL_QUARANTINE":"FULL_QUARANTINE"};
        state.WriteNew("admission-before-resume-"+job.JobId+".json",JsonSerializer.SerializeToUtf8Bytes(proof));
        sessionAdmission?.BeforeResume(this);
        resourceQualification?.BeforeResume(this);
        ResumeAttempted=true;
        var previous=ResumeThread(thread);if(previous==uint.MaxValue)throw Error("AtomicResumePrimaryThread");
        if(previous!=1)throw WfpNative.Contract("AtomicInitialSuspendCountMismatch");
        resumed=true;return proof;
    }
    internal uint WaitForCanaryExit()
    {
        return ObserveCanaryExit(network?.Kind==NetworkProbeKind.ProxySession?90000u:network is not null || gpuWorkload?30000u:15000u)
            ??throw new TimeoutException("Finite atomic canary did not exit");
    }
    internal void AssertGpuRuntimeOwner(ProtectedState exactState,VerifiedVersion exactVersion,OwnedKernelJob exactJob)
    {
        if(!gpuWorkload || disposed || resumed || !IsRunning || !ReferenceEquals(state,exactState) ||
            !ReferenceEquals(version,exactVersion) || !ReferenceEquals(job,exactJob) || !job.ContainsProcess(process))
            throw WfpNative.Contract("GpuRuntimeRequiresExactSuspendedChild");
    }
    internal uint? ObserveFixedGpuExit()
    {
        if(!gpuWorkload)throw WfpNative.Contract("FixedGpuWorkloadRequired");
        return ObserveCanaryExit(100);
    }
    internal void AssertSchannelRuntimeOwner(ProtectedState exactState,VerifiedVersion exactVersion,OwnedKernelJob exactJob)
    {
        if(!schannelWorkload || disposed || resumed || !IsRunning || !ReferenceEquals(state,exactState) ||
            !ReferenceEquals(version,exactVersion) || !ReferenceEquals(job,exactJob) || !job.ContainsProcess(process))
            throw WfpNative.Contract("SchannelRuntimeRequiresExactSuspendedChild");
    }
    internal uint? ObserveFixedSchannelExit()
    {
        if(!schannelWorkload)throw WfpNative.Contract("FixedSchannelWorkloadRequired");
        return ObserveCanaryExit(100);
    }
    internal static int RunSchannelAcquisitionChild()
    {
        var id=Identifiers.Hex32(Environment.GetEnvironmentVariable("CPC_SCHANNEL_SESSION")??"");
        if(new[]{"CPC_SESSION_ID","CPC_SESSION_SECRET","CPC_NETWORK_PLAN","CPC_RESOURCE_PLAN","CPC_GPU_PLAN",
            "HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"}.Any(name=>Environment.GetEnvironmentVariable(name) is not null))
            throw WfpNative.Contract("SchannelWorkerCannotBorrowOtherAuthority");
        using var self=new SafeProcessHandle((IntPtr)(-1),false);
        var token=ReadToken(self,false);
        if(!token.IsAppContainer || token.PackageSid is null || token.IntegritySid!="S-1-16-4096" ||
            !FixedCapabilities(true).Matches(token.CapabilityCount,token.Capabilities))
            throw WfpNative.Contract("SchannelWorkerIdentityRefused");
        Console.WriteLine(JsonSerializer.Serialize(SchannelAcquisition.Observe(id)));
        return 0;
    }
    private uint? ObserveCanaryExit(uint milliseconds)
    {
        if(!resumed || disposed)throw new InvalidOperationException("Canary has not resumed");
        var status=WaitForSingleObject(process,milliseconds);
        if(status==0x102)return null;
        if(status!=0)throw Error("AtomicCanaryWait");
        if(!GetExitCodeProcess(process,out var code))throw Error("AtomicCanaryExitCode");return code;
    }
    internal static void SetPrivateRuntimeDirectories(IDictionary<string,string> environment,string ownedDirectory)
    {
        // Pure mapping only. The creation owner supplies its bound profile or
        // resource workspace; this helper accepts no path operation or grant.
        if(string.IsNullOrEmpty(ownedDirectory) || ownedDirectory.Contains('\0'))
            throw new InvalidDataException("OwnedRuntimeDirectoryRequired");
        foreach(var name in new[]{"TEMP","TMP","LOCALAPPDATA","USERPROFILE"})environment[name]=ownedDirectory;
    }
    internal static void ConfigureFixedChildCulture()
    {
        // Only this fixed worker opts in. Do not alter the owner, GUI, Windows
        // locale/time zone or grant registry access for framework localization.
        var invariant=System.Globalization.CultureInfo.InvariantCulture;
        System.Globalization.CultureInfo.DefaultThreadCurrentCulture=invariant;
        System.Globalization.CultureInfo.DefaultThreadCurrentUICulture=invariant;
        System.Globalization.CultureInfo.CurrentCulture=invariant;
        System.Globalization.CultureInfo.CurrentUICulture=invariant;
    }
    internal static int RunGatewayQualificationCanary()
        =>RunGatewayQualificationCanaryCore(LpacCapabilityProfile.None,false);
    internal static int RunInternetClientGatewayQualificationCanary()
        =>RunGatewayQualificationCanaryCore(LpacCapabilityProfile.InternetClientQualification,true);
    internal static int RunNoContentHttpsCanary()
        =>RunGatewayQualificationCanaryCore(LpacCapabilityProfile.InternetClientQualification,true,true);
    internal static int RunZeroCapabilityComparisonCanary()
        =>RunGatewayQualificationCanaryCore(LpacCapabilityProfile.None,true);
    private static int RunGatewayQualificationCanaryCore(LpacCapabilityProfile expectedCapabilities,bool captureCapabilityContent,bool fixedNoContentHttpsCanary=false)
    {
        var phase="ENVIRONMENT";var id=Environment.GetEnvironmentVariable("CPC_SESSION_ID")??"";GatewayChildReport result;
        GatewayNetworkContent? networkContent=null;
        GatewayCapabilityEndpoint? endpoint=null;
        try
        {
            ConfigureFixedChildCulture();
            var secret=Environment.GetEnvironmentVariable("CPC_SESSION_SECRET");
            var publicTimeZone=Environment.GetEnvironmentVariable("CPC_PUBLIC_TIMEZONE_ID")??throw new InvalidDataException("FixedPublicTimeZoneMissing");
            _=PublicTimeZoneDefinition.PathFor(publicTimeZone,"ZONE_DEFINITION");
            if(id.Length==0 || secret is null || new[]{"CPC_RESOURCE_PLAN","CPC_NETWORK_PLAN","CPC_GPU_PLAN"}.Any(name=>Environment.GetEnvironmentVariable(name) is not null))
                throw new InvalidDataException("FixedGatewayEnvironmentRefused");
            _=Identifiers.Hex32(id);_=Identifiers.Hash(secret);
            // As in the verified resource worker, query basic self identity
            // without token duplication. The original Broker checks the exact
            // held LPAC before resume and on every admitted member inspection.
            phase="IDENTITY";using var current=new SafeProcessHandle((IntPtr)(-1),false);var token=ReadToken(current,false);
            if(!token.IsAppContainer || token.PackageSid is null || !expectedCapabilities.Matches(token.CapabilityCount,token.Capabilities) || token.IntegritySid!="S-1-16-4096")
                result=GatewayChildReport.Result(id,phase,125);
            else
            {
                if(captureCapabilityContent)
                {
                    // One unbound socket is created and immediately closed;
                    // no connect/bind/listen/IOCTL or external request. Continue
                    // the real reads even when endpoint creation is refused.
                    phase="NETWORK_CONTENT_READS";endpoint=GatewayCapabilityEndpoint.Observe();networkContent=GatewayCapabilityContent.Capture();
                    if(!(fixedNoContentHttpsCanary?networkContent.FixedNoContentHttpsCanaryEligible:networkContent.AllThreeDenied))
                    {
                        phase="NETWORK_CONTENT_REQUIRES_ANALYSIS";
                        throw new InvalidDataException("FixedNetworkCapabilityReadRequiresOwnerAnalysis");
                    }
                    if(endpoint is not {Created:true,OwnedHandleClosed:true,Phase:"SOCKET_CLOSED"})
                    {
                        phase=endpoint.Phase=="SOCKET_INITIALIZATION"?"HTTPS_SOCKET_INITIALIZATION":"HTTPS_SOCKET_CREATE";
                        throw new InvalidDataException("FixedNetworkCapabilityEndpointNotConfirmed");
                    }
                }
                // The historical leaf-only lease did not repair predefined
                // hive mapping. Use the original owner's public calendar
                // with a pinned managed compatibility adapter; never add
                // registryRead or treat the adapter as a privacy boundary.
                phase="TIMEZONE_PUBLIC_CACHE";
                PublicTimeZoneSnapshot.ApplyForFixedWorker(
                    Environment.GetEnvironmentVariable("CPC_PUBLIC_TIMEZONE_SNAPSHOT")??throw new InvalidDataException("FixedPublicTimeZoneSnapshotMissing"),
                    Environment.GetEnvironmentVariable("CPC_PUBLIC_TIMEZONE_SHA256")??throw new InvalidDataException("FixedPublicTimeZoneDigestMissing"),id,publicTimeZone);
                phase="TIMEZONE_LOCAL_BINDING";var localZone=TimeZoneInfo.Local;
                // Keep the OS's current daylight-saving setting. A public
                // definition's default rules do not override local settings.
                if(localZone.Id!=publicTimeZone)
                    throw new InvalidDataException("FixedGatewayLocalTimeZoneDefinitionDiffers");
                phase="HTTPS_SETTINGS";var status=RunFixedSessionHead(id,secret,p=>phase=p);
                result=GatewayChildReport.Result(id,status is >=200 and <400?"COMPLETE":"HTTPS",status is >=200 and <400?42:126,status);
            }
        }
        catch(Exception ex){result=GatewayChildReport.Result(id,phase,125,failure:ex);}
        Console.WriteLine(captureCapabilityContent?
            JsonSerializer.Serialize(new GatewayCapabilityChildReport(1,result,endpoint,networkContent)):JsonSerializer.Serialize(result));return result.ExitCode;
    }
    private static int RunFixedSessionHead(string sessionId,string sessionSecret,Action<string>? phase=null)
    {
        phase?.Invoke("HTTPS_SETTINGS");
        var tunnelConsumed=0;
        using var handler=new SocketsHttpHandler {UseProxy=false,AllowAutoRedirect=false,UseCookies=false,
            ConnectCallback=async (context,cancel)=>
            {
                if(context.DnsEndPoint.Host!=SessionProxy.Target || context.DnsEndPoint.Port!=443)throw WfpNative.Contract("FixedSessionHttpTargetRefused");
                SessionProxy.ConsumeFixedTunnelAttempt(ref tunnelConsumed);
                var tunnel=await SessionProxy.OpenFixedClientTunnel(sessionId,sessionSecret,cancel,phase).ConfigureAwait(false);
                phase?.Invoke("HTTPS_TLS_HANDSHAKE");
                return tunnel;
            }};
        if(phase is not null)
            handler.PlaintextStreamFilter=(context,_)=>
            {
                phase("HTTPS_HTTP_EXCHANGE");
                return ValueTask.FromResult(context.PlaintextStream);
            };
        phase?.Invoke("HTTPS_TLS_POLICY");handler.SslOptions=SessionProxy.OfflineTls();
        phase?.Invoke("HTTPS_CLIENT");
        using var client=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(10)};
        // Headers only; an unread GET body would abort its own TLS tunnel.
        using var request=new HttpRequestMessage(HttpMethod.Head,"https://"+SessionProxy.Target+"/") {
            Version=System.Net.HttpVersion.Version11,VersionPolicy=HttpVersionPolicy.RequestVersionExact};
        phase?.Invoke("HTTPS_SEND");
        using var response=client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();
        return (int)response.StatusCode;
    }
    internal static int RunCanary()
    {
        using var current=new SafeProcessHandle((IntPtr)(-1),false);var token=ReadToken(current);
        if(!token.IsAppContainer || token.CapabilityCount!=0 || token.IntegritySid!="S-1-16-4096")return 125;
        var plan=Environment.GetEnvironmentVariable("CPC_NETWORK_PLAN");
        var gpuPlan=Environment.GetEnvironmentVariable("CPC_GPU_PLAN");if(plan is not null && gpuPlan is not null)return 125;
        var sessionId=Environment.GetEnvironmentVariable("CPC_SESSION_ID");
        var sessionSecret=Environment.GetEnvironmentVariable("CPC_SESSION_SECRET");
        if(sessionId is not null || sessionSecret is not null)
        {
            if(!token.LpacAccessCheckObserved)return 125;
            if(plan is not null || gpuPlan is not null || sessionId is null || sessionSecret is null)return 125;
            _=Identifiers.Hex32(sessionId);_=Identifiers.Hash(sessionSecret);
            return RunFixedSessionHead(sessionId,sessionSecret) is >=200 and <400?42:126;
        }
        if(gpuPlan is not null)
        {
            if(gpuPlan.Length>256 || !token.LpacAccessCheckObserved || token.ApplicationPackageAccessMask!=2)
                throw WfpNative.Contract("GpuPlanOrLpacIdentityRefused");
            var gpu=JsonSerializer.Deserialize<GpuProbePlan>(gpuPlan)??throw WfpNative.Contract("GpuPlanMissing");gpu.Validate();
            var progress=gpu.ProgressProtocol==1?new GpuCallProgressWriter(Console.Out,gpu.Nonce,Environment.ProcessId):null;
            var computed=GpuQualification.Compute(gpu,GpuQualification.LpacScope,progress);Console.WriteLine(JsonSerializer.Serialize(computed));return GpuQualification.Qualified(computed)?0:3;
        }
        if(plan is not null)
        {
            if(plan.Length>8192)throw WfpNative.Contract("NetworkPlanSizeRefused");
            var network=JsonSerializer.Deserialize<NetworkProbePlan>(plan)??throw WfpNative.Contract("MissingNetworkPlan");network.Validate();
            var report=NetworkQualification.RunChild(network).GetAwaiter().GetResult();Console.WriteLine(JsonSerializer.Serialize(report));
            if(network.Kind==NetworkProbeKind.ProxySession && report.FailureMask==0)
            {
                // Fixed owned-loopback attempts keep the admitted child alive
                // during watchdog qualification. No children or extra targets.
                var clock=Stopwatch.StartNew();while(clock.ElapsedMilliseconds<60000)
                {Thread.Sleep(100);if(!NetworkQualification.NegativeCasesEligible(NetworkQualification.RawCases(network).GetAwaiter().GetResult()))return 126;}
                return 124; // Finite fallback is not watchdog success.
            }
            return report.FailureMask;
        }
        Thread.Sleep(200);return 42; // No network, state, file writes or children.
    }
    internal static int RunResourceCanary()
    {
        var phase="self-token";
        try
        {
            // The trusted manager MUST have checked LPAC on this exact held
            // process before ResumeQuarantined. A child cannot issue admission;
            // it only queries its basic identity, then attempts real resource
            // denial. Do not require token duplication inside the restricted
            // worker merely to repeat a privileged management observation.
            using var current=new SafeProcessHandle((IntPtr)(-1),false);var token=ReadToken(current,false);
            if(!token.IsAppContainer || token.CapabilityCount!=0 || token.IntegritySid!="S-1-16-4096" || token.PackageSid is null)
                throw WfpNative.Contract("RestrictedResourceChildTokenMismatch");
            phase="resource-input";return SessionResources.RunChild(token.PackageSid);
        }
        catch(Exception ex)
        {
            var native=ex.Data["Stage"] as string;
            if(native is not null && (native.Length>80 || native.Any(c=>!char.IsAsciiLetterOrDigit(c))))native=null;
            Console.WriteLine(JsonSerializer.Serialize(new ResourceBootstrapFailure(1,"RESOURCE_BOOTSTRAP_FAILURE",phase,ex.GetType().Name,
                ex is Win32Exception win32?win32.NativeErrorCode:ex.HResult,native)));return 125;
        }
    }
    // The restricted worker requests only the compiled fixed tool operations.
    // Its original Broker performs Windows startup bookkeeping, while package,
    // OPT_OUT and the original Job are atomically bound before first execution.
    // There is no elevated tool, arbitrary command endpoint or AC fallback.
    internal static InheritedTool StartInheritedTool(ProcessStartInfo start)
    {
        using var self=new SafeProcessHandle((IntPtr)(-1),false);var token=ReadToken(self,false);
        if(!token.IsAppContainer || token.CapabilityCount!=0 || token.IntegritySid!="S-1-16-4096" || token.PackageSid is null ||
            !IsProcessInJob(self,IntPtr.Zero,out var inJob) || !inJob)
            throw WfpNative.Contract("InheritedToolRequiresConfinedWorker");
        if(start.UseShellExecute || !start.CreateNoWindow || !start.RedirectStandardInput || !start.RedirectStandardOutput || !start.RedirectStandardError ||
            start.UserName.Length!=0 || start.Arguments.Length!=0 || !Path.IsPathFullyQualified(start.FileName) || !Path.IsPathFullyQualified(start.WorkingDirectory))
            throw WfpNative.Contract("InheritedToolStartContractRefused");
        _=InheritedToolCommand(start.FileName,start.ArgumentList.ToArray());
        var evidence=InspectToolCreationPrerequisites(start.FileName);
        return OwnedToolLaunch.Request(start,token.PackageSid,evidence);
    }
    internal static string AssertRestrictedToolSelf()
    {
        using var self=new SafeProcessHandle((IntPtr)(-1),false);var token=ReadToken(self,false);
        if(!token.IsAppContainer || token.CapabilityCount!=0 || token.IntegritySid!="S-1-16-4096" || token.PackageSid is null ||
            !IsProcessInJob(self,IntPtr.Zero,out var inJob) || !inJob)throw WfpNative.Contract("PowerShellRequiresConfinedTool");
        return token.PackageSid;
    }
    internal InheritedTool StartOwnedTool(OwnedKernelJob job,ProtectedSession.ResourceQualification permit,ProcessStartInfo start)
    {
        permit.AuthorizeToolCreation(this,job);
        if(disposed || !resumed || !IsRunning || !job.ContainsProcess(process))throw WfpNative.Contract("OwnedToolOriginalRootRequired");
        var token=ReadToken(process);
        if(!token.IsAppContainer || !token.LpacAccessCheckObserved || token.PackageSid!=packageSid || token.CapabilityCount!=0 || token.IntegritySid!="S-1-16-4096")
            throw WfpNative.Contract("OwnedToolOriginalRootTokenChanged");
        return CreateInheritedTool(start,InheritedToolCommand(start.FileName,start.ArgumentList.ToArray()),token,
            InspectToolCreationPrerequisites(start.FileName),job,permit);
    }
    internal ToolLaunchReply TransferToolHandles(InheritedTool tool,int sequence,string nonce)=>tool.TransferTo(process,checked((int)Pid),sequence,nonce);
    private static ToolCreationEvidence InspectToolCreationPrerequisites(string fixedImage)
    {
        using var self=new SafeProcessHandle((IntPtr)(-1),false);
        var childPolicyKnown=GetProcessMitigationPolicy(self,13,out var childPolicy,sizeof(uint));
        int? childPolicyError=childPolicyKnown?null:Marshal.GetLastWin32Error();
        var imagePolicyKnown=GetProcessMitigationPolicy(self,10,out var imagePolicy,sizeof(uint));
        int? imagePolicyError=imagePolicyKnown?null:Marshal.GetLastWin32Error();
        var evidence=new ToolCreationEvidence(childPolicyKnown?childPolicy:null,childPolicyError,imagePolicyKnown?imagePolicy:null,imagePolicyError,null);
        // Hash/read success does not establish FILE_EXECUTE access. Probe only
        // the already fixed, manager-held tool image, without mapping or running
        // it; do not read another resource or change any security descriptor.
        using var executable=SessionResources.OpenExecutableForProbe(fixedImage);
        if(executable.IsInvalid)
        {
            var code=Marshal.GetLastWin32Error();var failure=new Win32Exception(code);failure.Data["Stage"]="InheritedToolImageExecuteOpen";
            failure.Data["ToolCreationEvidence"]=evidence with{ImageExecuteOpenError=code};throw failure;
        }
        return evidence with{ImageExecuteOpenError=0};
    }
    private static InheritedTool CreateInheritedTool(ProcessStartInfo start,StringBuilder command,AdmissionToken token,ToolCreationEvidence evidence,OwnedKernelJob job,ProtectedSession.ResourceQualification permit)
    {
        if(token.PackageSid is null)throw WfpNative.Contract("InheritedToolPackageMissing");
        var sid=new SecurityIdentifier(token.PackageSid);var sidBytes=new byte[sid.BinaryLength];sid.GetBinaryForm(sidBytes,0);
        IntPtr attributes=IntPtr.Zero,package=IntPtr.Zero,capabilities=IntPtr.Zero,policy=IntPtr.Zero,handles=IntPtr.Zero,environment=IntPtr.Zero,jobList=IntPtr.Zero;
        bool initialized=false;SafeFileHandle? inputRead=null,inputWrite=null,outputRead=null,outputWrite=null,errorRead=null,errorWrite=null;
        SafeProcessHandle? process=null;SafeWaitHandle? thread=null;
        var jobHandle=job.ToolCreationHandle(permit);bool jobHeld=false;
        try
        {
            jobHandle.DangerousAddRef(ref jobHeld);
            var pipeSecurity=new KernelJobSeal.SecurityAttributes{Length=Marshal.SizeOf<KernelJobSeal.SecurityAttributes>(),Inherit=1};
            if(!CreateToolPipe(out inputRead,out inputWrite,ref pipeSecurity,0))throw Error("InheritedToolInputPipe");
            if(!CreateToolPipe(out outputRead,out outputWrite,ref pipeSecurity,0))throw Error("InheritedToolOutputPipe");
            if(!CreateToolPipe(out errorRead,out errorWrite,ref pipeSecurity,0))throw Error("InheritedToolErrorPipe");
            foreach(var parent in new[]{inputWrite,outputRead,errorRead})
                if(!SetToolHandleInformation(parent,1,0))throw Error("InheritedToolParentHandleSeal");
            nuint size=0;_=InitializeProcThreadAttributeList(IntPtr.Zero,4,0,ref size);
            if(size is 0 or >65536)throw Error("InheritedToolAttributeSize");
            attributes=Marshal.AllocHGlobal(checked((int)size));
            if(!InitializeProcThreadAttributeList(attributes,4,0,ref size))throw Error("InheritedToolAttributes");initialized=true;
            package=Marshal.AllocHGlobal(sidBytes.Length);Marshal.Copy(sidBytes,0,package,sidBytes.Length);
            capabilities=Marshal.AllocHGlobal(Marshal.SizeOf<SecurityCapabilities>());
            Marshal.StructureToPtr(new SecurityCapabilities{Sid=package},capabilities,false);
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x20009,capabilities,(nuint)Marshal.SizeOf<SecurityCapabilities>(),IntPtr.Zero,IntPtr.Zero))throw Error("InheritedToolPackage");
            policy=Marshal.AllocHGlobal(sizeof(uint));Marshal.WriteInt32(policy,1);
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x2000f,policy,sizeof(uint),IntPtr.Zero,IntPtr.Zero))throw Error("InheritedToolLpac");
            jobList=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(jobList,jobHandle.DangerousGetHandle());
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x2000d,jobList,(nuint)IntPtr.Size,IntPtr.Zero,IntPtr.Zero))throw Error("OwnedToolJobAtCreation");
            handles=Marshal.AllocHGlobal(3*IntPtr.Size);
            var inherited=new[]{inputRead,outputWrite,errorWrite};for(var i=0;i<inherited.Length;i++)Marshal.WriteIntPtr(handles,i*IntPtr.Size,inherited[i].DangerousGetHandle());
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x20002,handles,(nuint)(3*IntPtr.Size),IntPtr.Zero,IntPtr.Zero))throw Error("InheritedToolHandleList");
            var env=start.Environment.OrderBy(e=>e.Key,StringComparer.OrdinalIgnoreCase).Select(e=>e.Key+"="+e.Value).ToArray();
            if(env.Any(e=>e.Contains('\0')))throw WfpNative.Contract("InheritedToolEnvironmentRefused");
            environment=Marshal.StringToHGlobalUni(string.Join('\0',env)+"\0\0");
            var startup=new StartupInfoEx{Basic=new(){Size=Marshal.SizeOf<StartupInfoEx>(),Flags=0x100,
                Input=inputRead.DangerousGetHandle(),Output=outputWrite.DangerousGetHandle(),Error=errorWrite.DangerousGetHandle()},Attributes=attributes};
            using var descriptor=new KernelJobSeal.SessionObjectDescriptor();var processSecurity=descriptor.Attributes;var threadSecurity=descriptor.Attributes;
            permit.AssertCurrent();
            ProcessInfo info;
            using(var faultMode=ToolFaultMode.Enter())
                if(!CreateSealedProcess(start.FileName,command,ref processSecurity,ref threadSecurity,true,0x08080404,environment,start.WorkingDirectory,ref startup,out info))
                {var failure=Error("OwnedToolCreateProcess");failure.Data["ToolCreationEvidence"]=evidence;throw failure;}
            process=new SafeProcessHandle(info.Process,true);thread=new SafeWaitHandle(info.Thread,true);
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(process);KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread);
            var child=ReadToken(process);
            var actualImage=new StringBuilder(32768);uint actualSize=(uint)actualImage.Capacity;
            if(!QueryFullProcessImageName(process,0,actualImage,ref actualSize))throw Error("OwnedToolHeldImage");
            if(!child.IsAppContainer || !child.LpacAccessCheckObserved || child.PackageSid!=token.PackageSid || child.CapabilityCount!=0 || child.IntegritySid!="S-1-16-4096" ||
                !job.ContainsProcess(process) || !string.Equals(WindowsPathSeal.Canonical(actualImage.ToString()),WindowsPathSeal.Canonical(start.FileName),StringComparison.OrdinalIgnoreCase))
                throw WfpNative.Contract("OwnedToolSuspendedIdentityRefused");
            if(start.ArgumentList.FirstOrDefault()=="resource-powershell")
            {
                var descriptors=SessionEtwProviderAccess.RegistrationCheckDescriptors(token.PackageSid);
                permit.RecordEtwTokenAccess(checked((int)GetProcessId(process)),
                    ObserveTokenRegisterAccess(process,descriptors.Readback),ObserveTokenRegisterAccess(process,descriptors.InMemoryPackageAce));
            }
            // The trusted owner still independently checks actual Job members,
            // image and LPAC AccessCheck mask before releasing the tool gate.
            if(ResumeThread(thread)!=1)throw Error("InheritedToolResume");
            var result=new InheritedTool(process,inputWrite,outputRead,errorRead,evidence);process=null;inputWrite=null;outputRead=null;errorRead=null;return result;
        }
        finally
        {
            // Any admitted descendant remains owned by the enclosing original
            // Job even if setup/reporting fails; its supervisor closes that Job.
            thread?.Dispose();process?.Dispose();inputRead?.Dispose();inputWrite?.Dispose();outputRead?.Dispose();outputWrite?.Dispose();errorRead?.Dispose();errorWrite?.Dispose();
            if(initialized)DeleteProcThreadAttributeList(attributes);
            foreach(var pointer in new[]{attributes,package,capabilities,policy,handles,environment,jobList})if(pointer!=IntPtr.Zero)Marshal.FreeHGlobal(pointer);
            if(jobHeld)jobHandle.DangerousRelease();
        }
    }
    private static StringBuilder InheritedToolCommand(string image,string[] arguments)
    {
        var command=new StringBuilder();
        foreach(var arg in new[]{image}.Concat(arguments))
        {
            if(arg.Contains('\0'))throw WfpNative.Contract("InheritedToolArgumentRefused");
            if(command.Length>0)command.Append(' ');command.Append('"');var slashes=0;
            foreach(var c in arg)
            {
                if(c=='\\'){slashes++;continue;}
                command.Append('\\',c=='"'?2*slashes+1:slashes);command.Append(c);slashes=0;
            }
            command.Append('\\',2*slashes);command.Append('"');
        }
        if(command.Length>=32767)throw WfpNative.Contract("InheritedToolCommandTooLong");return command;
    }
    internal sealed class InheritedTool : IDisposable
    {
        private readonly SafeProcessHandle process;
        internal StreamWriter StandardInput {get;}
        internal StreamReader StandardOutput {get;}
        internal StreamReader StandardError {get;}
        internal ToolCreationEvidence CreationEvidence {get;}
        internal InheritedTool(SafeProcessHandle process,SafeFileHandle input,SafeFileHandle output,SafeFileHandle error,ToolCreationEvidence evidence)
        {
            this.process=process;CreationEvidence=evidence;StandardInput=new StreamWriter(new FileStream(input,FileAccess.Write),new UTF8Encoding(false)){AutoFlush=true};
            StandardOutput=new StreamReader(new FileStream(output,FileAccess.Read),Encoding.UTF8,true);
            StandardError=new StreamReader(new FileStream(error,FileAccess.Read),Encoding.UTF8,true);
        }
        internal bool HasExited=>WaitForExit(0);
        internal bool WaitForExit(int milliseconds)
        {
            if(milliseconds<0)throw new ArgumentOutOfRangeException(nameof(milliseconds));var result=WaitForSingleObject(process,(uint)milliseconds);
            if(result==0)return true;if(result==258)return false;throw Error("InheritedToolWait");
        }
        internal int ExitCode=>GetExitCodeProcess(process,out var code)?unchecked((int)code):throw Error("InheritedToolExitCode");
        internal ToolLaunchReply TransferTo(SafeProcessHandle root,int rootPid,int sequence,string nonce)
        {
            // No Job/token/thread/manager handle crosses into the worker.
            // Partial transfers are bounded to this exact original root and
            // close when the same owning Job stops after a setup failure.
            long Copy(SafeHandle source,uint access,uint options)
            {
                if(!DuplicateToolHandle((IntPtr)(-1),source,root,out var transferred,access,false,options))throw Error("OwnedToolHandleTransfer");
                return transferred.ToInt64();
            }
            var limitedProcess=Copy(process,0x101000,0); // SYNCHRONIZE + QUERY_LIMITED_INFORMATION.
            var input=Copy(((FileStream)StandardInput.BaseStream).SafeFileHandle,0,2);
            var output=Copy(((FileStream)StandardOutput.BaseStream).SafeFileHandle,0,2);
            var error=Copy(((FileStream)StandardError.BaseStream).SafeFileHandle,0,2);
            return new(1,nonce,rootPid,sequence,limitedProcess,input,output,error,null,null);
        }
        public void Dispose(){StandardInput.Dispose();StandardOutput.Dispose();StandardError.Dispose();process.Dispose();}
    }
    private static AdmissionToken ReadToken(SafeProcessHandle process,bool observePackageAccess=true)
    {
        if(!OpenProcessToken(process,observePackageAccess?8u|2u:8u,out var token))throw Error("AtomicOpenCreatedToken");
        using(token)
        {
            var container=Read(29,p=>Marshal.ReadInt32(p)!=0);
            var sid=Read(31,p=>{var s=Marshal.ReadIntPtr(p);return s==IntPtr.Zero?null:new SecurityIdentifier(s).Value;});
            // Read actual capability SIDs/attributes within the bounded native
            // buffer. Count alone must not become a future singleton-profile
            // identity check. Existing consumers still reject all nonzero sets.
            var capabilities=TokenCapabilitySnapshot.Read(token.DangerousGetHandle());
            var integrity=Read(25,p=>new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value);
            // Class46's zero-buffer query returned ERROR_INVALID_PARAMETER in
            // the preserved own-token qualification. Do not infer false or a
            // positive permit from that failure. Check the actual access
            // semantic using documented AccessCheck + a query-only duplicate.
            var packageAccess=observePackageAccess?ProbeApplicationPackageAccess(token):0u; // 0 = NOT_OBSERVED, never a grant.
            return new(container,sid,capabilities.Count,integrity,container && packageAccess==2,packageAccess){Capabilities=capabilities};
            T Read<T>(int type,Func<IntPtr,T> consume)
            {
                _=GetTokenInformation(token,type,IntPtr.Zero,0,out var size);
                if(size is <4 or >65536)throw Error("AtomicTokenBufferSize");var p=Marshal.AllocHGlobal(size);
                try{if(!GetTokenInformation(token,type,p,size,out _))throw Error("AtomicReadTokenInformation");return consume(p);}
                finally{Marshal.FreeHGlobal(p);}
            }
        }
    }
    private static uint ProbeApplicationPackageAccess(SafeAccessTokenHandle token)
    {
        // Pattern also exercised by Chromium's CheckLpacToken. These two bits
        // have meaning ONLY for this synthetic descriptor; no host resource,
        // package profile or process is created or granted additional access.
        // The World ACE satisfies the ordinary-user half of the access check.
        var descriptor=new RawSecurityDescriptor("O:SYG:SYD:P(A;;0x3;;;WD)(A;;0x1;;;S-1-15-2-1)(A;;0x2;;;S-1-15-2-2)");
        var bytes=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(bytes,0);
        if(!DuplicateTokenEx(token,8,IntPtr.Zero,1,2,out var query))throw Error("DuplicateTokenForLpacAccessCheck");
        using(query)
        {
            var mapping=new GenericMapping();var privileges=new byte[64];uint size=(uint)privileges.Length;
            if(!AccessCheck(bytes,query,0x02000000,ref mapping,privileges,ref size,out var granted,out var allowed))throw Error("ReadLpacAccessCheck");
            if(size>privileges.Length || !allowed || granted is <1 or >3)throw WfpNative.Contract("LpacAccessCheckResultNotQualified");
            return granted;
        }
    }
    internal static EtwTokenAccessCheck ObserveTokenRegisterAccess(SafeProcessHandle process,string descriptor)
    {
        var security=new RawSecurityDescriptor(descriptor);var bytes=new byte[security.BinaryLength];security.GetBinaryForm(bytes,0);
        var hash=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));
        if(!OpenProcessToken(process,8|2,out var token))throw Error("EtwComparisonOpenHeldToolToken");
        using(token)
        {
            if(!DuplicateTokenEx(token,8,IntPtr.Zero,1,2,out var query))throw Error("EtwComparisonDuplicateQueryOnlyToken");
            using(query)
            {
                var mapping=new GenericMapping();var privileges=new byte[64];uint size=(uint)privileges.Length;
                var succeeded=AccessCheck(bytes,query,SessionEtwProviderAccess.RegisterRight,ref mapping,privileges,ref size,out var granted,out var allowed);
                var error=succeeded?(int?)null:Marshal.GetLastWin32Error();
                if(size>privileges.Length)return new(hash,false,null,null,error??122);
                return new(hash,succeeded,succeeded?allowed:null,succeeded?granted:null,error);
            }
        }
    }
    public void Dispose(){if(disposed)return;disposed=true;thread.Dispose();process.Dispose();}
    private static Win32Exception Error(string stage){var e=new Win32Exception(Marshal.GetLastWin32Error());e.Data["Stage"]=stage;return e;}
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] private struct StartupInfo {internal int Size;internal string? Reserved,Desktop,Title;internal int X,Y,XSize,YSize,XCount,YCount,Fill;internal uint Flags;internal ushort Show,ReservedBytes;internal IntPtr ReservedPointer,Input,Output,Error;}
    [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx {internal StartupInfo Basic;internal IntPtr Attributes;}
    [StructLayout(LayoutKind.Sequential)] private struct SecurityCapabilities {internal IntPtr Sid,Capabilities;internal uint Count,Reserved;}
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInfo {internal IntPtr Process,Thread;internal uint ProcessId,ThreadId;}
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref nuint size);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,nuint size,IntPtr previous,IntPtr returned);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll",EntryPoint="CreateProcessW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateProcess(string image,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,[MarshalAs(UnmanagedType.Bool)] bool inherit,uint flags,IntPtr environment,string? cwd,ref StartupInfoEx startup,out ProcessInfo info);
    [DllImport("kernel32.dll",EntryPoint="CreateProcessW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateSealedProcess(string image,StringBuilder command,ref KernelJobSeal.SecurityAttributes processSecurity,ref KernelJobSeal.SecurityAttributes threadSecurity,[MarshalAs(UnmanagedType.Bool)] bool inherit,uint flags,IntPtr environment,string? cwd,ref StartupInfoEx startup,out ProcessInfo info);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint ResumeThread(SafeWaitHandle thread);
    [DllImport("kernel32.dll",EntryPoint="DuplicateHandle",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool DuplicateToolHandle(IntPtr sourceProcess,SafeHandle source,SafeProcessHandle targetProcess,out IntPtr target,uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint options);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint GetProcessId(SafeProcessHandle process);
    [DllImport("kernel32.dll",EntryPoint="CreatePipe",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateToolPipe(out SafeFileHandle read,out SafeFileHandle write,ref KernelJobSeal.SecurityAttributes attributes,uint size);
    [DllImport("kernel32.dll",EntryPoint="SetHandleInformation",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetToolHandleInformation(SafeFileHandle handle,uint mask,uint flags);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool IsProcessInJob(SafeProcessHandle process,IntPtr job,[MarshalAs(UnmanagedType.Bool)]out bool present);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetProcessMitigationPolicy(SafeProcessHandle process,int policy,out uint flags,nuint size);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)] bool inherit,uint pid);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetExitCodeProcess(SafeProcessHandle process,out uint code);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetProcessTimes(SafeProcessHandle process,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll",EntryPoint="QueryFullProcessImageNameW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder path,ref uint size);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool OpenProcessToken(SafeProcessHandle process,uint access,out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetTokenInformation(SafeAccessTokenHandle token,int type,IntPtr data,int size,out int returned);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetTokenInformation(SafeAccessTokenHandle token,int type,IntPtr data,uint size);
    [StructLayout(LayoutKind.Sequential)] private struct GenericMapping {internal uint Read,Write,Execute,All;}
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool DuplicateTokenEx(SafeAccessTokenHandle existing,uint access,IntPtr security,int level,int type,out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool AccessCheck(byte[] descriptor,SafeAccessTokenHandle token,uint desired,ref GenericMapping mapping,[Out]byte[] privileges,ref uint size,out uint granted,[MarshalAs(UnmanagedType.Bool)]out bool allowed);
}
