using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

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

internal sealed record AdmissionToken(bool IsAppContainer,string? PackageSid,int CapabilityCount,string IntegritySid,bool IsLessPrivilegedAppContainer);
internal sealed record OwnedMemberInspection(uint Pid,bool MembershipConfirmed,long? CreatedFileTime,string? ImagePath,AdmissionToken? Token,WfpErrorEvidence[] Failures);

// No supplied executable/arguments/PID/token. First consumer is the installed
// broker's own finite canary. Production Claude admission remains deferred.
internal sealed class AtomicChild : IDisposable
{
    private readonly ProtectedState state;
    private readonly VerifiedVersion version;
    private readonly OwnedKernelJob job;
    private readonly SafeProcessHandle process;
    private readonly SafeWaitHandle thread;
    private readonly string image,packageSid;
    private readonly NetworkProbePlan? network;
    private readonly bool gpuWorkload;
    private readonly ProtectedSession.Preparation? sessionPreparation;
    private readonly ProtectedSession.ResourceQualification? resourceQualification;
    private ProtectedSession.Admission? sessionAdmission;
    private bool resumed,disposed;
    internal bool ResumeAttempted {get;private set;}
    internal uint Pid {get;}
    internal string ExpectedPackageSid=>packageSid;
    internal string ExpectedImagePath=>image;
    internal bool RequiresLpac=>sessionPreparation is not null || resourceQualification is not null;
    internal long ExpectedCreatedFileTime
    {
        get
        {
            if(disposed || !GetProcessTimes(process,out var created,out _,out _,out _))throw Error("ReadHeldPrimaryCreationTime");
            return created;
        }
    }
    internal bool IsRunning=>!disposed && WaitForSingleObject(process,0)==0x102;
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
            !token.IsAppContainer || !token.IsLessPrivilegedAppContainer || token.PackageSid!=packageSid || token.CapabilityCount!=0 || token.IntegritySid!="S-1-16-4096")
            throw WfpNative.Contract("SuspendedSessionRootImageOrTokenMismatch");
    }
    internal static SafeProcessHandle HoldSessionPeer(OwnedKernelJob job,string sid,int sourcePort)
    {
        var process=OpenProcess(0x101000,false,ProxyChannelLease.SessionPeerOwner(sourcePort));
        try
        {
            if(process.IsInvalid)throw Error("OpenSessionGatewayPeer");
            AssertSessionPeer(job,process,sid,sourcePort);return process;
        }
        catch{process.Dispose();throw;}
    }
    internal static void AssertSessionPeer(OwnedKernelJob job,SafeProcessHandle process,string sid,int sourcePort)
    {
        if(process.IsClosed || process.IsInvalid || WaitForSingleObject(process,0)!=0x102 || !job.ContainsProcess(process) ||
            ProxyChannelLease.SessionPeerOwner(sourcePort)!=GetProcessId(process))throw WfpNative.Contract("SessionGatewayPeerJobOrLifetimeMismatch");
        var token=ReadToken(process);
        if(!token.IsAppContainer || !token.IsLessPrivilegedAppContainer || token.PackageSid!=sid || token.CapabilityCount!=0 || token.IntegritySid!="S-1-16-4096")
            throw WfpNative.Contract("SessionGatewayPeerTokenMismatch");
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
    private AtomicChild(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,ProcessInfo info,string image,string sid,NetworkProbePlan? network,bool gpuWorkload,ProtectedSession.Preparation? preparation,ProtectedSession.ResourceQualification? resources)
    {
        this.state=state;this.version=version;this.job=job;this.image=image;packageSid=sid;Pid=info.ProcessId;this.network=network;this.gpuWorkload=gpuWorkload;
        process=new(info.Process,true);thread=new(info.Thread,true);sessionPreparation=preparation;resourceQualification=resources;
    }
    internal static AtomicChild CreateCanary(FixedLayout layout,ProtectedState state,VerifiedVersion version,OwnedKernelJob job,InstallationProfileLease profile,
        NetworkProbePlan? network=null,IntPtr output=default,GpuProbePlan? gpu=null)
        =>CreateCore(layout,state,version,job,profile,network,output,gpu,null,null);
    internal static AtomicChild CreateResourceQualification(FixedLayout layout,ProtectedState state,VerifiedVersion version,OwnedKernelJob job,
        InstallationProfileLease profile,ProtectedSession.ResourceQualification permit,IntPtr output)
    {
        var child=CreateCore(layout,state,version,job,profile,null,output,null,null,permit);
        try{permit.BindCreated(child);return child;}catch{child.Dispose();throw;}
    }
    internal static AtomicChild CreateSession(FixedLayout layout,ProtectedState state,VerifiedVersion version,OwnedKernelJob job,InstallationProfileLease profile,
        ProtectedSession.Preparation preparation)
    {
        var child=CreateCore(layout,state,version,job,profile,null,default,null,preparation,null);
        try{preparation.BindCreated(child);return child;}catch{child.Dispose();throw;}
    }
    private static AtomicChild CreateCore(FixedLayout layout,ProtectedState state,VerifiedVersion version,OwnedKernelJob job,InstallationProfileLease profile,
        NetworkProbePlan? network,IntPtr output,GpuProbePlan? gpu,ProtectedSession.Preparation? preparation,ProtectedSession.ResourceQualification? resources)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);
        preparation?.BeforeCreate(job,version);
        resources?.BeforeCreate(job,version);
        if(resources is not null && (preparation is not null || network is not null || gpu is not null))throw WfpNative.Contract("ResourceQualificationCannotBorrowOtherAuthority");
        if(preparation is not null && (network is not null || gpu is not null))throw WfpNative.Contract("SuspendedSessionCannotBorrowQualificationPlan");
        if(!Environment.Is64BitProcess || Marshal.SizeOf<StartupInfo>()!=104 || Marshal.SizeOf<StartupInfoEx>()!=112 || Marshal.SizeOf<SecurityCapabilities>()!=24)
            throw new PlatformNotSupportedException("Atomic admission requires the declared x64 layout");
        if((preparation is not null || resources is not null) && Marshal.SizeOf<KernelJobSeal.SecurityAttributes>()!=24)
            throw new PlatformNotSupportedException("Suspended session security attributes require the declared x64 layout");
        var image=WindowsPathSeal.Child(layout.Version(version.Package.Release),"bin/admin/ProtectionBroker.exe");
        network?.Validate();gpu?.Validate();if(network is not null && gpu is not null)throw WfpNative.Contract("OneFixedQualificationWorkloadRequired");
        var report=network is not null || gpu is not null || resources is not null;if(report!=(output!=IntPtr.Zero))throw WfpNative.Contract("ReportHandleRequiredExactlyForQualificationWorkload");
        using var package=network?.Kind==NetworkProbeKind.Control?InstallationPackageSid.ForNetworkControl(state):new InstallationPackageSid(state);
        profile.AssertPackage(package);
        var jobHandle=job.ReserveAtomicAdmission(version);
        var requireLpac=preparation is not null || resources is not null;
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
            Marshal.StructureToPtr(new SecurityCapabilities{Sid=package.Pointer},capabilities,false);
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
            var inherited=preparation is null && resources is null?new[]{"SystemRoot","windir","SystemDrive","ProgramFiles","ProgramFiles(x86)","ProgramW6432","PROCESSOR_ARCHITECTURE","LOCALAPPDATA","USERPROFILE","TEMP","TMP"}:
                new[]{"SystemRoot","windir","SystemDrive","ProgramFiles","ProgramFiles(x86)","ProgramW6432","PROCESSOR_ARCHITECTURE"};
            foreach(var name in inherited)
            {var value=Environment.GetEnvironmentVariable(name);if(value is not null)env[name]=value;}
            env["PATH"]="C:\\Program Files\\dotnet;C:\\Windows\\System32;C:\\Windows";
            env["DOTNET_ROOT"]="C:\\Program Files\\dotnet";env["DOTNET_ROLL_FORWARD"]="LatestPatch";
            if(network is not null)env["CPC_NETWORK_PLAN"]=JsonSerializer.Serialize(network);
            if(gpu is not null){env["CPC_GPU_PLAN"]=JsonSerializer.Serialize(gpu);env["CUDA_CACHE_DISABLE"]="1";}
            if(resources is not null)
            {
                env["CPC_RESOURCE_PLAN"]=JsonSerializer.Serialize(resources.Plan);
                foreach(var name in new[]{"TEMP","TMP","LOCALAPPDATA","USERPROFILE"})env[name]=resources.Workspace;
            }
            if(preparation is not null)
            {
                env["CPC_SESSION_ID"]=preparation.SessionId;env["CPC_SESSION_SECRET"]=preparation.Gateway.Secret;
                var endpoint="http://"+preparation.SessionId+":"+preparation.Gateway.Secret+"@127.0.0.1:"+SessionProxy.Port;
                foreach(var name in new[]{"HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"})env[name]=endpoint;
                env["NO_PROXY"]="";
            }
            environment=Marshal.StringToHGlobalUni(string.Join('\0',env.Select(p=>p.Key+"="+p.Value))+"\0\0");
            var startup=new StartupInfoEx{Basic=new(){Size=Marshal.SizeOf<StartupInfoEx>()},Attributes=attributes};
            if(report){startup.Basic.Flags=0x100;startup.Basic.Output=output;startup.Basic.Error=output;}
            var command=new StringBuilder("\""+image+"\" admission-child");
            // The OS binds BOTH identity and Job before returning a suspended
            // initial thread. Only the explicit qualification report handle
            // may be inherited; no breakaway permission is enabled.
            profile.BeforeProcessCreation(job.JobId);
            ProcessInfo info;
            if(preparation is not null || resources is not null)
            {
                using var descriptor=new KernelJobSeal.SessionObjectDescriptor();
                var processAttributes=descriptor.Attributes;var threadAttributes=descriptor.Attributes;
                if(!CreateSealedProcess(image,command,ref processAttributes,ref threadAttributes,report,0x08080404,environment,resources?.Workspace??Path.GetDirectoryName(image)!,ref startup,out info))
                    throw Error("AtomicCreateSealedSuspendedSession");
            }
            else if(!CreateProcess(image,command,IntPtr.Zero,IntPtr.Zero,report,0x08080404,environment,Path.GetDirectoryName(image)!,ref startup,out info))
                throw Error("AtomicCreateSuspendedWithPackageAndJob");
            var child=new AtomicChild(state,version,job,info,image,package.Value,network,gpu is not null,preparation,resources);
            try
            {
                if(preparation is not null || resources is not null){KernelJobSeal.SessionObjectDescriptor.AssertSeal(child.process);KernelJobSeal.SessionObjectDescriptor.AssertSeal(child.thread);}
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
        if(!token.IsAppContainer || RequiresLpac && !token.IsLessPrivilegedAppContainer || token.PackageSid!=packageSid || token.CapabilityCount!=0 || token.IntegritySid!="S-1-16-4096")throw WfpNative.Contract("AtomicTokenBeforeResumeMismatch");
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
            ImageSHA256=version.Package.Files.Single(f=>f.Asset.Id=="broker-exe").SHA256,Job=snapshot,Fences=observations,
            Binding="SECURITY_CAPABILITIES_AND_JOB_LIST_AT_CREATION",Status="BEFORE_FIRST_RESUME",NetworkBehaviorQualified=false,
            SessionBindingSHA256=sessionAdmission?.BindingSHA256,
            Scope=sessionAdmission is not null?"AUTHENTICATED_SESSION_GATEWAY":network?.Kind==NetworkProbeKind.Control?"UNFENCED_OWNED_LOOPBACK_CONTROL":proxyOnly?"COMPILED_IPV4_PROXY_ONLY":gpuWorkload?"FIXED_CUDA_FULL_QUARANTINE":"FULL_QUARANTINE"};
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
        if(!resumed || disposed)throw new InvalidOperationException("Canary has not resumed");
        var status=WaitForSingleObject(process,network?.Kind==NetworkProbeKind.ProxySession?90000u:network is not null || gpuWorkload?30000u:15000u);
        if(status==0x102)throw new TimeoutException("Finite atomic canary did not exit");
        if(status!=0)throw Error("AtomicCanaryWait");
        if(!GetExitCodeProcess(process,out var code))throw Error("AtomicCanaryExitCode");return code;
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
            if(!token.IsLessPrivilegedAppContainer)return 125;
            if(plan is not null || gpuPlan is not null || sessionId is null || sessionSecret is null)return 125;
            _=Identifiers.Hex32(sessionId);_=Identifiers.Hash(sessionSecret);
            using var handler=new SocketsHttpHandler {UseProxy=true,Proxy=new System.Net.WebProxy("http://127.0.0.1:"+SessionProxy.Port) {
                BypassProxyOnLocal=false,Credentials=new System.Net.NetworkCredential(sessionId,sessionSecret)},
                AllowAutoRedirect=false,UseCookies=false,SslOptions=SessionProxy.OfflineTls()};
            using var client=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(10)};
            // A transport canary needs headers only. GET + disposing an unread
            // body can abort its own tunnel and look like a gateway failure.
            using var request=new HttpRequestMessage(HttpMethod.Head,"https://"+SessionProxy.Target+"/") {
                Version=System.Net.HttpVersion.Version11,VersionPolicy=HttpVersionPolicy.RequestVersionExact};
            using var response=client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();
            return (int)response.StatusCode is >=200 and <400?42:126;
        }
        if(gpuPlan is not null)
        {
            if(gpuPlan.Length>256)throw WfpNative.Contract("GpuPlanSizeRefused");
            var gpu=JsonSerializer.Deserialize<GpuProbePlan>(gpuPlan)??throw WfpNative.Contract("GpuPlanMissing");gpu.Validate();
            var computed=GpuQualification.Compute(gpu,"APPCONTAINER_LOW_ZERO_CAPABILITIES");Console.WriteLine(JsonSerializer.Serialize(computed));return GpuQualification.Qualified(computed)?0:3;
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
        using var current=new SafeProcessHandle((IntPtr)(-1),false);var token=ReadToken(current);
        if(!token.IsAppContainer || !token.IsLessPrivilegedAppContainer || token.CapabilityCount!=0 || token.IntegritySid!="S-1-16-4096" || token.PackageSid is null)return 125;
        return SessionResources.RunChild(token.PackageSid);
    }
    private static AdmissionToken ReadToken(SafeProcessHandle process)
    {
        if(!OpenProcessToken(process,8,out var token))throw Error("AtomicOpenCreatedToken");
        using(token)
        {
            var container=Read(29,p=>Marshal.ReadInt32(p)!=0);
            var sid=Read(31,p=>{var s=Marshal.ReadIntPtr(p);return s==IntPtr.Zero?null:new SecurityIdentifier(s).Value;});
            var count=Read(30,Marshal.ReadInt32);
            var integrity=Read(25,p=>new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value);
            var lpac=Read(46,p=>Marshal.ReadInt32(p)!=0);
            return new(container,sid,count,integrity,lpac);
            T Read<T>(int type,Func<IntPtr,T> consume)
            {
                _=GetTokenInformation(token,type,IntPtr.Zero,0,out var size);
                if(size is <4 or >65536)throw Error("AtomicTokenBufferSize");var p=Marshal.AllocHGlobal(size);
                try{if(!GetTokenInformation(token,type,p,size,out _))throw Error("AtomicReadTokenInformation");return consume(p);}
                finally{Marshal.FreeHGlobal(p);}
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
    [DllImport("kernel32.dll",EntryPoint="CreateProcessW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateProcess(string image,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,[MarshalAs(UnmanagedType.Bool)] bool inherit,uint flags,IntPtr environment,string cwd,ref StartupInfoEx startup,out ProcessInfo info);
    [DllImport("kernel32.dll",EntryPoint="CreateProcessW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateSealedProcess(string image,StringBuilder command,ref KernelJobSeal.SecurityAttributes processSecurity,ref KernelJobSeal.SecurityAttributes threadSecurity,[MarshalAs(UnmanagedType.Bool)] bool inherit,uint flags,IntPtr environment,string cwd,ref StartupInfoEx startup,out ProcessInfo info);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint ResumeThread(SafeWaitHandle thread);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint GetProcessId(SafeProcessHandle process);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)] bool inherit,uint pid);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetExitCodeProcess(SafeProcessHandle process,out uint code);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetProcessTimes(SafeProcessHandle process,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll",EntryPoint="QueryFullProcessImageNameW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder path,ref uint size);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool OpenProcessToken(SafeProcessHandle process,uint access,out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetTokenInformation(SafeAccessTokenHandle token,int type,IntPtr data,int size,out int returned);
}
