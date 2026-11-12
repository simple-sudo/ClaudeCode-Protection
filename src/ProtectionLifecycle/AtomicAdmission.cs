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

// No supplied executable/arguments/PID/token. First consumer is the installed
// broker's own finite canary. Production Claude admission remains deferred.
internal sealed partial class AtomicChild : IDisposable
{
    private readonly ProtectedState state;
    private readonly VerifiedVersion version;
    private readonly OwnedKernelJob job;
    private readonly SafeProcessHandle process;
    private readonly SafeWaitHandle thread;
    private readonly uint initialThreadId;
    private readonly string image,packageSid;
    private readonly NetworkProbePlan? network;
    private readonly bool gpuWorkload;
    private readonly OfflineTlsProbe? offlineTls;
    private readonly bool offlineConsole;
    private readonly bool independentOfflineConsole;
    private readonly bool independentCuda;
    private readonly SessionGitToolchain.Operation independentGit;
    private readonly bool startupWitness;
    private readonly SessionZeroCreatorChannel.TokenProof creatorTokenProof;
    private readonly ProtectedSession.Preparation? sessionPreparation;
    private readonly ProtectedSession.ResourceQualification? resourceQualification;
    private ProtectedSession.Admission? sessionAdmission;
    private bool resumed,disposed;
    internal bool ResumeAttempted {get;private set;}
    internal string? DefaultDaclPreparationSHA256 {get;private set;}
    internal uint Pid {get;}
    internal string ExpectedPackageSid=>packageSid;
    internal string ExpectedImagePath=>image;
    internal bool RequiresLpac=>sessionPreparation is not null || resourceQualification is not null || gpuWorkload || offlineTls is not null || offlineConsole;
    private LpacCapabilityProfile CapabilityProfile=>sessionPreparation?.CapabilityProfile??FixedCapabilities(offlineTls is not null);
    private static LpacCapabilityProfile FixedCapabilities(bool offlineTls)=>offlineTls?
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
        var localService=!exactPreparation.IsGatewayQualification;
        KernelJobSeal.SessionObjectDescriptor.AssertSeal(process,localService);
        KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread,localService);
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
        var requireIndependentUser=sessionPreparation is {IsGatewayQualification:false};
        var token=ReadTokenSnapshot(process,true,requireIndependentUser,out var actualUser);
        if(!string.Equals(WindowsPathSeal.Canonical(path.ToString()),image,StringComparison.OrdinalIgnoreCase) ||
            !token.IsAppContainer || !token.LpacAccessCheckObserved || token.PackageSid!=packageSid || !CapabilityProfile.Matches(token.CapabilityCount,token.Capabilities) || token.IntegritySid!="S-1-16-4096")
            throw WfpNative.Contract("SuspendedSessionRootImageOrTokenMismatch");
        if(requireIndependentUser)
        {
            using var host=WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            AssertIndependentSessionUser(actualUser,host.User);
        }
    }
    internal static void AssertIndependentSessionUser(SecurityIdentifier? actual,SecurityIdentifier? host)
    {
        // A different account on the same host can still disclose its machine
        // account domain. This creation route currently qualifies LocalService only.
        if(actual is null || host is null || actual.Equals(host) || !actual.IsWellKnown(WellKnownSidType.LocalServiceSid))
            throw WfpNative.Contract("FormalSessionRequiresIndependentLocalServiceUser");
    }
    internal static void AssertIndependentOfflineHandoffToken(SafeProcessHandle process,SessionZeroCreatorChannel.TokenProof proof,string expectedPackageSid)
    {
        var token=ReadIndependentOfflineToken(process,proof,out var actualUser);
        using var host=WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        AssertIndependentSessionUser(actualUser,host.User);
        if(!token.IsAppContainer || !token.LpacAccessCheckObserved || token.ApplicationPackageAccessMask!=2 ||
            token.PackageSid!=expectedPackageSid || token.IntegritySid!="S-1-16-4096" || !LpacCapabilityProfile.None.Matches(token.CapabilityCount,token.Capabilities))
            throw WfpNative.Contract("IndependentOfflineHandoffTokenMismatch");
        AssertNoChildCreation(process);
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
    private AtomicChild(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,ProcessInfo info,string image,string sid,NetworkProbePlan? network,bool gpuWorkload,ProtectedSession.Preparation? preparation,ProtectedSession.ResourceQualification? resources,OfflineTlsProbe? offlineTls,bool offlineConsole)
    {
        this.state=state;this.version=version;this.job=job;this.image=image;packageSid=sid;Pid=info.ProcessId;this.network=network;this.gpuWorkload=gpuWorkload;
        process=new(info.Process,true);thread=new(info.Thread,true);initialThreadId=info.ThreadId;
        sessionPreparation=preparation;resourceQualification=resources;this.offlineTls=offlineTls;this.offlineConsole=offlineConsole;
    }
    private AtomicChild(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,SessionZeroCreatorChannel.SuspendedRoot root,
        string image,string sid,bool startupWitness,SessionGitToolchain.Operation gitOperation,bool cuda)
    {
        this.state=state;this.version=version;this.job=job;this.image=image;packageSid=sid;
        Pid=root.Identity.Pid;initialThreadId=root.Identity.Tid;
        (process,thread)=root.TransferTo(job);
        offlineConsole=true;independentOfflineConsole=true;
        independentGit=gitOperation;
        independentCuda=cuda;
        this.startupWitness=startupWitness;
        creatorTokenProof=root.LpacProof;
    }
    internal static AtomicChild AdoptSessionZeroOfflineConsole(FixedLayout layout,ProtectedState state,VerifiedVersion version,
        OwnedKernelJob job,SessionZeroCreatorChannel.SuspendedRoot root,bool startupWitness,SessionGitToolchain.Operation gitOperation,bool cuda)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);
        _=job.SessionZeroCreatorSid;
        job.AssertCreatorSealedBeforeResume();
        var image=gitOperation!=SessionGitToolchain.Operation.None?SessionGitToolchain.ToolPath:startupWitness?SessionZeroStartupWitness.ReviewedImage(layout,version):
            WindowsPathSeal.Child(layout.Version(version.Package.Release),"bin/admin/ProtectionBroker.exe");
        using var package=new InstallationPackageSid(state);
        return new(state,version,job,root,image,package.Value,startupWitness,gitOperation,cuda);
    }
    internal static AtomicChild CreateCanary(FixedLayout layout,ProtectedState state,VerifiedVersion version,OwnedKernelJob job,InstallationProfileLease profile,
        NetworkProbePlan? network=null,IntPtr output=default,GpuProbePlan? gpu=null)
        =>CreateCore(layout,state,version,job,profile,network,output,gpu,null,null);
    internal static AtomicChild CreateOfflineTlsQualification(FixedLayout layout,ProtectedState state,VerifiedVersion version,
        OwnedKernelJob job,InstallationProfileLease profile,string sessionId,IntPtr output,OfflineTlsProbe probe)
        =>CreateCore(layout,state,version,job,profile,null,output,null,null,null,(probe,Identifiers.Hex32(sessionId)));
    internal static AtomicChild CreateOfflineConsoleQualification(FixedLayout layout,ProtectedState state,VerifiedVersion version,
        OwnedKernelJob job,InstallationProfileLease profile,string sessionId,PathLease workspace,OfflineConsoleStorage storage,OfflineConsoleStreams streams)
        =>CreateCore(layout,state,version,job,profile,null,IntPtr.Zero,null,null,null,console:(streams,Identifiers.Hex32(sessionId),workspace,storage));
    internal static (SafeProcessHandle Process,SafeWaitHandle Thread) CreateSessionZeroOfflineConsole(SessionZeroCreatorClient client,
        SessionZeroCreatorProfile profile,OfflineConsoleStreams streams)
    {
        if(!Environment.Is64BitProcess || Marshal.SizeOf<StartupInfoEx>()!=112 || Marshal.SizeOf<SecurityCapabilities>()!=24)
            throw new PlatformNotSupportedException("Creator startup requires the declared x64 layout");
        var brokerImage=ResolveSessionZeroImage(FixedLayout.FromWindows(),Environment.ProcessPath);
        using var git=client.Request.GitOperation!=SessionGitToolchain.Operation.None?SessionGitToolchain.Open():null;
        var image=git is not null?SessionGitToolchain.ToolPath:client.Request.StartupWitness?
            WindowsPathSeal.Child(Path.GetDirectoryName(brokerImage)!,Path.GetFileName(PackageAssetCatalog.SessionZeroStartupWitnessPath)):brokerImage;
        using var imageParent=git is null?WindowsPathSeal.LockDirectory(Path.GetDirectoryName(image)!,PathPolicy.Protected):null;
        using var heldImage=git is null?WindowsPathSeal.Open(image,false,true):null;
        if(heldImage is not null)WindowsPathSeal.AssertAcl(heldImage,true);
        var session=client.Request.JobId;
        using var workspace=WindowsPathSeal.LockDirectory(SessionTaskWorkspace.PathFor(session),PathPolicy.Source);
        var gitStart=client.Request.GitOperation switch
        {
            SessionGitToolchain.Operation.Init=>SessionGitToolchain.StartIndependentInit(workspace.Path),
            SessionGitToolchain.Operation.TrackedCommit=>SessionGitToolchain.StartIndependentCommit(workspace.Path),
            _=>null
        };
        var env=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        if(gitStart is not null)
        {
            foreach(var entry in gitStart.Environment)
                if(entry.Value is { } value)env.Add(entry.Key,value);
        }
        else
        {
            var windows=Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if(string.IsNullOrEmpty(windows))throw WfpNative.Contract("CreatorWindowsPathMissing");
            env["SystemRoot"]=env["windir"]=WindowsPathSeal.Canonical(windows);
            env["PATH"]=WindowsPathSeal.Child(windows,"System32")+";"+windows;
            env["DOTNET_ROOT"]=WindowsPathSeal.Child(Path.GetDirectoryName(workspace.Path)!,"dotnet");
            env["DOTNET_ROLL_FORWARD"]="LatestPatch";
            OfflineConsoleQualification.BindEnvironment(env,workspace.Path,profile.Package.Name,session);
            if(client.Request.Cuda)env[IndependentGpuWorkload.PreloadVariable]="0";
        }
        using var channels=streams.PrepareCreationAttributes();
        using var seal=new KernelJobSeal.SessionObjectDescriptor(localService:true);
        var processSecurity=seal.Attributes;var threadSecurity=seal.Attributes;
        var attributes=IntPtr.Zero;var values=IntPtr.Zero;var environment=IntPtr.Zero;
        var initialized=false;var assignmentHeld=false;
        try
        {
            client.Assignment.DangerousAddRef(ref assignmentHeld);
            nuint size=0;_=InitializeProcThreadAttributeList(IntPtr.Zero,5,0,ref size);
            if(size is 0 or >65536)throw Error("CreatorAttributeListSize");
            attributes=Marshal.AllocHGlobal(checked((int)size));
            if(!InitializeProcThreadAttributeList(attributes,5,0,ref size))throw Error("CreatorInitializeAttributes");
            initialized=true;
            var capabilitySize=Marshal.SizeOf<SecurityCapabilities>();
            values=Marshal.AllocHGlobal(capabilitySize+IntPtr.Size+sizeof(uint));
            Marshal.StructureToPtr(new SecurityCapabilities{Sid=profile.Package.Pointer},values,false);
            var jobList=IntPtr.Add(values,capabilitySize);Marshal.WriteIntPtr(jobList,client.Assignment.DangerousGetHandle());
            var policy=IntPtr.Add(jobList,IntPtr.Size);Marshal.WriteInt32(policy,1);
            Bind(0x20009,values,(nuint)capabilitySize);
            Bind(0x2000d,jobList,(nuint)IntPtr.Size);
            Bind(0x2000f,policy,sizeof(uint));
            channels.Bind(attributes);
            var std=channels.Channels;
            var desktop=client.Request.UsePrivateWindow?SessionZeroWindowPolicy.DesktopPathForJob(session):null;
            var startup=new StartupInfoEx{Basic=new(){Size=Marshal.SizeOf<StartupInfoEx>(),Desktop=desktop,Flags=0x100,
                Input=std.Input,Output=std.Output,Error=std.Error},Attributes=attributes};
            environment=Marshal.StringToHGlobalUni(string.Join('\0',env.Select(p=>p.Key+"="+p.Value))+"\0\0");
            var command=gitStart is not null?InheritedToolCommand(image,gitStart.ArgumentList.ToArray()):new StringBuilder("\""+image+"\"");
            if(gitStart is null && !client.Request.StartupWitness)command.Append(' ').Append(client.Request switch {
                {CudaDeviceIdentity:true}=>IndependentGpuWorkload.DeviceIdentityChildCommand,
                {CudaRegistryPrivacy:true}=>IndependentGpuWorkload.RegistryPrivacyChildCommand,
                {Cuda:true}=>IndependentGpuWorkload.ChildCommand,
                {NetworkSurvey:true}=>OfflineConsoleQualification.NetworkSurveyChildCommand,
                {IdentitySurvey:true}=>OfflineConsoleQualification.IdentitySurveyChildCommand,
                {UsePrivateWindow:true}=>OfflineConsoleQualification.PrivateWindowChildCommand,
                _=>OfflineConsoleQualification.ChildCommand
            });
            git?.AssertHeld();
            if(!CreateSealedProcess(image,command,ref processSecurity,ref threadSecurity,true,0x00080404u|OfflineConsoleStreams.DetachedCreationFlag,
                environment,workspace.Path,ref startup,out var created))throw Error("CreatorAtomicCreateSuspendedOfflineConsole");
            return(new(created.Process,true),new(created.Thread,true));
        }
        finally
        {
            if(initialized)DeleteProcThreadAttributeList(attributes);
            Marshal.FreeHGlobal(attributes);Marshal.FreeHGlobal(values);Marshal.FreeHGlobal(environment);
            if(assignmentHeld)client.Assignment.DangerousRelease();
        }
        void Bind(int attribute,IntPtr value,nuint length)
        {
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)attribute,value,length,IntPtr.Zero,IntPtr.Zero))throw Error("CreatorBindAtomicAttribute");
        }
    }
    internal static string ResolveSessionZeroImage(FixedLayout layout,string? processImage)
    {
        if(processImage is null)throw WfpNative.Contract("CreatorImageMissing");
        var actual=WindowsPathSeal.Canonical(processImage);
        var release=Path.GetFileName(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(actual))))??"";
        var expected=WindowsPathSeal.Child(layout.Version(Identifiers.Hex32(release)),"bin/admin/ProtectionBroker.exe");
        if(!string.Equals(actual,expected,StringComparison.OrdinalIgnoreCase))throw WfpNative.Contract("CreatorImageMustBeInstalledBroker");
        return expected;
    }
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
        (OfflineTlsProbe Probe,string Session)? tls=null,(OfflineConsoleStreams Streams,string Session,PathLease Workspace,OfflineConsoleStorage Storage)? console=null)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);
        preparation?.BeforeCreate(job,version);
        resources?.BeforeCreate(job,version);
        if(resources is not null && (preparation is not null || network is not null || gpu is not null))throw WfpNative.Contract("ResourceQualificationCannotBorrowOtherAuthority");
        if(preparation is not null && (network is not null || gpu is not null))throw WfpNative.Contract("SuspendedSessionCannotBorrowQualificationPlan");
        if(!Environment.Is64BitProcess || Marshal.SizeOf<StartupInfo>()!=104 || Marshal.SizeOf<StartupInfoEx>()!=112 || Marshal.SizeOf<SecurityCapabilities>()!=24)
            throw new PlatformNotSupportedException("Atomic admission requires the declared x64 layout");
        var tlsCommand=tls is { } fixedTls?OfflineTlsQualification.ChildCommand(fixedTls.Probe):null;
        if(tls is not null && (preparation is not null || resources is not null || network is not null || gpu is not null))
            throw WfpNative.Contract("OfflineTlsQualificationCannotBorrowOtherAuthority");
        if(tls?.Probe==OfflineTlsProbe.OpenSsl)OpenSslModuleLease.AssertOwnedPackage(version.Package);
        if(console is { } fixedConsole)
        {
            if(tls is not null || preparation is not null || resources is not null || network is not null || gpu is not null || output!=IntPtr.Zero)
                throw WfpNative.Contract("OfflineConsoleCannotBorrowOtherAuthority");
            fixedConsole.Workspace.AssertHeld();
            fixedConsole.Storage.AssertHeld(fixedConsole.Workspace);
            if(fixedConsole.Workspace.Path!=SessionTaskWorkspace.PathFor(fixedConsole.Session))
                throw WfpNative.Contract("OfflineConsoleWorkspaceMismatch");
        }
        var requireLpac=preparation is not null || resources is not null || gpu is not null || tls is not null || console is not null;
        if(requireLpac && Marshal.SizeOf<KernelJobSeal.SecurityAttributes>()!=24)
            throw new PlatformNotSupportedException("Suspended session security attributes require the declared x64 layout");
        var image=WindowsPathSeal.Child(layout.Version(version.Package.Release),"bin/admin/ProtectionBroker.exe");
        network?.Validate();gpu?.Validate();if(network is not null && gpu is not null)throw WfpNative.Contract("OneFixedQualificationWorkloadRequired");
        var report=network is not null || gpu is not null || resources is not null || preparation?.IsGatewayQualification==true || tls is not null;if(report!=(output!=IntPtr.Zero))throw WfpNative.Contract("ReportHandleRequiredExactlyForQualificationWorkload");
        var inherit=report || console is not null;
        using var package=network?.Kind==NetworkProbeKind.Control?InstallationPackageSid.ForNetworkControl(state):new InstallationPackageSid(state);
        profile.AssertPackage(package);
        var originalJobHandle=job.ReserveAtomicAdmission(version);
        using var consoleAssignment=console is null?null:originalJobHandle.DuplicateAssignment();
        var jobHandle=consoleAssignment??originalJobHandle;
        using var capabilityAttributes=(preparation?.CapabilityProfile??FixedCapabilities(tls is not null)).AllocateAttributes();
        IntPtr attributes=IntPtr.Zero,capabilities=IntPtr.Zero,jobList=IntPtr.Zero,environment=IntPtr.Zero,handles=IntPtr.Zero,packagesPolicy=IntPtr.Zero;
        OfflineConsoleStreams.CreationAttributes? consoleAttributes=null;
        bool initialized=false,handleHeld=false;
        try
        {
            jobHandle.DangerousAddRef(ref handleHeld);
            var count=(inherit?3:2)+(requireLpac?1:0)+(console is not null?1:0);
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
            var startup=new StartupInfoEx{Basic=new(){Size=Marshal.SizeOf<StartupInfoEx>()},Attributes=attributes};
            if(console is { } consoleSetup)
            {
                consoleAttributes=consoleSetup.Streams.PrepareCreationAttributes();
                consoleAttributes.Bind(attributes);
                var channels=consoleAttributes.Channels;
                startup.Basic.Flags=0x100;
                startup.Basic.Input=channels.Input;startup.Basic.Output=channels.Output;startup.Basic.Error=channels.Error;
            }
            else if(report)
            {
                handles=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(handles,output);
                if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x20002,handles,(nuint)IntPtr.Size,IntPtr.Zero,IntPtr.Zero))throw Error("AtomicSetOnlyReportHandleInheritance");
                startup.Basic.Flags=0x100;startup.Basic.Output=output;startup.Basic.Error=output;
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
            if(tls is { } offline)
            {
                SetPrivateRuntimeDirectories(env,profile.WorkspaceRoot());
                env[OfflineTlsQualification.SessionVariable(offline.Probe)]=offline.Session;
                if(offline.Probe==OfflineTlsProbe.OpenSsl)env[OpenSslModuleLease.ReleaseVariable]=version.Package.Release;
            }
            if(console is { } offlineConsoleSetup)
                OfflineConsoleQualification.BindEnvironment(env,offlineConsoleSetup.Workspace.Path,package.Name,offlineConsoleSetup.Session);
            if(preparation is not null)
            {
                // Creation requires LOCALAPPDATA; use the original freshly
                // owned profile, never the host user profile or inherited temp.
                SetPrivateRuntimeDirectories(env,profile.WorkspaceRoot());
                env["CPC_SESSION_ID"]=preparation.SessionId;env["CPC_SESSION_SECRET"]=preparation.Gateway.Secret;
                if(preparation.UsesFixedOpenSslHead)env[OpenSslModuleLease.ReleaseVariable]=version.Package.Release;
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
            var command=new StringBuilder("\""+image+"\" "+(console is not null?OfflineConsoleQualification.ChildCommand:tlsCommand??preparation?.ChildCommand??"admission-child"));
            // The OS binds BOTH identity and Job before returning a suspended
            // initial thread. Inherit only the selected report or console
            // handles; no breakaway permission is enabled.
            profile.BeforeProcessCreation(job.JobId);
            ProcessInfo info;
            if(requireLpac)
            {
                using var descriptor=new KernelJobSeal.SessionObjectDescriptor();
                var processAttributes=descriptor.Attributes;var threadAttributes=descriptor.Attributes;
                var flags=console is not null?0x00080404u|OfflineConsoleStreams.DetachedCreationFlag:0x08080404u;
                if(!CreateSealedProcess(image,command,ref processAttributes,ref threadAttributes,inherit,flags,environment,console?.Workspace.Path??resources?.Workspace??Path.GetDirectoryName(image)!,ref startup,out info))
                    throw Error("AtomicCreateSealedSuspendedSession");
            }
            else if(!CreateProcess(image,command,IntPtr.Zero,IntPtr.Zero,report,0x08080404,environment,Path.GetDirectoryName(image)!,ref startup,out info))
                throw Error("AtomicCreateSuspendedWithPackageAndJob");
            var child=new AtomicChild(state,version,job,info,image,package.Value,network,gpu is not null,preparation,resources,tls?.Probe,console is not null);
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
            consoleAttributes?.Dispose();
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
        if(disposed || ResumeAttempted)throw new InvalidOperationException("Canary resume is one-shot");
        if(sessionPreparation is not null)
        {
            if(sessionPermit is null || !sessionPermit.Matches(sessionPreparation))throw WfpNative.Contract("FullSessionPermitRequiredBeforeFirstInstruction");
            AssertSuspendedSessionIdentity(sessionPreparation);
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
        if(offlineTls is not null)
        {
            if(proxy is not null || sessionPermit is not null)throw WfpNative.Contract("TlsQualificationRequiresOfflineQuarantine");
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(process);
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread);
        }
        if(offlineConsole)
        {
            if(proxy is not null || sessionPermit is not null)throw WfpNative.Contract("OfflineConsoleRequiresFullQuarantine");
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(process,independentOfflineConsole);
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread,independentOfflineConsole);
            AssertNoChildCreation(process);
            job.AssertSingleProcessEverAdmitted();
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
        SecurityIdentifier? tokenUser;
        var token=independentOfflineConsole?ReadIndependentOfflineToken(process,creatorTokenProof,out tokenUser):
            ReadTokenSnapshot(process,true,offlineConsole,out tokenUser);
        if(!token.IsAppContainer || RequiresLpac && !token.LpacAccessCheckObserved || token.PackageSid!=packageSid || !CapabilityProfile.Matches(token.CapabilityCount,token.Capabilities) || token.IntegritySid!="S-1-16-4096")throw WfpNative.Contract("AtomicTokenBeforeResumeMismatch");
        if(independentOfflineConsole)
        {
            using var host=WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            AssertIndependentSessionUser(tokenUser,host.User);
        }
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
        AssertHeldInitialThread(process,thread,Pid,initialThreadId);
        var proof=new {SchemaVersion=1,state.InstallationId,job.JobId,Pid,CreatedFileTime=created.ToString("X16"),Token=token,
            ExpectedCapabilitiesSHA256=CapabilityProfile.SHA256,ObservedCapabilities=token.Capabilities?.CopyEntries(),
            ImageSHA256=independentGit!=SessionGitToolchain.Operation.None?SessionGitToolchain.ImageSHA256:
                version.Package.Files.Single(f=>f.Asset.Id==(startupWitness?PackageAssetCatalog.SessionZeroStartupWitnessId:"broker-exe")).SHA256,
            Job=snapshot,Fences=observations,
            CreatorLpacAccessCheckBoundToPrimaryToken=independentOfflineConsole?(bool?)true:null,
            Binding="SECURITY_CAPABILITIES_AND_JOB_LIST_AT_CREATION",Status="BEFORE_FIRST_RESUME",NetworkBehaviorQualified=false,
            SessionBindingSHA256=sessionAdmission?.BindingSHA256,
            Scope=sessionAdmission is not null?"AUTHENTICATED_SESSION_GATEWAY":network?.Kind==NetworkProbeKind.Control?"UNFENCED_OWNED_LOOPBACK_CONTROL":proxyOnly?"COMPILED_IPV4_PROXY_ONLY":gpuWorkload?"FIXED_CUDA_FULL_QUARANTINE":startupWitness?SessionZeroStartupWitness.Scope:
                independentGit!=SessionGitToolchain.Operation.None?SessionGitToolchain.Scope(independentGit):independentCuda?IndependentGpuWorkload.Scope:independentOfflineConsole?"FIXED_INDEPENDENT_CONSOLE_FULL_QUARANTINE":offlineConsole?"FIXED_CONSOLE_FULL_QUARANTINE":
                offlineTls switch {OfflineTlsProbe.Schannel=>"FIXED_SCHANNEL_FULL_QUARANTINE",OfflineTlsProbe.OpenSsl=>"FIXED_OPENSSL_FULL_QUARANTINE",_=>"FULL_QUARANTINE"}};
        state.WriteNew("admission-before-resume-"+job.JobId+".json",JsonSerializer.SerializeToUtf8Bytes(proof));
        OfflineConsoleUserSid=tokenUser;
        sessionAdmission?.BeforeResume(this);
        resourceQualification?.BeforeResume(this);
        job.AssertCreatorSealedBeforeResume();
        if(independentOfflineConsole)
        {
            using var held=OpenCreatorQueryToken(process);
            AssertCreatorLpacBinding(creatorTokenProof,WindowsTokenInformation.ReadPrimaryBinding(held));
        }
        var branchTrace=startupWitness && SessionZeroStartupWitness.UsesBranchTrace(version.Package.SchemaVersion);
        if(branchTrace || startupWitness && version.Package.SchemaVersion==PackageAssetCatalog.SessionZeroStartupDiagnosticsSchema)
        {
            const int processSystemCallDisablePolicy=4;
            BeforeResumeWin32k=GetProcessMitigationPolicy(process,processSystemCallDisablePolicy,out var flags,sizeof(uint))
                ?new(0,(flags&1)!=0):new(unchecked((uint)Marshal.GetLastWin32Error()),null);
        }
        if(branchTrace)
        {
            const int processSystemCallFilterPolicy=11;
            BeforeResumeSystemCallFilter=GetProcessMitigationPolicy(process,processSystemCallFilterPolicy,out var flags,sizeof(uint))
                ?new(0,flags&15):new(unchecked((uint)Marshal.GetLastWin32Error()),null);
        }
        ResumeAttempted=true;
        var previous=ResumeThread(thread);if(previous==uint.MaxValue)throw Error("AtomicResumePrimaryThread");
        if(previous!=1)throw WfpNative.Contract("AtomicInitialSuspendCountMismatch");
        resumed=true;return proof;
    }
    internal uint WaitForCanaryExit()=>WaitForCanaryExit(null);
    internal uint WaitForCanaryExit(int? timeoutMs)
    {
        var defaultTimeoutMs=network?.Kind==NetworkProbeKind.ProxySession?90000u:network is not null || gpuWorkload?30000u:15000u;
        return ObserveCanaryExit(ResolveCanaryTimeoutMs(timeoutMs,defaultTimeoutMs))
            ??throw new TimeoutException("Finite atomic canary did not exit");
    }
    internal static uint ResolveCanaryTimeoutMs(int? timeoutMs,uint defaultTimeoutMs)
    {
        if(defaultTimeoutMs is 0 or >120000 || timeoutMs is <1 or >120000)
            throw new ArgumentOutOfRangeException(nameof(timeoutMs));
        return timeoutMs.HasValue?checked((uint)timeoutMs.Value):defaultTimeoutMs;
    }
    internal static void AssertHeldInitialThread(SafeProcessHandle process,SafeWaitHandle thread,uint pid,uint tid)
    {
        if(pid==0 || tid==0 || process.IsClosed || process.IsInvalid || thread.IsClosed || thread.IsInvalid ||
            GetProcessId(process)!=pid || GetThreadId(thread)!=tid || GetProcessIdOfThread(thread)!=pid ||
            WaitForSingleObject(process,0)!=0x102 || WaitForInitialThread(thread,0)!=0x102)
            throw WfpNative.Contract("HeldInitialThreadIdentityOrLifetimeMismatch");
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
    internal void AssertOfflineTlsRuntimeOwner(ProtectedState exactState,VerifiedVersion exactVersion,OwnedKernelJob exactJob,OfflineTlsProbe probe)
    {
        if(offlineTls!=probe || disposed || resumed || !IsRunning || !ReferenceEquals(state,exactState) ||
            !ReferenceEquals(version,exactVersion) || !ReferenceEquals(job,exactJob) || !job.ContainsProcess(process))
            throw WfpNative.Contract("OfflineTlsRuntimeRequiresExactSuspendedChild");
    }
    internal uint? ObserveFixedOfflineTlsExit()
    {
        if(offlineTls is null)throw WfpNative.Contract("FixedOfflineTlsWorkloadRequired");
        return ObserveCanaryExit(100);
    }
    internal void AssertOfflineConsoleRuntimeOwner(ProtectedState exactState,VerifiedVersion exactVersion,OwnedKernelJob exactJob)
    {
        if(!offlineConsole || disposed || ResumeAttempted || !IsRunning || !ReferenceEquals(state,exactState) ||
            !ReferenceEquals(version,exactVersion) || !ReferenceEquals(job,exactJob) || !job.ContainsProcess(process))
            throw WfpNative.Contract("OfflineConsoleRuntimeRequiresExactSuspendedChild");
    }
    private static void AssertNoChildCreation(SafeProcessHandle process)
    {
        if(!GetProcessMitigationPolicy(process,13,out var flags,sizeof(uint)))throw Error("OfflineConsoleReadChildPolicy");
        if(flags!=1)throw WfpNative.Contract("OfflineConsoleChildPolicyNotEnforced");
    }
    public void Dispose(){if(disposed)return;disposed=true;thread.Dispose();process.Dispose();}
    private static Win32Exception Error(string stage){var e=new Win32Exception(Marshal.GetLastWin32Error());e.Data["Stage"]=stage;return e;}

}
