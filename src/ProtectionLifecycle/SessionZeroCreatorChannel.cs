using System.Buffers.Binary;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Broker side of the fixed offline creation protocol. The SCM owner supplies
// the original, held service process after checking its service configuration.
// This channel can never start a service or resume the returned thread.
internal sealed class SessionZeroCreatorChannel : IDisposable
{
    private const uint RequestMagic=0x32504343,ReplyMagic=0x31524343,FailureMagic=0x31464343; // CCP2, CCR1, CCF1.
    private const uint StartupWitnessRequestMagic=0x31574343; // CCW1, same size and peer binding.
    private const uint WindowAccessRequestMagic=0x32574343,WindowAccessProofMagic=0x31444343; // CCW2, CCD1.
    private const uint PrivateWindowRequestMagic=0x33574343; // CCW3.
    private const uint PrivateWindowReadControlRequestMagic=0x34574343; // CCW4.
    private const uint PrivateWindowConsoleRequestMagic=0x314d4343; // CCM1.
    private const uint IdentitySurveyRequestMagic=0x31534343; // CCS1.
    private const uint NetworkSurveyRequestMagic=0x314e4343; // CCN1.
    private const uint GitInitRequestMagic=0x31474343; // CCG1.
    private const uint CudaRequestMagic=0x31554343; // CCU1.
    private const uint CudaRegistryPrivacyRequestMagic=0x32554343; // CCU2.
    private const uint CudaDeviceIdentityRequestMagic=0x33554343; // CCU3.
    private const uint ProfileCreatedMagic=0x314a4343,ProfileRecordedMagic=0x31414343; // CCJ1, CCA1.
    private const uint TokenProofMagic=0x31544343; // CCT1.
    private const int NonceSize=16,ReplySize=44,ObjectIdentityBytes=12;
    internal const int RequestSize=60;
    internal const int ProfileReplySize=ReplySize;
    internal const int ProfileRecordedSize=4+NonceSize;
    internal const string ServicePrefix="CpcSessionCreator.";
    private readonly SessionZeroCreatorRegistration registration;
    private OwnedKernelJob? boundJob;
    private readonly NamedPipeServerStream pipe;
    private BoundPeer? boundPeer;
    private int consumed;
    private bool cudaCapture;
    private byte[]? cleanupNonce;
    private string? profileCreatedHash;
    internal bool ProfileCleanupConfirmed {get;private set;}
    internal bool ConfirmsProfileCleanupFor(OwnedKernelJob exactJob)=>ReferenceEquals(boundJob,exactJob) && ProfileCleanupConfirmed;
    internal bool IsPreparedFor(SessionZeroCreatorRegistration exactRegistration)=>ReferenceEquals(registration,exactRegistration) && Volatile.Read(ref consumed)==0 &&
        !pipe.SafePipeHandle.IsClosed && !pipe.SafePipeHandle.IsInvalid;
    internal string PipeName=>NameForJob(registration.JobId);
    internal static string NameForJob(string jobId)=>ServicePrefix+Identifiers.Hex32(jobId);

    internal SessionZeroCreatorChannel(SessionZeroCreatorRegistration registration)
    {
        this.registration=registration;
        pipe=CreateOwnerPipe(PipeName,registration.Sid);
    }

    internal static NamedPipeServerStream CreateOwnerPipe(string name,SecurityIdentifier sid)
    {
        ProtectedState.RequireAdministrator();
        // Explicit FILE_READ_ATTRIBUTES; no FILE_CREATE_PIPE_INSTANCE for the
        // client. One overlapped local-only server, refusing any occupied name.
        var sddl="O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x00120083;;;"+sid.Value+")S:(ML;;NW;;;ME)";
        if(!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl,1,out var descriptor,out _))throw Error("CreatorPipeDescriptor");
        try
        {
            var attributes=new KernelJobSeal.SecurityAttributes{Length=Marshal.SizeOf<KernelJobSeal.SecurityAttributes>(),Descriptor=descriptor};
            var handle=CreateNamedPipe(@"\\.\pipe\"+name,0x40080003,8,1,128,128,0,ref attributes);
            try
            {
                if(handle.IsInvalid)throw Error("CreateFirstLocalCreatorPipe");
                return new NamedPipeServerStream(PipeDirection.InOut,true,false,handle);
            }
            catch{handle.Dispose();throw;}
        }
        finally{LocalFree(descriptor);}
    }

    internal void BindReadyPeer(FixedLayout layout,ProtectedState state,VerifiedVersion version)
    {
        var service=registration.AssertReadyForPipe(state,version,this);
        if(boundPeer is not null || pipe.IsConnected)throw WfpNative.Contract("CreatorPipeAlreadyBound");
        var ownerPid=(uint)Environment.ProcessId;
        if(!ProcessIdToSessionId(ownerPid,out var ownerSession))throw Error("ReadBrokerSession");
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(10));
        pipe.WaitForConnectionAsync(deadline.Token).GetAwaiter().GetResult();
        var servicePid=AssertServicePeer(pipe.SafePipeHandle,service,ownerSession);
        AssertImage(service,WindowsPathSeal.Child(layout.Version(version.Package.Release),"bin/admin/ProtectionBroker.exe"));
        boundPeer=new(ownerPid,ownerSession,servicePid,ProcessCreated(service));
    }

    internal void AssertBoundPeer(SafeProcessHandle service,string image)
    {
        if(boundPeer is not { } peer || !pipe.IsConnected ||
            AssertServicePeer(pipe.SafePipeHandle,service,peer.OwnerSession)!=peer.ServicePid ||
            ProcessCreated(service)!=peer.ServiceCreated)
            throw WfpNative.Contract("CreatorPipePeerBindingMissingOrChanged");
        AssertImage(service,image);
    }

    // The caller must retain the original Job and close it through the
    // existing offline stop path if a granted exchange fails.
    internal SuspendedRoot Exchange(FixedLayout layout,ProtectedState state,VerifiedVersion version,OwnedKernelJob job,bool startupWitness,
        SessionZeroWindowOwner? privateWindows=null,bool gitInit=false,bool cuda=false)
    {
        if(startupWitness && (gitInit || cuda) || gitInit && cuda)throw WfpNative.Contract("CreatorFixedPurposeConflict");
        var service=registration.AssertReadyForJob(state,version,this);
        var peer=boundPeer??throw WfpNative.Contract("CreatorPipePeerBindingMissingOrChanged");
        if(job.JobId!=registration.JobId || job.SessionZeroCreatorSid!=registration.Sid.Value)
            throw WfpNative.Contract("CreatorPipeJobMismatch");
        if(Interlocked.Exchange(ref consumed,1)!=0)throw WfpNative.Contract("CreatorPipeAlreadyConsumed");
        boundJob=job;
        var image=WindowsPathSeal.Child(layout.Version(version.Package.Release),"bin/admin/ProtectionBroker.exe");
        using var package=new InstallationPackageSid(state);
        var nonce=RandomNumberGenerator.GetBytes(NonceSize);
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var cancellation=deadline.Token;
        var request=CreateRequest(nonce,state.InstallationId,job.JobId,peer.OwnerPid,peer.OwnerSession);
        var windowAccess=startupWitness && version.Package.SchemaVersion==PackageAssetCatalog.SessionZeroWindowAccessSchema;
        var schema=version.Package.SchemaVersion;
        var privateWindow=startupWitness?SessionZeroStartupWitness.UsesPrivateWindow(schema):SessionZeroWindowPolicy.SupportsConsole(schema);
        var stationReadControl=SessionZeroWindowPolicy.RequiresStationReadControl(schema);
        if(privateWindow!=(privateWindows is not null))throw WfpNative.Contract("CreatorPrivateWindowLeaseRequired");
        privateWindows?.AssertHeld(job);
        if(startupWitness)BinaryPrimitives.WriteUInt32LittleEndian(request,privateWindow?(stationReadControl?PrivateWindowReadControlRequestMagic:PrivateWindowRequestMagic):
            windowAccess?WindowAccessRequestMagic:StartupWitnessRequestMagic);
        else if(gitInit)
        {
            if(schema is not (PackageAssetCatalog.SessionZeroGitInitSchema or PackageAssetCatalog.SessionZeroCudaSchema or PackageAssetCatalog.SessionZeroCudaSplitInitSchema or PackageAssetCatalog.SessionZeroCudaAccessTraceSchema or PackageAssetCatalog.SessionZeroCudaMappedFaultSchema or PackageAssetCatalog.SessionZeroCudaWddmSchema or PackageAssetCatalog.SessionZeroCudaWddmSelfHandleSchema or PackageAssetCatalog.SessionZeroCudaDeferredPreloadSchema or PackageAssetCatalog.SessionZeroCudaInitializationTraceSchema or PackageAssetCatalog.SessionZeroCudaHelperPathSchema or PackageAssetCatalog.SessionZeroCudaRegistryCallsSchema or PackageAssetCatalog.SessionZeroCudaGraphicsReadSchema or PackageAssetCatalog.SessionZeroCudaGraphicsRootSchema or PackageAssetCatalog.SessionZeroCudaDeviceIdentitySchema) || !privateWindow)
                throw WfpNative.Contract("CreatorGitInitRequiresFixedPrivateWindowPackage");
            BinaryPrimitives.WriteUInt32LittleEndian(request,GitInitRequestMagic);
        }
        else if(cuda)
        {
            if(schema is not (PackageAssetCatalog.SessionZeroCudaDeferredPreloadSchema or PackageAssetCatalog.SessionZeroCudaInitializationTraceSchema or PackageAssetCatalog.SessionZeroCudaHelperPathSchema or PackageAssetCatalog.SessionZeroCudaRegistryCallsSchema or PackageAssetCatalog.SessionZeroCudaGraphicsReadSchema or PackageAssetCatalog.SessionZeroCudaGraphicsRootSchema or PackageAssetCatalog.SessionZeroCudaDeviceIdentitySchema) || !privateWindow)
                throw WfpNative.Contract("CreatorCudaRequiresFixedPrivateWindowPackage");
            BinaryPrimitives.WriteUInt32LittleEndian(request,schema switch
            {
                PackageAssetCatalog.SessionZeroCudaDeviceIdentitySchema=>CudaDeviceIdentityRequestMagic,
                PackageAssetCatalog.SessionZeroCudaGraphicsRootSchema=>CudaRegistryPrivacyRequestMagic,
                _=>CudaRequestMagic
            });
            cudaCapture=true;
        }
        else if(privateWindow)BinaryPrimitives.WriteUInt32LittleEndian(request,schema switch {
            PackageAssetCatalog.SessionZeroIdentitySurveySchema=>IdentitySurveyRequestMagic,
            PackageAssetCatalog.SessionZeroNetworkSurveySchema or PackageAssetCatalog.ReviewedProxyRouteSchema or
                PackageAssetCatalog.SessionZeroGitInitSchema or PackageAssetCatalog.SessionZeroCudaSchema or PackageAssetCatalog.SessionZeroCudaSplitInitSchema or PackageAssetCatalog.SessionZeroCudaAccessTraceSchema or PackageAssetCatalog.SessionZeroCudaMappedFaultSchema or PackageAssetCatalog.SessionZeroCudaWddmSchema or PackageAssetCatalog.SessionZeroCudaWddmSelfHandleSchema or PackageAssetCatalog.SessionZeroCudaDeferredPreloadSchema or PackageAssetCatalog.SessionZeroCudaInitializationTraceSchema or PackageAssetCatalog.SessionZeroCudaHelperPathSchema or PackageAssetCatalog.SessionZeroCudaRegistryCallsSchema or PackageAssetCatalog.SessionZeroCudaGraphicsReadSchema or PackageAssetCatalog.SessionZeroCudaGraphicsRootSchema or PackageAssetCatalog.SessionZeroCudaDeviceIdentitySchema=>NetworkSurveyRequestMagic,
            _=>PrivateWindowConsoleRequestMagic
        });
        AssertQuarantine(state);
        AssertBoundPeer(service,image);
        job.ReserveSessionZeroAdmission(version,registration.Sid);
        pipe.WriteAsync(request.AsMemory(),cancellation).AsTask().GetAwaiter().GetResult();
        var profile=ReadReply(frame=>ParseProfileCreated(frame,nonce));
        AssertBoundPeer(service,image);
        AssertQuarantine(state);
        job.AssertCreatorProfileBeforeFirstProcess();
        var admission=state.Read("job-admission-"+job.JobId+".json",8192);
        profileCreatedHash=state.WriteNew(ProfileCreatedLeaf(job.JobId),JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,state.InstallationId,job.JobId,version.Package.Release,version.Package.ManifestHash,
            CreatorSid=registration.Sid.Value,PackageSid=package.Value,AdmissionSHA256=admission.SHA256,
            profile.ParentIdentity,profile.StorageIdentity
        }));
        pipe.WriteAsync(CreateProfileRecorded(nonce).AsMemory(),cancellation).AsTask().GetAwaiter().GetResult();
        var report=ReadReply(frame=>ParseReply(frame,nonce,peer.ServicePid,peer.ServiceCreated));
        AssertBoundPeer(service,image);
        // A completed reply promises the fixed service has returned from
        // CreateProcess and closed its assignment handle. Read the DACL and
        // actual handle count before inspecting any returned process IDs.
        job.ConfirmSessionZeroCreatorReleased();
        // The creator can close its own profile after this original Job is
        // closed and it has independently observed its held child exit. Keep
        // that cleanup path available when the Broker cannot validate the root.
        cleanupNonce=nonce;
        var tokenProof=ParseTokenProof(ReadFrame(),nonce);
        AssertBoundPeer(service,image);
        SessionZeroWindowAccess.Evidence? windowProof=null;
        if(windowAccess || privateWindow)
        {
            windowProof=ParseWindowAccess(ReadFrame(),nonce);
            AssertBoundPeer(service,image);
            if(privateWindow)SessionZeroWindowPolicy.AssertGrants(windowProof.Value,stationReadControl);
        }
        var rootImage=gitInit?SessionGitToolchain.ToolPath:startupWitness?SessionZeroStartupWitness.ReviewedImage(layout,version):image;
        var root=OpenRoot(report,tokenProof,job,rootImage,package.Value);
        try
        {
            AssertQuarantine(state);
            job.AssertCreatorSealedBeforeResume();
            root.WindowAccess=windowProof;
            return root;
        }
        catch{root.Dispose();throw;}

        byte[] ReadFrame()
        {
            var frame=new byte[ReplySize];
            pipe.ReadExactlyAsync(frame.AsMemory(),cancellation).AsTask().GetAwaiter().GetResult();
            return frame;
        }

        T ReadReply<T>(Func<byte[],T> parse)
        {
            var frame=ReadFrame();
            try{return parse(frame);}
            catch(WfpFailure failure)
            {
                // An authenticated failure may be the service's final write.
                try{job.ConfirmSessionZeroCreatorReleased();}
                catch(Exception revocation){throw new AggregateException("Creator failure and assignment release both unconfirmed",failure,revocation);}
                throw;
            }
        }
    }

    internal (OfflineConsoleOutput? Output,OfflineConsoleOutput? Error,Exception? CaptureFailure) CloseCreatorProfile(ProtectedState state)
    {
        var job=boundJob??throw WfpNative.Contract("CreatorProfileCleanupJobUnavailable");
        job.AssertCreatorProfileCleanupAllowed(state);
        AssertQuarantine(state);
        var created=state.Read(ProfileCreatedLeaf(job.JobId),8192);
        if(created.SHA256!=profileCreatedHash)throw WfpNative.Contract("CreatorProfileCreationProofChanged");
        var nonce=Interlocked.Exchange(ref cleanupNonce,null)??throw WfpNative.Contract("CreatorProfileCleanupChannelUnavailable");
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(10));
        pipe.WriteAsync(SessionZeroCreatorTerminal.CloseFrame(nonce).AsMemory(),deadline.Token).AsTask().GetAwaiter().GetResult();
        SessionZeroCreatorTerminal.ReadCleaned(pipe,nonce,deadline.Token);
        var completion=state.Read("job-completed-"+job.JobId+".json",8192);
        state.WriteNew("creator-profile-closed-"+job.JobId+".json",JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,state.InstallationId,job.JobId,CreatedSHA256=created.SHA256,JobCompletionSHA256=completion.SHA256,
            Status="ORIGINAL_CREATOR_PROFILE_CLOSED"
        }));
        ProfileCleanupConfirmed=true;
        try
        {
            var result=cudaCapture?SessionZeroCreatorTerminal.ReadGpuReceipt(pipe,nonce,deadline.Token):
                SessionZeroCreatorTerminal.ReadReceipt(pipe,nonce,deadline.Token);
            return(result.Output,result.Error,null);
        }
        catch(Exception error) when(error is IOException or InvalidDataException or OperationCanceledException or WfpFailure)
        {return(null,null,error);}
    }

    private static string ProfileCreatedLeaf(string jobId)=>"creator-profile-created-"+Identifiers.Hex32(jobId)+".json";

    private static void AssertQuarantine(ProtectedState state)
    {
        var plans=FencePlan.ReadAll(state);
        if(plans.Count==0)throw WfpNative.Contract("CreatorHandoffNeedsRegisteredQuarantine");
        foreach(var plan in plans)
        {
            using var fence=PersistentFence.OpenExisting(state,plan.Data.FenceId);
            if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("CreatorHandoffNeedsFullQuarantine");
        }
    }

    internal static uint AssertServicePeer(SafePipeHandle pipe,SafeProcessHandle service,uint ownerSession)
    {
        var (pid,session)=ReadClientPeer(pipe);
        var expectedPid=GetProcessId(service);
        if(ownerSession==0 || expectedPid==0 || pid!=expectedPid || session!=0 || WaitForSingleObject(service,0)!=258)
            throw WfpNative.Contract("CreatorPipeRequiresOriginalSessionZeroService");
        return pid;
    }
    internal static (uint Pid,uint Session) ReadClientPeer(SafePipeHandle pipe)
    {
        if(!GetNamedPipeClientProcessId(pipe,out var pid) || !GetNamedPipeClientSessionId(pipe,out var session))
            throw Error("ReadCreatorPipeClient");
        return(pid,session);
    }

    internal static byte[] CreateRequest(byte[] nonce,string installId,string jobId,uint ownerPid,uint ownerSession)
    {
        if(nonce.Length!=NonceSize || ownerPid==0 || ownerSession==0)throw WfpNative.Contract("CreatorRequestIdentityInvalid");
        var request=new byte[RequestSize];
        BinaryPrimitives.WriteUInt32LittleEndian(request,RequestMagic);
        BinaryPrimitives.WriteUInt32LittleEndian(request.AsSpan(4),ownerPid);
        BinaryPrimitives.WriteUInt32LittleEndian(request.AsSpan(8),ownerSession);
        nonce.CopyTo(request,12);
        Convert.FromHexString(Identifiers.Hex32(installId)).CopyTo(request,28);
        Convert.FromHexString(Identifiers.Hex32(jobId)).CopyTo(request,44);
        return request;
    }

    private sealed record BoundPeer(uint OwnerPid,uint OwnerSession,uint ServicePid,long ServiceCreated);
    internal sealed record Request(string InstallationId,string JobId,byte[] Nonce)
    {
        internal bool StartupWitness {get;init;}
        internal bool ObserveWindowAccess {get;init;}
        internal bool UsePrivateWindow {get;init;}
        internal bool PrivateStationReadControl {get;init;}
        internal bool IdentitySurvey {get;init;}
        internal bool NetworkSurvey {get;init;}
        internal bool GitInit {get;init;}
        internal bool Cuda {get;init;}
        internal bool CudaRegistryPrivacy {get;init;}
        internal bool CudaDeviceIdentity {get;init;}
    }
    internal static Request ParseRequest(byte[] frame,string fixedJobId,uint serverPid,uint serverSession)
        =>ParseBoundRequest(frame,fixedJobId,serverPid,serverSession,allowStartupWitness:false);

    internal static Request ParseWorkloadRequest(byte[] frame,string fixedJobId,uint serverPid,uint serverSession)
        =>ParseBoundRequest(frame,fixedJobId,serverPid,serverSession,allowStartupWitness:true);

    private static Request ParseBoundRequest(byte[] frame,string fixedJobId,uint serverPid,uint serverSession,bool allowStartupWitness)
    {
        if(frame.Length!=RequestSize || serverPid==0 || serverSession==0 ||
            BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(4))!=serverPid || BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(8))!=serverSession ||
            !frame.AsSpan(44,16).SequenceEqual(Convert.FromHexString(Identifiers.Hex32(fixedJobId))))
            throw WfpNative.Contract("CreatorRequestBindingMismatch");
        var magic=BinaryPrimitives.ReadUInt32LittleEndian(frame);
        if(magic!=RequestMagic && (!allowStartupWitness || magic is not (StartupWitnessRequestMagic or WindowAccessRequestMagic or
            PrivateWindowRequestMagic or PrivateWindowReadControlRequestMagic or PrivateWindowConsoleRequestMagic or
            IdentitySurveyRequestMagic or NetworkSurveyRequestMagic or GitInitRequestMagic or CudaRequestMagic or CudaRegistryPrivacyRequestMagic or CudaDeviceIdentityRequestMagic)))
            throw WfpNative.Contract("CreatorRequestPurposeMismatch");
        var cuda=magic is CudaRequestMagic or CudaRegistryPrivacyRequestMagic or CudaDeviceIdentityRequestMagic;
        var consolePrivate=cuda || magic is PrivateWindowConsoleRequestMagic or IdentitySurveyRequestMagic or NetworkSurveyRequestMagic or GitInitRequestMagic;
        return new(Convert.ToHexString(frame.AsSpan(28,16)).ToLowerInvariant(),fixedJobId,frame.AsSpan(12,NonceSize).ToArray()) {
            StartupWitness=magic!=RequestMagic && !consolePrivate,
            ObserveWindowAccess=magic==WindowAccessRequestMagic,
            UsePrivateWindow=consolePrivate || magic is PrivateWindowRequestMagic or PrivateWindowReadControlRequestMagic,
            PrivateStationReadControl=consolePrivate || magic==PrivateWindowReadControlRequestMagic,
            IdentitySurvey=magic is IdentitySurveyRequestMagic or NetworkSurveyRequestMagic,
            NetworkSurvey=magic==NetworkSurveyRequestMagic,
            GitInit=magic==GitInitRequestMagic,Cuda=cuda,
            CudaRegistryPrivacy=magic is CudaRegistryPrivacyRequestMagic or CudaDeviceIdentityRequestMagic,
            CudaDeviceIdentity=magic==CudaDeviceIdentityRequestMagic
        };
    }

    internal readonly record struct Reply(uint Pid,uint Tid,long ProcessCreated,long ThreadCreated);
    internal readonly record struct CreatedProfile(string ParentIdentity,string StorageIdentity);
    internal readonly record struct TokenProof(WindowsTokenInformation.PrimaryBinding Binding,uint PackageAccess);
    internal enum CreationFailure : uint { Profile=1, AtomicCreate=2, Streams=3, TokenOpen=4, TokenAccessCheck=5, WindowAccess=6 }

    internal static byte[] CreateTokenProof(Request request,TokenProof proof)
    {
        AssertTokenProof(proof);
        if(request.Nonce.Length!=NonceSize)throw WfpNative.Contract("CreatorTokenProofNonceInvalid");
        var frame=new byte[ReplySize];
        BinaryPrimitives.WriteUInt32LittleEndian(frame,TokenProofMagic);
        request.Nonce.CopyTo(frame,4);
        BinaryPrimitives.WriteUInt64LittleEndian(frame.AsSpan(20),proof.Binding.TokenId);
        BinaryPrimitives.WriteUInt64LittleEndian(frame.AsSpan(28),proof.Binding.ModifiedId);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(36),proof.PackageAccess);
        return frame;
    }

    internal static TokenProof ParseTokenProof(byte[] frame,byte[] nonce)
    {
        if(ReadBoundReplyKind(frame,nonce)!=TokenProofMagic || BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(40))!=0)
            throw WfpNative.Contract("CreatorTokenProofFrameInvalid");
        var proof=new TokenProof(new(BinaryPrimitives.ReadUInt64LittleEndian(frame.AsSpan(20)),
            BinaryPrimitives.ReadUInt64LittleEndian(frame.AsSpan(28))),BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(36)));
        AssertTokenProof(proof);
        return proof;
    }

    private static void AssertTokenProof(TokenProof proof)
    {
        if(proof.Binding.TokenId==0 || proof.Binding.ModifiedId==0 || proof.PackageAccess is <1 or >3)
            throw WfpNative.Contract("CreatorTokenProofInvalid");
    }

    internal static byte[] CreateWindowAccess(Request request,SessionZeroWindowAccess.Evidence proof)
    {
        if(!(request.ObserveWindowAccess || request.UsePrivateWindow) || request.Nonce.Length!=NonceSize)
            throw WfpNative.Contract("CreatorWindowAccessPurposeRequired");
        var frame=new byte[ReplySize];
        BinaryPrimitives.WriteUInt32LittleEndian(frame,WindowAccessProofMagic);
        request.Nonce.CopyTo(frame,4);
        WriteWindowAccess(frame.AsSpan(20,12),proof.Station,SessionZeroWindowAccess.StationRights);
        WriteWindowAccess(frame.AsSpan(32,12),proof.Desktop,SessionZeroWindowAccess.DesktopRights);
        return frame;
    }

    internal static SessionZeroWindowAccess.Evidence ParseWindowAccess(byte[] frame,byte[] nonce)
    {
        if(ReadBoundReplyKind(frame,nonce)!=WindowAccessProofMagic)
            throw WfpNative.Contract("CreatorWindowAccessProofInvalid");
        return new(ReadWindowAccess(frame.AsSpan(20,12),SessionZeroWindowAccess.StationRights),
            ReadWindowAccess(frame.AsSpan(32,12),SessionZeroWindowAccess.DesktopRights));
    }

    private static SessionZeroWindowAccess.ObjectAccess ReadWindowAccess(ReadOnlySpan<byte> data,uint validRights)
    {
        var access=new SessionZeroWindowAccess.ObjectAccess(BinaryPrimitives.ReadUInt32LittleEndian(data),
            BinaryPrimitives.ReadUInt32LittleEndian(data[4..]),BinaryPrimitives.ReadUInt32LittleEndian(data[8..]));
        AssertWindowAccess(access,validRights);
        return access;
    }

    private static void WriteWindowAccess(Span<byte> data,SessionZeroWindowAccess.ObjectAccess access,uint validRights)
    {
        AssertWindowAccess(access,validRights);
        BinaryPrimitives.WriteUInt32LittleEndian(data,access.Error);
        BinaryPrimitives.WriteUInt32LittleEndian(data[4..],access.CreatorGranted);
        BinaryPrimitives.WriteUInt32LittleEndian(data[8..],access.ChildGranted);
    }

    private static void AssertWindowAccess(SessionZeroWindowAccess.ObjectAccess access,uint validRights)
    {
        var granted=access.CreatorGranted|access.ChildGranted;
        if((granted&~validRights)!=0 || access.Error!=0 && granted!=0)
            throw WfpNative.Contract("CreatorWindowAccessMaskInvalid");
    }

    internal static byte[] CreateProfileCreated(Request request,CreatedProfile profile)
    {
        AssertProfileIdentity(profile);
        if(request.Nonce.Length!=NonceSize)throw WfpNative.Contract("CreatorProfileNonceInvalid");
        var frame=new byte[ReplySize];
        BinaryPrimitives.WriteUInt32LittleEndian(frame,ProfileCreatedMagic);
        request.Nonce.CopyTo(frame,4);
        Convert.FromHexString(profile.ParentIdentity.Replace(":","",StringComparison.Ordinal)).CopyTo(frame,20);
        Convert.FromHexString(profile.StorageIdentity.Replace(":","",StringComparison.Ordinal)).CopyTo(frame,20+ObjectIdentityBytes);
        return frame;
    }

    internal static CreatedProfile ParseProfileCreated(byte[] frame,byte[] nonce)
    {
        if(ReadBoundReplyKind(frame,nonce)!=ProfileCreatedMagic)throw WfpNative.Contract("CreatorProfileReplyBindingMismatch");
        var profile=new CreatedProfile(DecodeIdentity(frame.AsSpan(20,ObjectIdentityBytes)),DecodeIdentity(frame.AsSpan(20+ObjectIdentityBytes,ObjectIdentityBytes)));
        AssertProfileIdentity(profile);
        return profile;

        static string DecodeIdentity(ReadOnlySpan<byte> value)=>
            Convert.ToHexString(value[..4])+":"+Convert.ToHexString(value[4..8])+":"+Convert.ToHexString(value[8..]);
    }

    internal static void AssertProfileIdentity(CreatedProfile profile)
    {
        var parent=Identifiers.ObjectIdentity(profile.ParentIdentity);
        var storage=Identifiers.ObjectIdentity(profile.StorageIdentity);
        if(parent==storage || !parent.AsSpan(0,8).SequenceEqual(storage.AsSpan(0,8)) ||
            parent.EndsWith(":00000000:00000000",StringComparison.Ordinal) || storage.EndsWith(":00000000:00000000",StringComparison.Ordinal))
            throw WfpNative.Contract("CreatorProfileStorageIdentityInvalid");
    }

    internal static byte[] CreateProfileRecorded(byte[] nonce)
    {
        if(nonce.Length!=NonceSize)throw WfpNative.Contract("CreatorProfileNonceInvalid");
        var frame=new byte[ProfileRecordedSize];
        BinaryPrimitives.WriteUInt32LittleEndian(frame,ProfileRecordedMagic);
        nonce.CopyTo(frame,4);
        return frame;
    }

    internal static void AssertProfileRecorded(byte[] frame,byte[] nonce)
    {
        if(frame.Length!=ProfileRecordedSize || nonce.Length!=NonceSize ||
            BinaryPrimitives.ReadUInt32LittleEndian(frame)!=ProfileRecordedMagic || !CryptographicOperations.FixedTimeEquals(frame.AsSpan(4),nonce))
            throw WfpNative.Contract("CreatorProfileRecordAcknowledgementInvalid");
    }
    internal static byte[] CreateFailure(Request request,CreationFailure stage,uint code)
    {
        if(request.Nonce.Length!=NonceSize || !Enum.IsDefined(stage) || code==0)
            throw WfpNative.Contract("CreatorFailureFrameInvalid");
        var frame=new byte[ReplySize];
        BinaryPrimitives.WriteUInt32LittleEndian(frame,FailureMagic);
        request.Nonce.CopyTo(frame,4);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(20),(uint)stage);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(24),code);
        return frame;
    }
    internal static Reply ObserveCreatedRoot(SafeProcessHandle process,SafeWaitHandle thread)
    {
        var pid=GetProcessId(process);
        var tid=GetThreadId(thread);
        AtomicChild.AssertHeldInitialThread(process,thread,pid,tid);
        if(!GetThreadTimes(thread,out var threadCreated,out _,out _,out _))throw Error("ReadCreatorChildThreadTime");
        return new(pid,tid,ProcessCreated(process),threadCreated);
    }
    internal static byte[] CreateReply(Request request,Reply report)
    {
        if(request.Nonce.Length!=NonceSize || report.Pid==0 || report.Tid==0 || report.ProcessCreated<=0 || report.ThreadCreated<report.ProcessCreated)
            throw WfpNative.Contract("CreatorReplyObjectIdentityInvalid");
        var frame=new byte[ReplySize];
        BinaryPrimitives.WriteUInt32LittleEndian(frame,ReplyMagic);
        request.Nonce.CopyTo(frame,4);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(20),report.Pid);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(24),report.Tid);
        BinaryPrimitives.WriteInt64LittleEndian(frame.AsSpan(28),report.ProcessCreated);
        BinaryPrimitives.WriteInt64LittleEndian(frame.AsSpan(36),report.ThreadCreated);
        return frame;
    }
    private static uint ReadBoundReplyKind(byte[] frame,byte[] nonce)
    {
        if(frame.Length!=ReplySize || nonce.Length!=NonceSize ||
            !CryptographicOperations.FixedTimeEquals(frame.AsSpan(4,NonceSize),nonce))
            throw WfpNative.Contract("CreatorReplyBindingMismatch");
        var magic=BinaryPrimitives.ReadUInt32LittleEndian(frame);
        if(magic==FailureMagic)
        {
            var stage=(CreationFailure)BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(20));
            var code=BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(24));
            if(!Enum.IsDefined(stage) || code==0 || frame.AsSpan(28).ContainsAnyExcept((byte)0))
                throw WfpNative.Contract("CreatorFailureFrameInvalid");
            throw new WfpFailure("CreatorService"+stage,code);
        }
        return magic;
    }

    internal static Reply ParseReply(byte[] frame,byte[] nonce,uint creatorPid,long creatorCreated)
    {
        if(creatorPid==0 || creatorCreated<=0 || ReadBoundReplyKind(frame,nonce)!=ReplyMagic)
            throw WfpNative.Contract("CreatorReplyBindingMismatch");
        var pid=BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(20));
        var tid=BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(24));
        var processCreated=BinaryPrimitives.ReadInt64LittleEndian(frame.AsSpan(28));
        var threadCreated=BinaryPrimitives.ReadInt64LittleEndian(frame.AsSpan(36));
        if(pid==0 || pid==creatorPid || tid==0 || processCreated<creatorCreated || threadCreated<processCreated)
            throw WfpNative.Contract("CreatorReplyObjectIdentityInvalid");
        return new(pid,tid,processCreated,threadCreated);
    }

    private static SuspendedRoot OpenRoot(Reply report,TokenProof tokenProof,OwnedKernelJob job,string image,string packageSid)
    {
        // Query, wait and READ_CONTROL. Only the thread handle adds the
        // single suspend/resume right for later use by AtomicChild.
        var process=OpenProcess(0x121000,false,report.Pid);
        SafeWaitHandle? thread=null;
        try
        {
            if(process.IsInvalid)throw Error("HoldCreatorChildProcess");
            if(!ProcessIdToSessionId(report.Pid,out var childSession))
                throw Error("ReadCreatorChildObjectIdentity");
            var observed=job.Observe();
            if(childSession!=0 || ProcessCreated(process)!=report.ProcessCreated ||
                !observed.ExpectedLimits || observed.ActiveBefore!=1 || observed.ActiveAfter!=1 || !observed.ProcessIds.SequenceEqual([report.Pid]) || !job.ContainsProcess(process))
                throw WfpNative.Contract("CreatorChildJobOrObjectMismatch");
            job.AssertSingleProcessEverAdmitted();
            AssertImage(process,image);
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(process,true);
            thread=OpenThread(0x120802,false,report.Tid);
            if(thread.IsInvalid)throw Error("HoldCreatorChildThread");
            AtomicChild.AssertHeldInitialThread(process,thread,report.Pid,report.Tid);
            if(!GetThreadTimes(thread,out var threadCreated,out _,out _,out _))throw Error("ReadCreatorChildThreadTime");
            if(threadCreated!=report.ThreadCreated)throw WfpNative.Contract("CreatorChildThreadTimeMismatch");
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread,true);
            AtomicChild.AssertIndependentOfflineHandoffToken(process,tokenProof,packageSid);
            return new(process,thread,report,tokenProof,job);
        }
        catch{thread?.Dispose();process.Dispose();throw;}
    }

    internal sealed class SuspendedRoot(SafeProcessHandle process,SafeWaitHandle thread,Reply identity,TokenProof tokenProof,OwnedKernelJob job) : IDisposable
    {
        internal SessionZeroWindowAccess.Evidence? WindowAccess {get;set;}
        private int transferredOrDisposed;
        internal Reply Identity=>identity;
        internal TokenProof LpacProof=>tokenProof;
        internal (SafeProcessHandle Process,SafeWaitHandle Thread) TransferTo(OwnedKernelJob exactJob)
        {
            if(!ReferenceEquals(job,exactJob) || Interlocked.Exchange(ref transferredOrDisposed,1)!=0)
                throw WfpNative.Contract("CreatorRootTransferMismatch");
            return(process,thread);
        }
        public void Dispose()
        {
            if(Interlocked.Exchange(ref transferredOrDisposed,1)!=0)return;
            thread.Dispose();process.Dispose();
        }
    }

    internal static void AssertImage(SafeProcessHandle process,string expected)
    {
        var path=new StringBuilder(32768);uint length=(uint)path.Capacity;
        if(!QueryFullProcessImageName(process,0,path,ref length))throw Error("ReadCreatorProcessImage");
        if(!string.Equals(WindowsPathSeal.Canonical(path.ToString()),expected,StringComparison.OrdinalIgnoreCase))
            throw WfpNative.Contract("CreatorProcessImageMismatch");
    }
    private static long ProcessCreated(SafeProcessHandle process)
    {
        if(!GetProcessTimes(process,out var created,out _,out _,out _))throw Error("ReadCreatorProcessTime");
        return created;
    }
    private static Win32Exception Error(string stage)=>new(Marshal.GetLastWin32Error(),stage);
    public void Dispose()=>pipe.Dispose();

    [DllImport("advapi32.dll",EntryPoint="ConvertStringSecurityDescriptorToSecurityDescriptorW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl,uint revision,out IntPtr descriptor,out uint size);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll",EntryPoint="CreateNamedPipeW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafePipeHandle CreateNamedPipe(string name,uint open,uint mode,uint instances,uint output,uint input,uint timeout,ref KernelJobSeal.SecurityAttributes security);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe,out uint pid);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetNamedPipeClientSessionId(SafePipeHandle pipe,out uint session);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ProcessIdToSessionId(uint pid,out uint session);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint GetProcessId(SafeProcessHandle process);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint GetThreadId(SafeWaitHandle thread);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint pid);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeWaitHandle OpenThread(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint tid);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetProcessTimes(SafeProcessHandle process,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetThreadTimes(SafeWaitHandle thread,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll",EntryPoint="QueryFullProcessImageNameW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder path,ref uint length);
}
