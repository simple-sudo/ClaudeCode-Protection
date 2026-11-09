using System.Buffers.Binary;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using static ProtectionLifecycle.SessionZeroCreatorRegistration;

namespace ProtectionLifecycle;

// The SYSTEM role owns two USER objects only. The original interactive Broker
// retains the SCM registration, original Job, and all process admission rights.
internal sealed class SessionZeroWindowOwner : IDisposable
{
    internal const string IntentPrefix="window-owner-intent-";
    private const string Prefix="CpcWindowOwner.",Account="LocalSystem",Closed="WINDOWS_CLOSED_AND_SERVICE_REMOVED",Unstarted="WINDOW_OWNER_REMOVED_BEFORE_START";
    internal enum Message:uint {Ready=0x31525743,Release=0x31585743,Closed=0x31445743}
    private const uint Running=258;
    private readonly ProtectedState state;
    private readonly OwnedKernelJob job;
    private readonly string name,image,intentHash;
    private readonly ServiceHandle manager,service;
    private readonly SafeProcessHandle worker;
    private readonly NamedPipeServerStream pipe;
    private readonly byte[] nonce;
    private readonly uint brokerSession;

    private SessionZeroWindowOwner(ProtectedState state,OwnedKernelJob job,string name,string image,string intentHash,
        ServiceHandle manager,ServiceHandle service,SafeProcessHandle worker,NamedPipeServerStream pipe,byte[] nonce,uint brokerSession)
    {this.state=state;this.job=job;this.name=name;this.image=image;this.intentHash=intentHash;
        this.manager=manager;this.service=service;this.worker=worker;this.pipe=pipe;this.nonce=nonce;this.brokerSession=brokerSession;}

    internal static string NameForJob(string jobId)=>Prefix+Identifiers.Hex32(jobId);
    internal static string JobIdFromName(string name)=>name.StartsWith(Prefix,StringComparison.Ordinal)?Identifiers.Hex32(name[Prefix.Length..]):
        throw WfpNative.Contract("PrivateWindowOwnerServiceNameInvalid");
    private static string DoneLeaf(string jobId)=>"window-owner-done-"+Identifiers.Hex32(jobId)+".json";
    private static string StartLeaf(string jobId)=>"window-owner-start-"+Identifiers.Hex32(jobId)+".json";

    internal static SessionZeroWindowOwner Start(FixedLayout layout,ProtectedState state,VerifiedVersion version,OwnedKernelJob job)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);
        if(version.Package.SchemaVersion!=PackageAssetCatalog.SessionZeroPrivateWindowSchema)
            throw WfpNative.Contract("PrivateWindowOwnerRequiresFixedPackage");
        var intent=OwnedJobIntent.Read(state,job.JobId);
        if(intent.CreatorServiceSid!=job.SessionZeroCreatorSid || intent.Release!=version.Package.Release || intent.ManifestSHA256!=version.Package.ManifestHash)
            throw WfpNative.Contract("PrivateWindowOwnerJobMismatch");
        var image=AtomicChild.ResolveSessionZeroImage(layout,Environment.ProcessPath);
        if(!string.Equals(image,WindowsPathSeal.Child(layout.Version(intent.Release),"bin/admin/ProtectionBroker.exe"),StringComparison.OrdinalIgnoreCase))
            throw WfpNative.Contract("PrivateWindowOwnerImageMismatch");
        var brokerPid=(uint)Environment.ProcessId;
        if(!ProcessIdToSessionId(brokerPid,out var brokerSession) || brokerSession==0)throw WfpNative.Contract("PrivateWindowOwnerBrokerSessionMissing");
        var name=NameForJob(job.JobId);
        var command="\""+image+"\" session-zero-window-owner";
        var manager=OpenSCManager(null,null,3);
        ServiceHandle? service=null;
        NamedPipeServerStream? pipe=null;
        SafeProcessHandle? worker=null;
        string? intentHash=null;
        var startAttempted=false;
        try
        {
            if(manager.IsInvalid)throw Error("OpenWindowOwnerServiceManager");
            using(var prior=OpenService(manager,name,4))
                if(!prior.IsInvalid || Marshal.GetLastWin32Error()!=1060)throw WfpNative.Contract("PrivateWindowOwnerServiceNotFresh");
            var jobHash=state.Read(OwnedJobIntent.Leaf(job.JobId),8192).SHA256;
            intentHash=state.WriteNew(IntentPrefix+job.JobId+".json",JsonSerializer.SerializeToUtf8Bytes(new{
                SchemaVersion=1,state.InstallationId,job.JobId,JobSHA256=jobHash}));
            service=CreateService(manager,name,name,0x000f0017,0x10,3,1,command,null,IntPtr.Zero,null,Account,null);
            if(service.IsInvalid)throw Error("CreatePrivateWindowOwnerService");
            SealRegistration(service);
            AssertServiceConfiguration(service,name,command,Account);
            var sid=ServiceSid(name);
            pipe=SessionZeroCreatorChannel.CreateOwnerPipe(name,sid);
            var nonce=RandomNumberGenerator.GetBytes(16);
            state.WriteNew(StartLeaf(job.JobId),JsonSerializer.SerializeToUtf8Bytes(new{SchemaVersion=1,IntentSHA256=intentHash}));
            startAttempted=true;
            if(!StartService(service,0,IntPtr.Zero))throw Error("StartPrivateWindowOwnerService");
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(8));
            worker=HoldWorker(service,image,deadline.Token);
            pipe.WaitForConnectionAsync(deadline.Token).GetAwaiter().GetResult();
            SessionZeroCreatorChannel.AssertServicePeer(pipe.SafePipeHandle,worker,brokerSession);
            // Mark only after the worker has registered with the SCM and its
            // pipe is bound. No USER object can be created before this succeeds.
            if(!DeleteService(service))throw Error("MarkOriginalPrivateWindowOwnerForDeletion");
            Send(pipe,SessionZeroCreatorChannel.CreateRequest(nonce,state.InstallationId,job.JobId,brokerPid,brokerSession),deadline.Token);
            Receive(pipe,nonce,Message.Ready,deadline.Token);
            var owner=new SessionZeroWindowOwner(state,job,name,image,intentHash,manager,service,worker,pipe,nonce,brokerSession);
            owner.AssertHeld(job);
            return owner;
        }
        catch(Exception original)
        {
            try
            {
                if(!startAttempted && service is {IsInvalid:false} && intentHash is not null)
                    CloseRegistration(state,job.JobId,manager,service,name,intentHash,Unstarted,null);
            }
            catch(Exception cleanup){throw new AggregateException("Private window owner setup and unstarted cleanup failed",original,cleanup);}
            finally{pipe?.Dispose();worker?.Dispose();service?.Dispose();manager.Dispose();}
            throw;
        }
    }

    internal void AssertHeld(OwnedKernelJob exactJob)
    {
        state.AssertHeld();
        if(!ReferenceEquals(job,exactJob) || !pipe.IsConnected)throw WfpNative.Contract("PrivateWindowOwnerBindingLost");
        var pid=SessionZeroCreatorChannel.AssertServicePeer(pipe.SafePipeHandle,worker,brokerSession);
        var status=ReadStatus(service);
        if(status.State!=4 || status.Pid!=pid)throw WfpNative.Contract("PrivateWindowOwnerServiceNotRunning");
        SessionZeroCreatorChannel.AssertImage(worker,image);
    }

    internal void CloseAfterJob(OwnedKernelJob exactJob)
    {
        exactJob.AssertCreatorProfileCleanupAllowed(state);
        AssertHeld(exactJob);
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Send(pipe,Frame(nonce,Message.Release),deadline.Token);
        Receive(pipe,nonce,Message.Closed,deadline.Token);
        if(WaitForSingleObject(worker,5000)!=0 || !GetExitCodeProcess(worker,out var exit) || exit!=0)
            throw WfpNative.Contract("PrivateWindowOwnerTerminalUnconfirmed");
        var completion=state.Read("job-completed-"+job.JobId+".json",8192).SHA256;
        CloseRegistration(state,job.JobId,manager,service,name,intentHash,Closed,completion);
    }

    private static void CloseRegistration(ProtectedState state,string jobId,ServiceHandle manager,ServiceHandle service,string name,string hash,
        string disposition,string? completion)
    {
        var status=ReadStatus(service);
        if(status.State!=1 || status.Pid!=0 || status.ServiceCode!=0 ||
            (disposition==Unstarted?status.Win32Code is not (0 or 1077):status.Win32Code!=0))
            throw WfpNative.Contract("PrivateWindowOwnerStoppedUnconfirmed");
        if(disposition==Unstarted && !DeleteService(service))throw Error("RemoveUnstartedPrivateWindowOwnerService");
        service.Dispose();
        WaitForAbsence(manager,name);
        state.WriteNew(DoneLeaf(jobId),JsonSerializer.SerializeToUtf8Bytes(new{SchemaVersion=1,IntentSHA256=hash,Disposition=disposition,JobCompletionSHA256=completion}));
    }

    internal static void AssertNoPending(ProtectedState state)
    {
        var leaves=state.ListLeaves(IntentPrefix);
        if(leaves.Length>1024)throw WfpNative.Contract("PrivateWindowOwnerInventoryLimit");
        foreach(var leaf in leaves)
        {
            if(leaf.Length!=IntentPrefix.Length+37)throw WfpNative.Contract("PrivateWindowOwnerIntentNameInvalid");
            var jobId=Identifiers.Hex32(leaf.Substring(IntentPrefix.Length,32));
            if(leaf!=IntentPrefix+jobId+".json")throw WfpNative.Contract("PrivateWindowOwnerIntentNameInvalid");
            var intent=state.Read(leaf,4096);
            CheckIntent(intent,state.InstallationId,jobId,state.Read(OwnedJobIntent.Leaf(jobId),8192).SHA256);
            var done=state.ReadOptional(DoneLeaf(jobId))??throw WfpNative.Contract("PrivateWindowOwnerRecoveryRequired");
            using var doc=JsonDocument.Parse(done.Bytes);
            var record=doc.RootElement;
            StrictJson.Fields(record,"SchemaVersion","IntentSHA256","Disposition","JobCompletionSHA256");
            var disposition=StrictJson.Text(record,"Disposition");
            if(record.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(record,"IntentSHA256")!=intent.SHA256 ||
                disposition is not (Closed or Unstarted))throw WfpNative.Contract("PrivateWindowOwnerClosureMismatch");
            var started=state.ReadOptional(StartLeaf(jobId));
            if(disposition==Unstarted)
            {
                if(started is not null || record.GetProperty("JobCompletionSHA256").ValueKind!=JsonValueKind.Null)
                    throw WfpNative.Contract("PrivateWindowOwnerUnstartedClosureMismatch");
                continue;
            }
            if(started is null)throw WfpNative.Contract("PrivateWindowOwnerStartProofMissing");
            ValidateStartProof(started.Bytes,intent.SHA256);
            if(AtomicJobCompletion.ReadClosed(state,OwnedJobIntent.Read(state,jobId)) is null ||
                StrictJson.Text(record,"JobCompletionSHA256")!=state.Read("job-completed-"+jobId+".json",8192).SHA256)
                throw WfpNative.Contract("PrivateWindowOwnerJobClosureChanged");
        }
    }

    private static void CheckIntent(BoundBytes raw,string install,string jobId,string jobHash)
    {
        using var doc=JsonDocument.Parse(raw.Bytes);
        var record=doc.RootElement;
        StrictJson.Fields(record,"SchemaVersion","InstallationId","JobId","JobSHA256");
        if(record.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(record,"InstallationId")!=install ||
            StrictJson.Text(record,"JobId")!=jobId || StrictJson.Text(record,"JobSHA256")!=jobHash)
            throw WfpNative.Contract("PrivateWindowOwnerIntentMismatch");
    }

    internal static SecurityIdentifier VerifyCurrentService(string name)
    {
        using var impersonating=WindowsIdentity.GetCurrent(ifImpersonating:true);
        using var identity=WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        var token=identity.AccessToken;
        const string stage="PrivateWindowOwnerToken";
        if(impersonating is not null || identity.User?.IsWellKnown(WellKnownSidType.LocalSystemSid)!=true ||
            WindowsTokenInformation.Read(token,WindowsTokenInformation.Dword.Type,stage)!=1 ||
            WindowsTokenInformation.Read(token,WindowsTokenInformation.Dword.SessionId,stage)!=0 ||
            WindowsTokenInformation.Read(token,WindowsTokenInformation.Dword.IsAppContainer,stage)!=0)
            throw WfpNative.Contract("PrivateWindowOwnerRequiresSystemServiceToken");
        var sid=ServiceSid(name);
        if(RestrictingSidToken.ReadGroups(token,2).Count(group=>group.Sid==sid.Value && (group.Attributes&0x14)==4)!=1 ||
            RestrictingSidToken.ReadGroups(token,11).Count!=0)throw WfpNative.Contract("PrivateWindowOwnerServiceSidMismatch");
        RestrictingSidToken.AssertTraverseOnly(token);
        return sid;
    }

    internal static void RunWorker(string jobId,SecurityIdentifier sid)
    {
        var layout=FixedLayout.FromWindows();
        var image=AtomicChild.ResolveSessionZeroImage(layout,Environment.ProcessPath);
        using var parent=WindowsPathSeal.LockDirectory(Path.GetDirectoryName(layout.StateRoot)!,PathPolicy.CreationParent);
        using var directory=WindowsPathSeal.LockDirectory(layout.StateRoot,PathPolicy.Protected);
        using var handle=SessionZeroCreatorClient.OpenOwnerPipeByName(NameForJob(jobId));
        SessionZeroCreatorClient.AssertOwnerPipe(KernelJobSeal.ReadCreatorPipeDescriptor(handle),sid);
        var peer=SessionZeroCreatorClient.ReadServerPeer(handle);
        using var broker=OpenProcess(0x101000,false,peer.Pid);
        if(broker.IsInvalid || peer.Session==0 || WaitForSingleObject(broker,0)!=Running)throw WfpNative.Contract("PrivateWindowOwnerBrokerUnconfirmed");
        SessionZeroCreatorChannel.AssertImage(broker,image);
        AssertBrokerToken(broker,peer.Session);
        using var pipe=new NamedPipeClientStream(PipeDirection.InOut,true,true,handle);
        using var setup=new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var request=SessionZeroCreatorChannel.ParseRequest(Read(pipe,SessionZeroCreatorChannel.RequestSize,setup.Token),jobId,peer.Pid,peer.Session);
        if(SessionZeroCreatorClient.ReadServerPeer(handle)!=peer ||
            directory.ReadCreationTag().Sid!=CreationTag.For(CreationRole.StateRoot,request.InstallationId).Sid)
            throw WfpNative.Contract("PrivateWindowOwnerBrokerOrInstallationChanged");
        var original=ProtectedState.ReadBound(directory,OwnedJobIntent.Leaf(jobId),8192,true);
        CheckIntent(ProtectedState.ReadBound(directory,IntentPrefix+jobId+".json",4096,true),request.InstallationId,jobId,original.SHA256);
        using var doc=JsonDocument.Parse(original.Bytes);
        var job=OwnedJobIntent.Parse(doc.RootElement,request.InstallationId,jobId);
        var current=CurrentPointer.Parse(ProtectedState.ReadBound(directory,"current.json",4096,true),job.InstallationId);
        if(job.CreatorServiceSid!=ServiceSid(SessionZeroCreatorChannel.NameForJob(jobId)).Value || job.Release!=current.Release || job.ManifestSHA256!=current.ManifestSHA256 ||
            !string.Equals(image,WindowsPathSeal.Child(layout.Version(job.Release),"bin/admin/ProtectionBroker.exe"),StringComparison.OrdinalIgnoreCase))
            throw WfpNative.Contract("PrivateWindowOwnerOriginalJobMismatch");
        using var lease=SessionZeroWindowLease.Create(job);
        try
        {
            Send(pipe,Frame(request.Nonce,Message.Ready),setup.Token);
            using var run=new CancellationTokenSource(TimeSpan.FromSeconds(45));
            Receive(pipe,request.Nonce,Message.Release,run.Token);
            AssertCompletion(directory,job,original.SHA256);
        }
        catch
        {
            // Loss of the original IPC is not normal closure. Keep the USER
            // objects until the broker has proved zero or lost its kernel Job.
            WaitForSafeAbandonment(broker,directory,job,original.SHA256);
            throw;
        }
        lease.CloseAndConfirmAbsent();
        using var reply=new CancellationTokenSource(TimeSpan.FromSeconds(3));
        Send(pipe,Frame(request.Nonce,Message.Closed),reply.Token);
    }

    private static void AssertCompletion(PathLease directory,OwnedJobIntent job,string jobHash)
    {
        if(ProtectedState.ReadBound(directory,OwnedJobIntent.Leaf(job.JobId),8192,true).SHA256!=jobHash)
            throw WfpNative.Contract("PrivateWindowOwnerOriginalJobChanged");
        var done=ProtectedState.ReadBound(directory,"job-completed-"+job.JobId+".json",8192,true);
        var proof=AtomicJobCompletion.ParseClosed(done.Bytes,job);
        var admission=ProtectedState.ReadBound(directory,"job-admission-"+job.JobId+".json",8192,true);
        if(admission.SHA256!=proof.AdmissionSHA256)throw WfpNative.Contract("PrivateWindowOwnerAdmissionProofChanged");
    }

    private static void WaitForSafeAbandonment(SafeProcessHandle broker,PathLease directory,OwnedJobIntent job,string jobHash)
    {
        while(WaitForSingleObject(broker,250)!=0)
        {
            try{AssertCompletion(directory,job,jobHash);return;}
            catch(Exception error) when(error is IOException or InvalidDataException or JsonException or Win32Exception){Thread.Sleep(100);}
        }
        // The original Broker is gone. Do not open or touch the Job while it
        // could still be owned by the original Broker's live creation path.
        while(true)
        {
            try{OwnedKernelJob.AssertCreatorNameAbsent(job);return;}
            catch(InvalidDataException){Thread.Sleep(250);}
        }
    }

    private static void AssertBrokerToken(SafeProcessHandle broker,uint session)
    {
        if(!OpenProcessToken(broker,8,out var token))throw Error("ReadPrivateWindowOwnerBrokerToken");
        using(token)
        {
            const string stage="PrivateWindowOwnerBrokerToken";
            if(WindowsTokenInformation.Read(token,WindowsTokenInformation.Dword.SessionId,stage)!=session ||
                WindowsTokenInformation.Read(token,WindowsTokenInformation.Dword.IsAppContainer,stage)!=0 ||
                WindowsTokenInformation.Read(token,WindowsTokenInformation.Dword.Elevation,stage)!=1 ||
                !RestrictingSidToken.ReadGroups(token,2).Any(g=>g.Sid=="S-1-5-32-544" && (g.Attributes&0x14)==4))
                throw WfpNative.Contract("PrivateWindowOwnerBrokerTokenRefused");
        }
    }

    private static SafeProcessHandle HoldWorker(ServiceHandle service,string image,CancellationToken deadline)
    {
        while(!deadline.IsCancellationRequested)
        {
            var status=ReadStatus(service);
            if(status.State==1)throw new WfpFailure("PrivateWindowOwnerStoppedDuringStartup",status.Win32Code==1066?status.ServiceCode:status.Win32Code);
            if(status.State==4 && status.Pid!=0)
            {
                var worker=OpenProcess(0x101000,false,status.Pid);
                try
                {
                    if(worker.IsInvalid)throw Error("HoldPrivateWindowOwnerProcess");
                    SessionZeroCreatorChannel.AssertImage(worker,image);
                    var after=ReadStatus(service);
                    if(after.State!=4 || after.Pid!=status.Pid || WaitForSingleObject(worker,0)!=Running)
                        throw WfpNative.Contract("PrivateWindowOwnerProcessChanged");
                    return worker;
                }
                catch{worker.Dispose();throw;}
            }
            Thread.Sleep(25);
        }
        throw new TimeoutException("Private window owner startup unconfirmed");
    }

    private static SecurityIdentifier ServiceSid(string name)=>(SecurityIdentifier)new NTAccount("NT SERVICE",name).Translate(typeof(SecurityIdentifier));
    internal static byte[] Frame(byte[] nonce,Message kind)
    {
        if(nonce.Length!=16 || !Enum.IsDefined(kind))throw WfpNative.Contract("PrivateWindowOwnerFrameInvalid");
        var frame=new byte[20];
        BinaryPrimitives.WriteUInt32LittleEndian(frame,(uint)kind);
        nonce.CopyTo(frame,4);
        return frame;
    }
    internal static void AssertFrame(byte[] frame,byte[] nonce,Message kind)
    {
        if(frame.Length!=20 || !CryptographicOperations.FixedTimeEquals(frame,Frame(nonce,kind)))throw WfpNative.Contract("PrivateWindowOwnerFrameMismatch");
    }
    private static void Receive(PipeStream pipe,byte[] nonce,Message kind,CancellationToken cancellation)=>AssertFrame(Read(pipe,20,cancellation),nonce,kind);
    private static byte[] Read(PipeStream pipe,int size,CancellationToken cancellation)
    {var bytes=new byte[size];pipe.ReadExactlyAsync(bytes.AsMemory(),cancellation).AsTask().GetAwaiter().GetResult();return bytes;}
    private static void Send(PipeStream pipe,byte[] bytes,CancellationToken cancellation)=>pipe.WriteAsync(bytes.AsMemory(),cancellation).AsTask().GetAwaiter().GetResult();
    public void Dispose(){pipe.Dispose();worker.Dispose();service.Dispose();manager.Dispose();}
    private static Win32Exception Error(string stage)=>new(Marshal.GetLastWin32Error(),stage);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ProcessIdToSessionId(uint pid,out uint session);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint rights,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint pid);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetExitCodeProcess(SafeProcessHandle process,out uint exit);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool OpenProcessToken(SafeProcessHandle process,uint access,out SafeAccessTokenHandle token);
}
