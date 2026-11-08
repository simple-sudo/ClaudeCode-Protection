using System.Buffers.Binary;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Broker side of the fixed offline creation protocol. The SCM owner supplies
// the original, held service process after checking its service configuration.
// This channel can never start a service or resume the returned thread.
internal sealed class SessionZeroCreatorChannel : IDisposable
{
    private const uint RequestMagic=0x31504343,ReplyMagic=0x31524343; // CCP1, CCR1.
    private const int NonceSize=16,ReplySize=44;
    internal const int RequestSize=60;
    internal const string ServicePrefix="CpcSessionCreator.";
    private readonly OwnedKernelJob job;
    private readonly NamedPipeServerStream pipe;
    private int consumed;
    private byte[]? cleanupNonce;
    internal bool ProfileCleanupConfirmed {get;private set;}
    internal bool ConfirmsProfileCleanupFor(OwnedKernelJob exactJob)=>ReferenceEquals(job,exactJob) && ProfileCleanupConfirmed;
    internal bool IsPreparedFor(OwnedKernelJob exactJob)=>ReferenceEquals(job,exactJob) && Volatile.Read(ref consumed)==0 &&
        !pipe.SafePipeHandle.IsClosed && !pipe.SafePipeHandle.IsInvalid;
    internal string PipeName=>NameForJob(job.JobId);
    internal static string NameForJob(string jobId)=>ServicePrefix+Identifiers.Hex32(jobId);

    internal SessionZeroCreatorChannel(OwnedKernelJob job)
    {
        ProtectedState.RequireAdministrator();
        this.job=job;
        // Explicit FILE_READ_ATTRIBUTES; no FILE_CREATE_PIPE_INSTANCE for the
        // client. One overlapped local-only server, refusing any occupied name.
        var sddl="O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x00120083;;;"+job.SessionZeroCreatorSid+")S:(ML;;NW;;;ME)";
        if(!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl,1,out var descriptor,out _))throw Error("CreatorPipeDescriptor");
        try
        {
            var attributes=new KernelJobSeal.SecurityAttributes{Length=Marshal.SizeOf<KernelJobSeal.SecurityAttributes>(),Descriptor=descriptor};
            var handle=CreateNamedPipe(@"\\.\pipe\"+PipeName,0x40080003,8,1,128,128,0,ref attributes);
            try
            {
                if(handle.IsInvalid)throw Error("CreateFirstLocalCreatorPipe");
                pipe=new NamedPipeServerStream(PipeDirection.InOut,true,false,handle);
            }
            catch{handle.Dispose();throw;}
        }
        finally{LocalFree(descriptor);}
    }

    // The caller must retain the original Job and close it through the
    // existing offline stop path if a granted exchange fails.
    internal SuspendedRoot Exchange(FixedLayout layout,ProtectedState state,VerifiedVersion version,SafeProcessHandle service,SecurityIdentifier verifiedCreatorSid)
    {
        if(Interlocked.Exchange(ref consumed,1)!=0)throw WfpNative.Contract("CreatorPipeAlreadyConsumed");
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);
        var image=WindowsPathSeal.Child(layout.Version(version.Package.Release),"bin/admin/ProtectionBroker.exe");
        using var package=new InstallationPackageSid(state);
        var nonce=RandomNumberGenerator.GetBytes(NonceSize);
        var ownerPid=(uint)Environment.ProcessId;
        if(!ProcessIdToSessionId(ownerPid,out var ownerSession))throw Error("ReadBrokerSession");
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var cancellation=deadline.Token;
        pipe.WaitForConnectionAsync(cancellation).GetAwaiter().GetResult();
        var servicePid=AssertServicePeer(pipe.SafePipeHandle,service,ownerSession);
        // The service uses a distinct entry role of the verified Broker image.
        AssertImage(service,image);
        var serviceCreated=ProcessCreated(service);
        var request=CreateRequest(nonce,state.InstallationId,job.JobId,ownerPid,ownerSession);
        AssertQuarantine(state);
        job.ReserveSessionZeroAdmission(version,verifiedCreatorSid);
        pipe.WriteAsync(request.AsMemory(),cancellation).AsTask().GetAwaiter().GetResult();
        var reply=new byte[ReplySize];
        pipe.ReadExactlyAsync(reply.AsMemory(),cancellation).AsTask().GetAwaiter().GetResult();
        _=AssertServicePeer(pipe.SafePipeHandle,service,ownerSession);
        var report=ParseReply(reply,nonce,servicePid,serviceCreated);
        // A completed reply promises the fixed service has returned from
        // CreateProcess and closed its assignment handle. Read the DACL and
        // actual handle count before inspecting any returned process IDs.
        job.ConfirmSessionZeroCreatorReleased();
        var root=OpenRoot(report,job,image,package.Value);
        try
        {
            AssertQuarantine(state);
            job.AssertCreatorSealedBeforeResume();
            cleanupNonce=nonce;
            return root;
        }
        catch{root.Dispose();throw;}
    }

    internal (OfflineConsoleOutput Output,OfflineConsoleOutput Error) CloseCreatorProfile(ProtectedState state)
    {
        job.AssertCreatorProfileCleanupAllowed(state);
        AssertQuarantine(state);
        var nonce=Interlocked.Exchange(ref cleanupNonce,null)??throw WfpNative.Contract("CreatorProfileCleanupChannelUnavailable");
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(10));
        pipe.WriteAsync(SessionZeroCreatorTerminal.CloseFrame(nonce).AsMemory(),deadline.Token).AsTask().GetAwaiter().GetResult();
        var result=SessionZeroCreatorTerminal.ReadReceipt(pipe,nonce,deadline.Token);
        ProfileCleanupConfirmed=true;
        return result;
    }

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

    internal sealed record Request(string InstallationId,string JobId,byte[] Nonce);
    internal static Request ParseRequest(byte[] frame,string fixedJobId,uint serverPid,uint serverSession)
    {
        if(frame.Length!=RequestSize || serverPid==0 || serverSession==0 || BinaryPrimitives.ReadUInt32LittleEndian(frame)!=RequestMagic ||
            BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(4))!=serverPid || BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(8))!=serverSession ||
            !frame.AsSpan(44,16).SequenceEqual(Convert.FromHexString(Identifiers.Hex32(fixedJobId))))
            throw WfpNative.Contract("CreatorRequestBindingMismatch");
        return new(Convert.ToHexString(frame.AsSpan(28,16)).ToLowerInvariant(),fixedJobId,frame.AsSpan(12,NonceSize).ToArray());
    }

    internal readonly record struct Reply(uint Pid,uint Tid,long ProcessCreated,long ThreadCreated);
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
    internal static Reply ParseReply(byte[] frame,byte[] nonce,uint creatorPid,long creatorCreated)
    {
        if(frame.Length!=ReplySize || nonce.Length!=NonceSize || creatorPid==0 || creatorCreated<=0 ||
            BinaryPrimitives.ReadUInt32LittleEndian(frame)!=ReplyMagic || !CryptographicOperations.FixedTimeEquals(frame.AsSpan(4,NonceSize),nonce))
            throw WfpNative.Contract("CreatorReplyBindingMismatch");
        var pid=BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(20));
        var tid=BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(24));
        var processCreated=BinaryPrimitives.ReadInt64LittleEndian(frame.AsSpan(28));
        var threadCreated=BinaryPrimitives.ReadInt64LittleEndian(frame.AsSpan(36));
        if(pid==0 || pid==creatorPid || tid==0 || processCreated<creatorCreated || threadCreated<processCreated)
            throw WfpNative.Contract("CreatorReplyObjectIdentityInvalid");
        return new(pid,tid,processCreated,threadCreated);
    }

    private static SuspendedRoot OpenRoot(Reply report,OwnedKernelJob job,string image,string packageSid)
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
            AtomicChild.AssertIndependentOfflineHandoffToken(process,packageSid);
            thread=OpenThread(0x120802,false,report.Tid);
            if(thread.IsInvalid)throw Error("HoldCreatorChildThread");
            AtomicChild.AssertHeldInitialThread(process,thread,report.Pid,report.Tid);
            if(!GetThreadTimes(thread,out var threadCreated,out _,out _,out _))throw Error("ReadCreatorChildThreadTime");
            if(threadCreated!=report.ThreadCreated)throw WfpNative.Contract("CreatorChildThreadTimeMismatch");
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread,true);
            return new(process,thread,report,job);
        }
        catch{thread?.Dispose();process.Dispose();throw;}
    }

    internal sealed class SuspendedRoot(SafeProcessHandle process,SafeWaitHandle thread,Reply identity,OwnedKernelJob job) : IDisposable
    {
        private int transferredOrDisposed;
        internal Reply Identity=>identity;
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
