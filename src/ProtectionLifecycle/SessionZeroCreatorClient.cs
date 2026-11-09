using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// LocalService half of the fixed one-shot protocol. The future SCM entry must
// pass only the identifier from its own verified fixed service name.
internal sealed class SessionZeroCreatorClient : IDisposable
{
    private const int PipeRights=0x00120083;
    private readonly NamedPipeClientStream pipe;
    private readonly SafeJobHandle assignment;
    private int completed;
    private bool profileRecorded;
    internal SessionZeroCreatorChannel.Request Request {get;}
    internal SafeJobHandle Assignment=>profileRecorded?assignment:throw WfpNative.Contract("CreatorProfileMustBeRecordedBeforeAssignment");

    private SessionZeroCreatorClient(NamedPipeClientStream pipe,SafeJobHandle assignment,SessionZeroCreatorChannel.Request request)
    {this.pipe=pipe;this.assignment=assignment;Request=request;}

    internal static SessionZeroCreatorClient Connect(string jobId)
    {
        var name=SessionZeroCreatorChannel.NameForJob(jobId);
        var sid=VerifyCurrentService(name);
        var handle=OpenOwnerPipeHandle(jobId);
        NamedPipeClientStream? client=null;
        SafeJobHandle? job=null;
        try
        {
            AssertOwnerPipe(KernelJobSeal.ReadCreatorPipeDescriptor(handle),sid);
            var peer=ReadServerPeer(handle);
            if(peer.Session==0 || peer.Pid==0)throw WfpNative.Contract("CreatorOwnerRequiresInteractiveSession");
            client=new NamedPipeClientStream(PipeDirection.InOut,true,true,handle);
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var frame=new byte[SessionZeroCreatorChannel.RequestSize];
            client.ReadExactlyAsync(frame.AsMemory(),deadline.Token).AsTask().GetAwaiter().GetResult();
            if(ReadServerPeer(handle)!=peer)throw WfpNative.Contract("CreatorOwnerPeerChanged");
            var request=SessionZeroCreatorChannel.ParseWorkloadRequest(frame,jobId,peer.Pid,peer.Session);
            job=OpenJobObject(KernelJobSeal.CreatorRights,false,OwnedJobIntent.CreatorJobName(request.InstallationId,request.JobId));
            if(job.IsInvalid)throw Error("OpenCreatorAssignmentJob");
            KernelJobSeal.AssertGrantedCreatorJob(job,jobId,sid.Value);
            return new(client,job,request);
        }
        catch
        {
            job?.Dispose();
            if(client is null)handle.Dispose();else client.Dispose();
            throw;
        }
    }

    internal static SafePipeHandle OpenOwnerPipeHandle(string jobId)
    {
        // Explicit rights exclude FILE_CREATE_PIPE_INSTANCE. Identification
        // prevents the peer from borrowing the service's primary authority.
        var handle=OpenPipe(@"\\.\pipe\"+SessionZeroCreatorChannel.NameForJob(jobId),PipeRights,0,IntPtr.Zero,3,0x40110000,IntPtr.Zero);
        if(!handle.IsInvalid)return handle;
        var failure=Error("OpenLocalCreatorOwnerPipe");handle.Dispose();throw failure;
    }

    // Call after the synchronous creation call has returned. Do not publish
    // completion until this side's sole assignment handle has been closed.
    internal void CompleteCreation(SafeProcessHandle process,SafeWaitHandle thread)
    {
        if(Interlocked.Exchange(ref completed,1)!=0)throw WfpNative.Contract("CreatorCompletionAlreadySent");
        assignment.Dispose();
        var frame=SessionZeroCreatorChannel.CreateReply(Request,SessionZeroCreatorChannel.ObserveCreatedRoot(process,thread));
        thread.Dispose();
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        pipe.WriteAsync(frame.AsMemory(),deadline.Token).AsTask().GetAwaiter().GetResult();
    }

    private void ReportTokenProof(SafeProcessHandle process)
    {
        byte[] frame;
        SessionZeroCreatorChannel.TokenProof? proof=null;
        try
        {
            var observed=AtomicChild.ObserveCreatorTokenProof(process);
            frame=SessionZeroCreatorChannel.CreateTokenProof(Request,observed);
            proof=observed;
        }
        catch(Exception error) when(error is Win32Exception or WfpFailure or InvalidDataException)
        {
            var stage=error.Data["Stage"] is "CreatorOpenHeldChildTokenForAccessCheck"?
                SessionZeroCreatorChannel.CreationFailure.TokenOpen:SessionZeroCreatorChannel.CreationFailure.TokenAccessCheck;
            frame=SessionZeroCreatorChannel.CreateFailure(Request,stage,FailureCode(error));
        }
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        pipe.WriteAsync(frame.AsMemory(),deadline.Token).AsTask().GetAwaiter().GetResult();
        if(Request.ObserveWindowAccess && proof is { } exactProof)
        {
            try{frame=SessionZeroCreatorChannel.CreateWindowAccess(Request,SessionZeroWindowAccess.Observe(process,exactProof));}
            catch(Exception error) when(error is Win32Exception or WfpFailure or InvalidDataException)
            {
                frame=SessionZeroCreatorChannel.CreateFailure(Request,SessionZeroCreatorChannel.CreationFailure.WindowAccess,FailureCode(error));
            }
            pipe.WriteAsync(frame.AsMemory(),deadline.Token).AsTask().GetAwaiter().GetResult();
        }
    }

    private void RecordCreatedProfile(SessionZeroCreatorProfile profile)
    {
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var frame=SessionZeroCreatorChannel.CreateProfileCreated(Request,profile.ObserveCreatedStorage());
        pipe.WriteAsync(frame.AsMemory(),deadline.Token).AsTask().GetAwaiter().GetResult();
        var acknowledgement=new byte[SessionZeroCreatorChannel.ProfileRecordedSize];
        pipe.ReadExactlyAsync(acknowledgement.AsMemory(),deadline.Token).AsTask().GetAwaiter().GetResult();
        SessionZeroCreatorChannel.AssertProfileRecorded(acknowledgement,Request.Nonce);
        profileRecorded=true;
    }

    internal static void RunOfflineCreator(string jobId)
    {
        using var client=Connect(jobId);
        var stage=SessionZeroCreatorChannel.CreationFailure.Profile;
        try
        {
            using var profile=SessionZeroCreatorProfile.Create(client);
            client.RecordCreatedProfile(profile);
            stage=SessionZeroCreatorChannel.CreationFailure.Streams;
            using var streams=new OfflineConsoleStreams();
            stage=SessionZeroCreatorChannel.CreationFailure.AtomicCreate;
            var root=AtomicChild.CreateSessionZeroOfflineConsole(client,profile,streams);
            using var process=root.Process;
            using var thread=root.Thread;
            stage=SessionZeroCreatorChannel.CreationFailure.Streams;
            var capture=streams.ReadAfterCreate();
            client.CompleteCreation(process,thread);
            client.ReportTokenProof(process);
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(35));
            var close=new byte[SessionZeroCreatorTerminal.CloseSize];
            client.pipe.ReadExactlyAsync(close.AsMemory(),deadline.Token).AsTask().GetAwaiter().GetResult();
            SessionZeroCreatorTerminal.AssertCloseFrame(close,client.Request.Nonce);
            if(WaitForSingleObject(process,0)!=0)throw WfpNative.Contract("CreatorProfileChildNotTerminal");
            profile.CleanupAfterOwnerStop();
            using var replyDeadline=new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var nonce=client.Request.Nonce;
            client.pipe.WriteAsync(SessionZeroCreatorTerminal.CleanedFrame(nonce).AsMemory(),replyDeadline.Token)
                .AsTask().GetAwaiter().GetResult();
            byte[] receipt;
            try
            {
                using var captureDeadline=new CancellationTokenSource(TimeSpan.FromSeconds(3));
                var results=Task.WhenAll(capture.Output,capture.Error).WaitAsync(captureDeadline.Token).GetAwaiter().GetResult();
                receipt=SessionZeroCreatorTerminal.CreateReceipt(nonce,results[0],results[1]);
            }
            catch(Exception error) when(error is IOException or InvalidDataException or OperationCanceledException)
            {
                receipt=SessionZeroCreatorTerminal.CaptureFailure(nonce,unchecked((uint)error.HResult));
            }
            client.pipe.WriteAsync(receipt.AsMemory(),replyDeadline.Token).AsTask().GetAwaiter().GetResult();
        }
        catch(Exception failure)
        {
            try{client.ReportCreationFailure(stage,failure);}
            catch(Exception transport){throw new AggregateException("Creator and failure report both failed",failure,transport);}
            throw;
        }
    }

    private void ReportCreationFailure(SessionZeroCreatorChannel.CreationFailure stage,Exception failure)
    {
        if(Interlocked.Exchange(ref completed,1)!=0)return;
        assignment.Dispose();
        var frame=SessionZeroCreatorChannel.CreateFailure(Request,stage,FailureCode(failure));
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(2));
        pipe.WriteAsync(frame.AsMemory(),deadline.Token).AsTask().GetAwaiter().GetResult();
    }

    private static uint FailureCode(Exception failure)
    {
        var code=failure switch
        {
            WfpFailure wfp=>wfp.Status,
            Win32Exception native=>unchecked((uint)native.NativeErrorCode),
            _=>unchecked((uint)failure.HResult)
        };
        return code==0?13u:code;
    }

    internal static SecurityIdentifier VerifyCurrentService(string name,Action<SessionZeroCreatorService.FailurePhase>? reportStartupPhase=null)
    {
        using var identity=WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        var token=identity.AccessToken;
        const string stage="CreatorPrimaryToken";
        if(!Environment.Is64BitProcess || identity.User?.IsWellKnown(WellKnownSidType.LocalServiceSid)!=true ||
            WindowsTokenInformation.Read(token,WindowsTokenInformation.Dword.Type,stage)!=1 ||
            WindowsTokenInformation.Read(token,WindowsTokenInformation.Dword.SessionId,stage)!=0 ||
            WindowsTokenInformation.Read(token,WindowsTokenInformation.Dword.IsAppContainer,stage)!=0 ||
            WindowsTokenInformation.Read(token,WindowsTokenInformation.Dword.Elevation,stage)!=0 || IsTokenRestricted(token))
            throw WfpNative.Contract("CreatorRequiresUnrestrictedLocalServicePrimaryToken");
        reportStartupPhase?.Invoke(SessionZeroCreatorService.FailurePhase.VerifyTokenGroups);
        var service=(SecurityIdentifier)new NTAccount("NT SERVICE",name).Translate(typeof(SecurityIdentifier));
        var groups=RestrictingSidToken.ReadGroups(token,2);
        AssertCreatorGroups(groups,RestrictingSidToken.ReadGroups(token,11),service.Value);
        reportStartupPhase?.Invoke(SessionZeroCreatorService.FailurePhase.VerifyTokenPrivileges);
        RestrictingSidToken.AssertTraverseOnly(token);
        return service;
    }

    internal static void AssertCreatorGroups(IReadOnlyList<(string Sid,uint Attributes)> groups,
        IReadOnlyList<(string Sid,uint Attributes)> restricting,string serviceSid)
    {
        if(groups.Any(g=>g.Sid.StartsWith("S-1-5-21-",StringComparison.Ordinal) || g.Sid=="S-1-5-32-544" && (g.Attributes&4)!=0) ||
            restricting.Count!=0 || groups.Count(g=>g.Sid==serviceSid && (g.Attributes&0x14)==4)!=1)
            throw WfpNative.Contract("CreatorServiceGroupMismatch");
    }

    internal static void AssertOwnerPipe(RawSecurityDescriptor descriptor,SecurityIdentifier service)
    {
        var required=new Dictionary<string,int>(StringComparer.Ordinal){{"S-1-5-18",0x001f01ff},{"S-1-5-32-544",0x001f01ff},{service.Value,PipeRights}};
        if(descriptor.Owner?.Value!="S-1-5-32-544" || (descriptor.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 ||
            descriptor.DiscretionaryAcl is not {Count:3} grants)
            throw WfpNative.Contract("CreatorOwnerPipeDescriptorMismatch");
        foreach(GenericAce entry in grants)
            if(entry is not CommonAce ace || ace.IsCallback || ace.AceFlags!=AceFlags.None || ace.AceQualifier!=AceQualifier.AccessAllowed ||
                !required.Remove(ace.SecurityIdentifier.Value,out var mask) || ace.AccessMask!=mask)
                throw WfpNative.Contract("CreatorOwnerPipeUnexpectedGrant");
    }

    internal static (uint Pid,uint Session) ReadServerPeer(SafePipeHandle pipe)
    {
        if(!GetNamedPipeServerProcessId(pipe,out var pid) || !GetNamedPipeServerSessionId(pipe,out var session))throw Error("ReadCreatorOwnerPipePeer");
        return(pid,session);
    }

    public void Dispose(){assignment.Dispose();pipe.Dispose();}
    private static Win32Exception Error(string stage)=>new(Marshal.GetLastWin32Error(),stage);
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafePipeHandle OpenPipe(string name,int access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll",EntryPoint="OpenJobObjectW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafeJobHandle OpenJobObject(int access,[MarshalAs(UnmanagedType.Bool)]bool inherit,string name);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint pid);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetNamedPipeServerSessionId(SafePipeHandle pipe,out uint session);
    [DllImport("advapi32.dll",ExactSpelling=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool IsTokenRestricted(SafeAccessTokenHandle token);
    [DllImport("kernel32.dll",ExactSpelling=true)] private static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
}
