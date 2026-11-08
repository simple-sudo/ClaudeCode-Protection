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
    internal SessionZeroCreatorChannel.Request Request {get;}
    internal SafeJobHandle Assignment=>assignment;

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
            var request=SessionZeroCreatorChannel.ParseRequest(frame,jobId,peer.Pid,peer.Session);
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
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        pipe.WriteAsync(frame.AsMemory(),deadline.Token).AsTask().GetAwaiter().GetResult();
    }

    internal static SecurityIdentifier VerifyCurrentService(string name)
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
        var service=(SecurityIdentifier)new NTAccount("NT SERVICE",name).Translate(typeof(SecurityIdentifier));
        var groups=RestrictingSidToken.ReadGroups(token,2);
        AssertCreatorGroups(groups,RestrictingSidToken.ReadGroups(token,11),service.Value);
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
}
