using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Security;

namespace ProtectionLifecycle;

internal sealed partial class SessionProxy
{
    internal static byte[] FixedClientConnectHeader(string sessionId,string secret)
    {
        _=Identifiers.Hex32(sessionId);_=Identifiers.Hash(secret);
        var identity=Encoding.ASCII.GetBytes(sessionId+":"+secret);string encoded;
        try{encoded=Convert.ToBase64String(identity);}finally{CryptographicOperations.ZeroMemory(identity);}
        return Encoding.ASCII.GetBytes("CONNECT "+Target+":443 HTTP/1.1\r\nHost: "+Target+":443\r\nProxy-Authorization: Basic "+encoded+"\r\n\r\n");
    }
    internal static void RequireFixedClientConnectReply(string reply)
    {
        if(reply!="HTTP/1.1 200 Connection Established\r\n\r\n")throw WfpNative.Contract("FixedSessionGatewayConnectRefused");
    }
    internal static void InitializeFixedClientSockets()
    {
        // Run the same lazy initializer used by SocketPal.CreateSocket, once,
        // before the creation phase. Do not alter its cache or native counters.
        var assembly=typeof(Socket).Assembly;
        if(!Environment.Is64BitProcess || assembly.ManifestModule.ModuleVersionId!=Guid.Parse("8e3d46e4-f844-481c-ae6d-d2130aa6965d"))
            throw new PlatformNotSupportedException("FixedSocketRuntimeNotQualified");
        var type=assembly.GetType("Interop+Winsock",false);
        var method=type?.GetMethod("EnsureInitialized",System.Reflection.BindingFlags.Static|System.Reflection.BindingFlags.NonPublic,
            null,Type.EmptyTypes,null);
        if(method is null || method.DeclaringType!=type || method.ReturnType!=typeof(void) || method.ContainsGenericParameters)
            throw WfpNative.Contract("FixedSocketInitializerLayoutDiffers");
        try{method.Invoke(null,null);}
        catch(System.Reflection.TargetInvocationException error)when(error.InnerException is not null)
        {System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error.InnerException).Throw();throw;}
    }
    // Same single WSASocketW call and flags as the pinned SocketPal. Capture
    // thread context before constructing an exception or querying the handle.
    // LastNtStatus is supporting context, NOT the proven return of NtCreateFile.
    internal sealed class FixedSocketCreationException : SocketException
    {
        internal int LastNtStatus { get; }
        internal FixedSocketCreationException(int socketError,int lastNtStatus):base(socketError)
        {LastNtStatus=lastNtStatus;}
    }
    [DllImport("ws2_32.dll",ExactSpelling=true,SetLastError=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr WSASocketW(int family,int type,int protocol,IntPtr protocolInfo,uint group,uint flags);
    [DllImport("ntdll.dll",ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int RtlGetLastNtStatus();
    internal static Socket CreateFixedClientSocket()
    {
        // Resolve this P/Invoke before creation so first-call resolution cannot
        // replace the context being sampled. Initialization is still explicit.
        _=RtlGetLastNtStatus();
        var handle=new SafeSocketHandle();
        try
        {
            var raw=WSASocketW(2,1,6,IntPtr.Zero,0,0x81);
            var error=Marshal.GetLastPInvokeError();
            var status=RtlGetLastNtStatus();
            Marshal.InitHandle(handle,raw);
            if(handle.IsInvalid)throw new FixedSocketCreationException(error,status);
            var socket=new Socket(handle);
            try
            {
                if(socket.AddressFamily!=AddressFamily.InterNetwork || socket.SocketType!=SocketType.Stream ||
                    socket.ProtocolType!=ProtocolType.Tcp || !socket.Blocking || socket.IsBound || socket.Connected)
                    throw WfpNative.Contract("FixedSocketAdoptionDiffers");
                return socket;
            }
            catch{socket.Dispose();throw;}
        }
        catch{handle.Dispose();throw;}
    }
    internal static async ValueTask<Stream> OpenFixedClientTunnel(string sessionId,string secret,CancellationToken cancel,Action<string>? phase)
    {
        var header=FixedClientConnectHeader(sessionId,secret);
        Socket? socket=null;
        try
        {
            phase?.Invoke("HTTPS_SOCKET_INITIALIZATION");InitializeFixedClientSockets();
            phase?.Invoke("HTTPS_SOCKET_CREATE");socket=CreateFixedClientSocket();
            phase?.Invoke("HTTPS_CONNECT");await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback,Port),cancel);
            var stream=new NetworkStream(socket,ownsSocket:true);
            phase?.Invoke("HTTPS_CONNECT_WRITE");
            try{await stream.WriteAsync(header,cancel);}finally{CryptographicOperations.ZeroMemory(header);}
            phase?.Invoke("HTTPS_CONNECT_REPLY");RequireFixedClientConnectReply(await ReadHeader(stream,cancel));return stream;
        }
        catch{socket?.Dispose();throw;}
        finally{CryptographicOperations.ZeroMemory(header);}
    }
    // Do not let chain-building or revocation silently start host DNS/HTTP.
    // Missing intermediates/revocation data therefore fail; this is not NoCheck.
    internal static SslClientAuthenticationOptions OfflineTls()=>new() {
        AllowTlsResume=false,AllowRenegotiation=false,
        CertificateRevocationCheckMode=X509RevocationMode.Offline,
        CertificateChainPolicy=new X509ChainPolicy { DisableCertificateDownloads=true,
            RevocationMode=X509RevocationMode.Offline,VerificationFlags=X509VerificationFlags.NoFlag }
    };
}
