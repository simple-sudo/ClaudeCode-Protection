using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record LocalManagementAttempt(string Role,string Phase,int? Code,byte[] Received)
{
    internal bool ExplicitDenial=>Phase=="CONNECT" && Code==(int)SocketError.AccessDenied;
    internal object Summary()=>new {Role,Phase,Code,ReceivedBytes=Received.Length,
        SHA256=Received.Length==0?null:Convert.ToHexString(SHA256.HashData(Received))};
}

internal sealed record LocalManagementBoundaryReport(int SchemaVersion,string SessionId,int Pid,string Phase,int ExitCode,
    int? SetupError,LocalManagementAttempt[] Attempts)
{
    internal const int MaximumCharacters=16384;
    internal bool BoundaryObserved=>Attempts is [
        {Role:"OWNED_GATEWAY",Phase:"ACKNOWLEDGED"}, {Role:"RAW_PROXY",ExplicitDenial:true},
        {Role:"CONTROLLER",ExplicitDenial:true}
    ];
    internal static LocalManagementBoundaryReport Parse(string raw,string session,uint pid,uint exit)
    {
        if(raw.Length is <2 or >MaximumCharacters)throw WfpNative.Contract("LocalManagementFeedbackBounds");
        using var doc=JsonDocument.Parse(raw,new JsonDocumentOptions{MaxDepth=6});
        var root=doc.RootElement;
        StrictJson.Fields(root,"SchemaVersion","SessionId","Pid","Phase","ExitCode","SetupError","Attempts");
        var attempts=root.GetProperty("Attempts");
        if(attempts.ValueKind!=JsonValueKind.Array || attempts.GetArrayLength() is not (0 or 3))
            throw WfpNative.Contract("LocalManagementFeedbackShape");
        foreach(var attempt in attempts.EnumerateArray())StrictJson.Fields(attempt,"Role","Phase","Code","Received");
        var report=JsonSerializer.Deserialize<LocalManagementBoundaryReport>(raw)??throw WfpNative.Contract("LocalManagementFeedbackMissing");
        if(report.SchemaVersion!=1 || report.SessionId!=Identifiers.Hex32(session) || pid==0 || report.Pid!=pid ||
            report.ExitCode!=exit || exit is not (42 or 125) || report.Attempts is null ||
            report.BoundaryObserved!=(exit==42))
            throw WfpNative.Contract("LocalManagementFeedbackIdentity");
        if(report.Attempts.Length==0)
        {
            if(report.Phase is not ("ENVIRONMENT" or "IDENTITY" or "SOCKET_INITIALIZATION") || report.SetupError is null)
                throw WfpNative.Contract("LocalManagementSetupFeedbackShape");
        }
        else
        {
            if(report.Phase!="LOCAL_BOUNDARY" || report.SetupError is not null)
                throw WfpNative.Contract("LocalManagementAttemptFeedbackShape");
            for(int i=0;i<3;i++)
            {
                var item=report.Attempts[i];
                var expected=i switch{0=>"OWNED_GATEWAY",1=>"RAW_PROXY",_=>"CONTROLLER"};
                if(item is null || item.Role!=expected || item.Received is null || item.Received.Length>LocalManagementBoundary.MaxResponseBytes ||
                    (i!=2 && item.Received.Length!=0) || !ValidPhase(item,i))
                    throw WfpNative.Contract("LocalManagementAttemptFeedbackShape");
            }
        }
        return report;
    }
    private static bool ValidPhase(LocalManagementAttempt item,int index)=>item.Phase switch {
        "ACKNOWLEDGED"=>index==0 && item.Code is null,
        "ACK_FAILED"=>index==0 && item.Code is not null,
        "SOCKET" or "CONNECT"=>index!=0 && item.Code is not null && item.Received.Length==0,
        "CONNECTED"=>index==1 && item.Code is null,
        "READ_COMPLETE"=>index==2 && item.Code is null && item.Received.Length<LocalManagementBoundary.MaxResponseBytes,
        "READ_LIMIT"=>index==2 && item.Code is null && item.Received.Length==LocalManagementBoundary.MaxResponseBytes,
        "READ_FAILURE"=>index==2 && item.Code is not null,
        _=>false
    };
    internal static async Task<string> ReadBounded(StreamReader reader)
    {
        var buffer=new char[MaximumCharacters+1];
        try
        {
            var used=await reader.ReadBlockAsync(buffer.AsMemory()).ConfigureAwait(false);
            if(used>MaximumCharacters)throw WfpNative.Contract("LocalManagementFeedbackBounds");
            return new string(buffer,0,used);
        }
        finally{Array.Clear(buffer);}
    }
}

// Fixed IPv4 loopback only. The raw proxy receives no request. The local
// controller sees one read-only GET only if the restricted connection works.
internal static class LocalManagementBoundary
{
    internal const int ControllerPort=9090,MaxResponseBytes=8192;
    internal const string WorkerCommand="local-management-boundary-child";
    private static readonly byte[] ControllerRequest=
        "GET /configs HTTP/1.1\r\nHost: 127.0.0.1:9090\r\nConnection: close\r\n\r\n"u8.ToArray();

    internal static async Task<LocalManagementBoundaryReport> RunWorker(string session,string secret)
    {
        SessionProxy.InitializeFixedClientSockets();
        LocalManagementAttempt gateway;
        using(var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(2)))
        {
            try
            {
                using var stream=await SessionProxy.OpenFixedClientTunnel(session,secret,deadline.Token,null).ConfigureAwait(false);
                gateway=new("OWNED_GATEWAY","ACKNOWLEDGED",null,[]);
            }
            catch(Exception error)when(error is not OutOfMemoryException)
            {gateway=new("OWNED_GATEWAY","ACK_FAILED",Code(error),[]);}
        }
        var raw=await ObserveRestricted("RAW_PROXY",CompiledFencePolicy.ProxyPort).ConfigureAwait(false);
        var controller=await ObserveRestricted("CONTROLLER",ControllerPort).ConfigureAwait(false);
        var report=new LocalManagementBoundaryReport(1,session,Environment.ProcessId,"LOCAL_BOUNDARY",125,null,[gateway,raw,controller]);
        return report.BoundaryObserved?report with {ExitCode=42}:report;
    }

    private static async Task<LocalManagementAttempt> ObserveRestricted(string role,int port)
    {
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var phase="SOCKET";
        try
        {
            using var socket=SessionProxy.CreateFixedClientSocket();
            phase="CONNECT";
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback,port),deadline.Token).ConfigureAwait(false);
            return port==ControllerPort?await ReadController(socket,deadline.Token).ConfigureAwait(false):
                new(role,"CONNECTED",null,[]);
        }
        catch(Exception error)when(error is not OutOfMemoryException){return new(role,phase,Code(error),[]);}
    }

    internal static async Task<byte[]> CaptureTrustedController(ProxyChannelLease proxy)
    {
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(2));
        using var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp);
        await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback,ControllerPort),deadline.Token).ConfigureAwait(false);
        proxy.AssertControllerPeer(socket);
        var observed=await ReadController(socket,deadline.Token).ConfigureAwait(false);
        proxy.AssertControllerListener();
        if(observed.Phase!="READ_COMPLETE" || !TrustedResponseObserved(observed.Received))
            throw WfpNative.Contract("LocalControllerTrustedReferenceNotConfirmed");
        return observed.Received;
    }

    internal static bool TrustedResponseObserved(ReadOnlySpan<byte> bytes)
    {
        if(!bytes.StartsWith("HTTP/1.1 200 "u8) && !bytes.StartsWith("HTTP/1.0 200 "u8))return false;
        var end=bytes.IndexOf("\r\n\r\n"u8);
        return end>=12 && bytes.Length>end+4;
    }

    private static async Task<LocalManagementAttempt> ReadController(Socket socket,CancellationToken cancel)
    {
        var buffer=new byte[MaxResponseBytes];var used=0;
        try
        {
            using var stream=new NetworkStream(socket,ownsSocket:false);
            await stream.WriteAsync(ControllerRequest,cancel).ConfigureAwait(false);
            while(used<buffer.Length)
            {
                var count=await stream.ReadAsync(buffer.AsMemory(used),cancel).ConfigureAwait(false);
                if(count==0)return new("CONTROLLER","READ_COMPLETE",null,buffer[..used]);
                used+=count;
            }
            return new("CONTROLLER","READ_LIMIT",null,buffer.ToArray());
        }
        catch(Exception error)when(error is not OutOfMemoryException)
        {return new("CONTROLLER","READ_FAILURE",Code(error),buffer[..used]);}
        finally{CryptographicOperations.ZeroMemory(buffer);}
    }

    private static int Code(Exception error)=>error is SocketException socket?socket.NativeErrorCode:error.HResult;
}
