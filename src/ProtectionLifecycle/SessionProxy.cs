using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Security;

namespace ProtectionLifecycle;

// Owned by ProtectedSession, never a machine proxy or an independently usable
// launch service. The initial compiled policy authorizes one synthetic target.
internal sealed class SessionProxy : IDisposable
{
    internal const int Port = 17891;
    internal const string Target = "www.microsoft.com";
    internal static readonly string PolicySHA256 = Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(
        "CPC-SESSION-NET3;host-target=refuse-current-unicast-v4-v6+bounded-private-snapshot+drift-fail-closed;listen=127.0.0.1:17891;upstream=127.0.0.1:7890+held-reverse-established-tuple;connect=www.microsoft.com:443;doh=1.1.1.1:443/cloudflare-dns.com;A-only;ipv6=deny;no-direct-fallback;tls=offline-no-download;auth=per-session+held-job-peer+AC-low-zero;max-connections=4;accepted=32;max-bytes=8MiB-per-direction+64MiB-total;connection-seconds=20;session-seconds=60;half-close=send-fin+drain-peer;fault=cancel+drain-both;forward=bound-admission+runtime-health-2s+per-write;client-hello=visible-matching-SNI+http-ALPN;hello=32KiB+8records;no-ECH")));
    private readonly TcpListener listener = new(IPAddress.Loopback, Port);
    private readonly CancellationTokenSource stop = new(TimeSpan.FromSeconds(60));
    private readonly ConcurrentDictionary<int, (TcpClient Client, Task Work)> clients = new();
    private readonly OwnedKernelJob job;
    private readonly ProxyChannelLease upstream;
    private readonly GatewayDestinationGuard destinations;
    private readonly string packageSid, sessionId;
    private readonly byte[] authorization;
    private readonly Task accept;
    private readonly TaskCompletionSource<(uint Pid,long CreatedFileTime)> fixedExchange=new(TaskCreationOptions.RunContinuationsAsynchronously);
    private sealed record GatewayFailure(Exception Cause,string Phase);
    private GatewayFailure? failure;
    internal GatewayFailureFeedback? FailureFeedback
    {
        get{var f=Volatile.Read(ref failure);return f is null?null:new(f.Phase,GatewayChildReport.Describe(f.Cause));}
    }
    private ProtectedSession.Admission? admission;
    private int sequence;
    private long transferred;
    private volatile bool disposed;
    internal string Secret { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    internal string SessionId => sessionId;
    internal SessionProxy(OwnedKernelJob job, ProxyChannelLease upstream, string packageSid, string sessionId)
    {
        this.job = job; this.upstream = upstream; this.packageSid = packageSid; this.sessionId = Identifiers.Hex32(sessionId);
        authorization = Encoding.ASCII.GetBytes("Basic " + Convert.ToBase64String(Encoding.ASCII.GetBytes(sessionId + ":" + Secret)));
        listener.Server.ExclusiveAddressUse = true;
        try { destinations=GatewayDestinationGuard.CaptureCurrent();upstream.AssertHealthy(); listener.Start(8); accept = Accept(); }
        catch { CryptographicOperations.ZeroMemory(authorization);listener.Stop(); stop.Dispose(); throw; }
    }
    internal void AssertHealthy()
    {
        if (disposed || stop.IsCancellationRequested || failure is not null || accept.IsCompleted || clients.Values.Any(entry=>entry.Work.IsFaulted))
            throw WfpNative.Contract("SessionGatewayStoppedExpiredOrFailed");
        if(ProxyChannelLease.SessionListenerOwner()!=unchecked((uint)Environment.ProcessId))throw WfpNative.Contract("SessionGatewayListenerOwnerDrift");
        upstream.AssertHealthy();destinations.AssertCurrent();
    }
    internal void BindAdmission(ProtectedSession.Admission permit)
    {
        if(!ReferenceEquals(permit.Gateway,this))throw WfpNative.Contract("GatewayAdmissionOwnerMismatch");
        permit.AssertCurrent();
        if(Interlocked.CompareExchange(ref admission,permit,null) is not null)throw WfpNative.Contract("GatewayAdmissionAlreadyBound");
    }
    internal void AssertReadyToOpen()
    {
        AssertHealthy();
        (Volatile.Read(ref admission)??throw WfpNative.Contract("GatewayAdmissionMissing")).AssertGatewayOpening();
    }
    internal void RequireFixedExchange(uint pid,long createdFileTime)
    {
        // The child can receive the final write before the gateway continuation
        // records it. Wait briefly for that observation without another request.
        var peer=fixedExchange.Task.WaitAsync(TimeSpan.FromMilliseconds(500)).GetAwaiter().GetResult();
        if(peer!=(pid,createdFileTime))throw WfpNative.Contract("FixedGatewayExchangeRootIdentityDiffers");
    }
    private void AssertForwardingCurrent()
    {
        (Volatile.Read(ref admission)??throw WfpNative.Contract("GatewayAdmissionMissing")).AssertForwardingCurrent();
        if(disposed || stop.IsCancellationRequested || failure is not null)throw WfpNative.Contract("GatewayForwardingStopped");
        destinations.AssertCurrent();
    }
    private async Task Accept()
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(stop.Token);
                foreach (var entry in clients.Where(entry => entry.Value.Work.IsCompleted).ToArray())
                {
                    if (entry.Value.Work.IsFaulted) { Fail(entry.Value.Work.Exception!); client.Dispose(); return; }
                    clients.TryRemove(entry.Key, out _);
                }
                if (clients.Count >= 4) { client.Dispose(); continue; }
                var id = Interlocked.Increment(ref sequence);
                if(id>32){client.Dispose();Fail(new InvalidDataException("SessionConnectionBudgetExceeded"));return;}
                // Store before starting: cleanup must see even a synchronously
                // rejected connection. Only the accept loop adds entries.
                clients[id] = (client, Task.CompletedTask);
                var work = Serve(client);
                clients[id] = (client, work);
            }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        { if (!stop.IsCancellationRequested) Fail(ex); }
    }
    private void Fail(Exception error,string phase="LISTENER")
    {
        Interlocked.CompareExchange(ref failure,new GatewayFailure(error,phase),null);
        stop.Cancel(); listener.Stop();
        foreach (var entry in clients.Values) entry.Client.Dispose();
    }
    private async Task Serve(TcpClient client)
    {
        using (client)
        using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(stop.Token))
        {
            deadline.CancelAfter(TimeSpan.FromSeconds(20));
            var authenticated = false;var phase="REQUEST";
            try
            {
                var stream = client.GetStream();
                var request = ProxyDestinationPolicy.ParseConnect(await ReadHeader(stream, deadline.Token));
                if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(request.Authorization), authorization))
                {
                    await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"CPC session\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), deadline.Token);
                    return;
                }
                authenticated = true;
                if (request.Host != Target) throw new InvalidDataException("SessionDestinationNotAuthorized");
                phase="PEER";
                if (client.Client.RemoteEndPoint is not IPEndPoint peer || !peer.Address.Equals(IPAddress.Loopback))
                    throw new InvalidDataException("SessionLoopbackPeerRequired");
                using var process = AtomicChild.HoldSessionPeer(job, packageSid, peer.Port);
                AssertHealthy();AssertForwardingCurrent();
                AtomicChild.AssertSessionPeer(job, process, packageSid, peer.Port);
                AssertForwardingCurrent();
                await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"), deadline.Token);
                phase="CLIENT_TLS";
                using var tlsClient=await SessionTunnel.RequireTlsClientHelloAsync(stream,request.Host,AssertForwardingCurrent,deadline.Token);
                AssertHealthy();AtomicChild.AssertSessionPeer(job,process,packageSid,peer.Port);AssertForwardingCurrent();
                phase="RESOLVER";
                var addresses=await Resolve(request.Host,deadline.Token);var chosen=addresses[0];
                if(!ProxyDestinationPolicy.AuthorizePinnedHttps(request.Host,443,addresses,chosen).Allowed)
                    throw new InvalidDataException("SessionResolvedDestinationRefused");
                // Resolve immediately before the literal CONNECT, after the
                // client's bounded handshake has passed. No invalid ClientHello
                // starts even a resolver tunnel on behalf of that connection.
                AssertForwardingCurrent();
                phase="UPSTREAM";
                using var remote=await OpenTunnel(chosen,deadline.Token);
                AssertHealthy();AtomicChild.AssertSessionPeer(job,process,packageSid,peer.Port);AssertForwardingCurrent();
                Action<bool>? observeWrite=null;
                if(Volatile.Read(ref admission)?.IsFixedGatewayQualification==true)
                {
                    var identity=AtomicChild.SessionPeerIdentity(process);
                    var completedDirections=0;
                    observeWrite=towardUpstream=>
                    {
                        var bit=towardUpstream?1:2;
                        if((Interlocked.Or(ref completedDirections,bit)|bit)==3)fixedExchange.TrySetResult(identity);
                    };
                }
                phase="FORWARDING";
                await SessionTunnel.CopyAsync(tlsClient,remote,
                    ()=>client.Client.Shutdown(SocketShutdown.Send),()=>remote.Socket.Shutdown(SocketShutdown.Send),
                    count=>{if(Interlocked.Add(ref transferred,count)>64*1024*1024)throw new InvalidDataException("SessionTunnelByteBudgetExceeded");},
                    8*1024*1024,AssertForwardingCurrent,deadline.Token,observeWrite);
            }
            catch (Exception ex)
            { if (authenticated && !stop.IsCancellationRequested) Fail(ex,phase); }
        }
    }
    private async Task<IPAddress[]> Resolve(string host, CancellationToken token)
    {
        using var handler = new SocketsHttpHandler {
            UseProxy = false, AllowAutoRedirect = false, UseCookies = false, Credentials = null,
            MaxConnectionsPerServer = 1, MaxResponseHeadersLength = 8,
            SslOptions = OfflineTls(),
            ConnectCallback = async (context, cancel) => {
                if (context.DnsEndPoint.Host != "cloudflare-dns.com" || context.DnsEndPoint.Port != 443)
                    throw new InvalidDataException("UnapprovedResolverTransport");
                return await OpenTunnel(IPAddress.Parse("1.1.1.1"), cancel);
            }
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5), MaxResponseContentBufferSize = 65536 };
        using var message = new HttpRequestMessage(HttpMethod.Get, "https://cloudflare-dns.com/dns-query?name=" + Uri.EscapeDataString(host) + "&type=A") {
            Version=HttpVersion.Version11,VersionPolicy=HttpVersionPolicy.RequestVersionExact
        };
        message.Headers.Accept.ParseAdd("application/dns-json");
        using var response = await client.SendAsync(message, token);
        if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentType?.MediaType != "application/dns-json")
            throw new InvalidDataException("TrustedResolverResponseRefused");
        return ProxyDestinationPolicy.ParseResolution(host, await response.Content.ReadAsByteArrayAsync(token));
    }
    private async Task<NetworkStream> OpenTunnel(IPAddress ip, CancellationToken token)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork || !ProxyDestinationPolicy.IsPublicAddressCandidate(ip))
            throw new InvalidDataException("PublicIPv4TunnelRequired");
        AssertForwardingCurrent();upstream.AssertHealthy();destinations.RequireRemotePublicAddress(ip);
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, CompiledFencePolicy.ProxyPort), token);
            upstream.AssertConnectedPeer(socket);AssertForwardingCurrent();
            var stream = new NetworkStream(socket, ownsSocket: true);
            destinations.RequireRemotePublicAddress(ip);
            var authority = ip + ":443";
            await stream.WriteAsync(Encoding.ASCII.GetBytes("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n"), token);
            var reply = await ReadHeader(stream, token);
            var status = reply.Split("\r\n", StringSplitOptions.None)[0].Split(' ');
            if (status.Length < 2 || status[0] is not ("HTTP/1.1" or "HTTP/1.0") || status[1] != "200")
                throw new InvalidDataException("UpstreamLiteralConnectRefused");
            upstream.AssertConnectedPeer(socket);AssertForwardingCurrent();destinations.RequireRemotePublicAddress(ip);return stream;
        }
        catch { socket.Dispose(); throw; }
    }
    internal static async Task<string> ReadHeader(Stream stream, CancellationToken token)
    {
        var bytes = new byte[8192]; var one = new byte[1]; var count = 0;
        while (count < bytes.Length)
        {
            if (await stream.ReadAsync(one, token) != 1) throw new InvalidDataException("IncompleteConnectHeader");
            var value = one[0];
            if (value > 126 || value < 32 && value is not (10 or 13)) throw new InvalidDataException("NonAsciiConnectHeader");
            if(value==10 && (count==0 || bytes[count-1]!=13) || count>0 && bytes[count-1]==13 && value!=10)
                throw new InvalidDataException("AmbiguousConnectLineEnding");
            bytes[count++] = value;
            if (count >= 4 && bytes[count - 4] == 13 && bytes[count - 3] == 10 && bytes[count - 2] == 13 && bytes[count - 1] == 10)
                return Encoding.ASCII.GetString(bytes, 0, count);
        }
        throw new InvalidDataException("ConnectHeaderCapacity");
    }
    // Fixed caller-side CONNECT; shares this gateway's target and bounded
    // header reader. No OS proxy discovery, credential negotiation or DNS.
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
    internal static async ValueTask<Stream> OpenFixedClientTunnel(string sessionId,string secret,CancellationToken cancel,Action<string>? phase)
    {
        var header=FixedClientConnectHeader(sessionId,secret);
        Socket? socket=null;
        try
        {
            phase?.Invoke("HTTPS_CONNECT");socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp);await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback,Port),cancel);
            var stream=new NetworkStream(socket,ownsSocket:true);
            try{await stream.WriteAsync(header,cancel);}finally{CryptographicOperations.ZeroMemory(header);}
            phase?.Invoke("HTTPS_CONNECT_REPLY");RequireFixedClientConnectReply(await ReadHeader(stream,cancel));return stream;
        }
        catch{socket?.Dispose();throw;}
        finally{CryptographicOperations.ZeroMemory(header);}
    }
    // Do not let chain-building or revocation silently start host DNS/HTTP.
    // Missing intermediates/revocation data therefore fail; this is not NoCheck.
    internal static SslClientAuthenticationOptions OfflineTls()=>new() {
        CertificateRevocationCheckMode=X509RevocationMode.Offline,
        CertificateChainPolicy=new X509ChainPolicy { DisableCertificateDownloads=true,
            RevocationMode=X509RevocationMode.Offline,VerificationFlags=X509VerificationFlags.NoFlag }
    };
    internal void Revoke()
    {
        stop.Cancel(); listener.Stop();
        foreach (var entry in clients.Values) entry.Client.Dispose();
    }
    public void Dispose()
    {
        if (disposed) return; disposed = true; Revoke();
        var drained = false;
        try
        {
            if (!accept.Wait(TimeSpan.FromSeconds(3))) throw new TimeoutException("GatewayAcceptDrainUnknown");
            var tasks = clients.Values.Select(entry => entry.Work).ToArray();
            drained = Task.WhenAll(tasks).Wait(TimeSpan.FromSeconds(3));
            if (!drained) throw new TimeoutException("GatewayTunnelDrainUnknown");
        }
        finally { if (drained) { CryptographicOperations.ZeroMemory(authorization); stop.Dispose(); } }
    }
}
