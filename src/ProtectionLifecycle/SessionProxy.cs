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

internal sealed record ReviewedProxyRouteEvidence(int ActiveControllerHealthChecks,int ResolverBeforeConnect,int ResolverAfterReply,
    int TargetBeforeConnect,int TargetAfterReply)
{
    internal bool FixedExchangeCovered=>ActiveControllerHealthChecks>0 && ResolverBeforeConnect==1 && ResolverAfterReply==1 &&
        TargetBeforeConnect==1 && TargetAfterReply==1;
}

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
    private readonly LpacCapabilityProfile capabilityProfile;
    private readonly bool fixedNoContentHttpsCanary;
    private readonly bool localManagementBoundary;
    private readonly bool requireFreshProxyRoute;
    private readonly FixedResolverTrust? fixedResolverTrust;
    private ResolverTlsEvidence? resolverTlsEvidence;
    private UpstreamTunnelEvidence? upstreamTunnelEvidence;
    private int activeControllerHealthChecks,resolverBeforeConnect,resolverAfterReply,targetBeforeConnect,targetAfterReply;
    internal ResolverTlsEvidence? ResolverTls=>Volatile.Read(ref resolverTlsEvidence);
    internal UpstreamTunnelEvidence? TargetTunnel=>Volatile.Read(ref upstreamTunnelEvidence);
    internal ReviewedProxyRouteEvidence? ReviewedRouteEvidence=>requireFreshProxyRoute
        ?new(Volatile.Read(ref activeControllerHealthChecks),Volatile.Read(ref resolverBeforeConnect),Volatile.Read(ref resolverAfterReply),
            Volatile.Read(ref targetBeforeConnect),Volatile.Read(ref targetAfterReply)):null;
    // The retained base hash identifies the existing compiled endpoint/WFP
    // policy. Bind the candidate identity separately, rather than pretending
    // an internetClient token is the historical zero-capability identity.
    internal string EffectivePolicySHA256 {get;}
    private readonly byte[] authorization;
    private readonly Task accept;
    private readonly TaskCompletionSource<(uint Pid,long CreatedFileTime)> fixedExchange=new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<(uint Pid,long CreatedFileTime)> localAcknowledged=new(TaskCreationOptions.RunContinuationsAsynchronously);
    private sealed record GatewayFailure(Exception Cause,string Phase);
    private GatewayFailure? failure;
    internal GatewayFailureFeedback? FailureFeedback
    {
        get{var f=Volatile.Read(ref failure);return f is null?null:new(f.Phase,GatewayChildReport.Describe(f.Cause));}
    }
    private ProtectedSession.Admission? admission;
    private int fixedRootTunnelConsumed;
    private int sequence;
    private long transferred;
    private volatile bool disposed;
    internal string Secret { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    internal string SessionId => sessionId;
    internal SessionProxy(OwnedKernelJob job, ProxyChannelLease upstream, string packageSid, string sessionId,
        LpacCapabilityProfile? capabilities=null,bool fixedNoContentHttpsCanary=false,FixedResolverTrust? fixedResolverTrust=null,
        bool localManagementBoundary=false,bool requireFreshProxyRoute=true)
    {
        capabilityProfile=capabilities??LpacCapabilityProfile.None;
        if(fixedNoContentHttpsCanary && !capabilityProfile.IsInternetClientQualification)throw WfpNative.Contract("NoContentHttpsGatewayRequiresFixedInternetClient");
        if(fixedResolverTrust is not null && !fixedNoContentHttpsCanary)throw WfpNative.Contract("ResolverTlsTrustRequiresFixedHead");
        if(localManagementBoundary && (!capabilityProfile.IsInternetClientQualification || fixedNoContentHttpsCanary))
            throw WfpNative.Contract("LocalManagementGatewayPlanDiffers");
        this.fixedNoContentHttpsCanary=fixedNoContentHttpsCanary;
        this.localManagementBoundary=localManagementBoundary;
        this.requireFreshProxyRoute=requireFreshProxyRoute;
        this.fixedResolverTrust=fixedResolverTrust;
        var effective="CPC-GATEWAY-EFFECTIVE-V3;"+PolicySHA256+";"+capabilityProfile.SHA256+
            ";resolver-freshness=authenticated-request-stream;fixed-no-content-https-canary="+fixedNoContentHttpsCanary;
        if(fixedResolverTrust is not null)effective+=";fixed-openssl-head-resolver-explicit-offline-revocation;request=HEAD "+
            FixedOpenSslHead.RequestPath+";client="+FixedOpenSslHead.UserAgent;
        if(localManagementBoundary)effective+=";fixed-local-management-boundary;relay=never";
        if(requireFreshProxyRoute)effective+=";controller-listener-required;controller-route-readback-before-connect-and-after-reply";
        EffectivePolicySHA256=Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(effective)));
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
        if(requireFreshProxyRoute)upstream.AssertControllerListener();
        else upstream.AssertHealthy();
        destinations.AssertCurrent();
    }
    internal void AssertRuntimeHealthy(bool active)
    {
        AssertHealthy();
        if(active && requireFreshProxyRoute)Interlocked.Increment(ref activeControllerHealthChecks);
    }
    internal void BindAdmission(ProtectedSession.Admission permit)
    {
        if(!ReferenceEquals(permit.Gateway,this) || !ReferenceEquals(permit.CapabilityProfile,capabilityProfile) || permit.FixedNoContentHttpsCanary!=fixedNoContentHttpsCanary ||
            permit.UsesFixedOpenSslHead!=(fixedResolverTrust is not null) ||
            permit.IsLocalManagementBoundary!=localManagementBoundary || permit.RequiresReviewedProxyRoute!=requireFreshProxyRoute ||
            capabilityProfile.IsInternetClientQualification && !permit.IsFixedGatewayQualification)throw WfpNative.Contract("GatewayAdmissionOwnerOrCapabilitiesMismatch");
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
    internal bool FixedExchangeObserved(uint pid,long createdFileTime)
        =>fixedExchange.Task.IsCompletedSuccessfully && fixedExchange.Task.Result==(pid,createdFileTime);
    internal void RequireLocalAcknowledgement(uint pid,long createdFileTime)
    {
        if(!localManagementBoundary ||
            localAcknowledged.Task.WaitAsync(TimeSpan.FromMilliseconds(500)).GetAwaiter().GetResult()!=(pid,createdFileTime))
            throw WfpNative.Contract("LocalGatewayAcknowledgementOwnerDiffers");
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
                if(stop.IsCancellationRequested){client.Dispose();return;}
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
                using var process = AtomicChild.HoldSessionPeer(job, packageSid, peer.Port,capabilityProfile);
                AssertHealthy();AssertForwardingCurrent();
                AtomicChild.AssertSessionPeer(job, process, packageSid, peer.Port,capabilityProfile);
                var permit=Volatile.Read(ref admission)??throw WfpNative.Contract("GatewayAdmissionMissing");
                (uint Pid,long CreatedFileTime)? fixedPeer=null;
                if(permit.IsFixedGatewayQualification)
                {
                    var identity=AtomicChild.SessionPeerIdentity(process);
                    permit.AssertFixedGatewayRoot(identity);
                    ConsumeFixedTunnelAttempt(ref fixedRootTunnelConsumed);
                    fixedPeer=identity;
                }
                AssertForwardingCurrent();
                await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"), deadline.Token);
                if(localManagementBoundary)
                {
                    if(fixedPeer is not { } localPeer || !localAcknowledged.TrySetResult(localPeer))
                        throw WfpNative.Contract("LocalGatewayAcknowledgementOwnerMissing");
                    return;
                }
                phase="CLIENT_TLS";
                using var tlsClient=await SessionTunnel.RequireTlsClientHelloAsync(stream,request.Host,AssertForwardingCurrent,deadline.Token);
                AssertHealthy();AtomicChild.AssertSessionPeer(job,process,packageSid,peer.Port,capabilityProfile);AssertForwardingCurrent();
                phase="RESOLVER";
                var (resolution,responseAge,requestStarted)=await Resolve(request.Host,deadline.Token);
                void AssertFreshResolution()=>resolution.RequireFresh(responseAge,Stopwatch.GetElapsedTime(requestStarted));
                var addresses=resolution.Addresses;var chosen=addresses[0];
                if(!ProxyDestinationPolicy.AuthorizePinnedHttps(request.Host,443,addresses,chosen).Allowed)
                    throw new InvalidDataException("SessionResolvedDestinationRefused");
                using var remote=await OpenTargetTunnel();
                async Task<NetworkStream> OpenTargetTunnel()
                {
                    // The target consumes the authenticated resolver result.
                    // Observe the exact gate without giving it recovery authority.
                    var attempt=fixedResolverTrust is null?null:
                        new UpstreamTunnelAttempt(resolution.MinimumTtlSeconds,(int)responseAge.TotalSeconds,requestStarted);
                    phase="UPSTREAM";
                    try
                    {
                        AssertForwardingCurrent();
                        return await OpenTunnel(chosen,deadline.Token,AssertFreshResolution,attempt);
                    }
                    finally
                    {
                        if(attempt is not null)Volatile.Write(ref upstreamTunnelEvidence,attempt.Capture());
                    }
                }
                // Close the literal upstream socket on revoke/deadline as
                // well as passing the token to pending stream I/O.
                using var closeUpstream=deadline.Token.UnsafeRegister(static stream=>((NetworkStream)stream!).Dispose(),remote);
                AssertHealthy();AtomicChild.AssertSessionPeer(job,process,packageSid,peer.Port,capabilityProfile);AssertForwardingCurrent();
                Action<bool>? observeWrite=null;
                if(fixedPeer is { } identityForReceipt)
                {
                    var completedDirections=0;
                    observeWrite=towardUpstream=>
                    {
                        var bit=towardUpstream?1:2;
                        if((Interlocked.Or(ref completedDirections,bit)|bit)==3)fixedExchange.TrySetResult(identityForReceipt);
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
    private async Task<(ProxyDestinationPolicy.Resolution Resolution,TimeSpan ResponseAge,long RequestStarted)> Resolve(string host, CancellationToken token)
    {
        var resolverTunnelConsumed=0;
        var tls=OfflineTls();
        using var modules=fixedResolverTrust?.OpenModules();
        if(fixedResolverTrust is { } trust && modules is not null)tls.RemoteCertificateValidationCallback=(sender,certificate,chain,errors)=>
        {
            var observation=ResolverTlsEvidence.Observe((sender as SslStream)?.TargetHostName,certificate,chain,errors) with {Accepted=false};
            try
            {
                token.ThrowIfCancellationRequested();
                var accepted=trust.Verify(modules,observation,certificate,chain);
                if(accepted)AssertForwardingCurrent();
                observation=observation with {Accepted=accepted};
            }
            finally
            {
                if(Interlocked.CompareExchange(ref resolverTlsEvidence,observation,null) is not null)
                    throw WfpNative.Contract("FixedResolverValidationAlreadyObserved");
            }
            return observation.Accepted;
        };
        using var message = new HttpRequestMessage(HttpMethod.Get, "https://"+ResolverTlsEvidence.Host+"/dns-query?name=" + Uri.EscapeDataString(host) + "&type=A") {
            Version=HttpVersion.Version11,VersionPolicy=HttpVersionPolicy.RequestVersionExact
        };
        var timing=new ResolverRequestTiming(message);
        using var handler = new SocketsHttpHandler {
            UseProxy = false, AllowAutoRedirect = false, UseCookies = false, Credentials = null,
            MaxConnectionsPerServer = 1, MaxResponseHeadersLength = 8,
            SslOptions = tls,
            PlaintextStreamFilter=timing.OnAuthenticatedStream,
            ConnectCallback = async (context, cancel) => {
                if (context.DnsEndPoint.Host != ResolverTlsEvidence.Host || context.DnsEndPoint.Port != 443)
                    throw new InvalidDataException("UnapprovedResolverTransport");
                ConsumeFixedTunnelAttempt(ref resolverTunnelConsumed);
                return await OpenTunnel(IPAddress.Parse("1.1.1.1"),cancel,resolver:true);
            }
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5), MaxResponseContentBufferSize = 65536 };
        message.Headers.Accept.ParseAdd("application/dns-json");
        message.Headers.CacheControl=new System.Net.Http.Headers.CacheControlHeaderValue{NoCache=true};
        using var response = await client.SendAsync(message, token);
        if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentType?.MediaType != "application/dns-json")
            throw new InvalidDataException("TrustedResolverResponseRefused");
        var responseAge=TimeSpan.Zero;
        if(response.Headers.NonValidated.TryGetValues("Age",out var ages))
        {
            if(ages.Count!=1 || !int.TryParse(ages.First(),System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,out var seconds))throw new InvalidDataException("ResolverResponseAgeRefused");
            responseAge=TimeSpan.FromSeconds(seconds);
        }
        return (ProxyDestinationPolicy.ParseResolution(host,await response.Content.ReadAsByteArrayAsync(token)),responseAge,timing.StartedAt);
    }
    internal static void ConsumeFixedTunnelAttempt(ref int consumed)
    {
        if(Interlocked.Exchange(ref consumed,1)!=0)throw WfpNative.Contract("FixedGatewayTunnelAttemptAlreadyConsumed");
    }
    private async Task<NetworkStream> OpenTunnel(IPAddress ip,CancellationToken token,Action? assertFreshResolution=null,
        UpstreamTunnelAttempt? attempt=null,bool resolver=false)
    {
        if(localManagementBoundary)throw WfpNative.Contract("LocalGatewayCannotRelay");
        void Step(UpstreamTunnelStep next){if(attempt is not null)attempt.Step=next;}
        Step(UpstreamTunnelStep.AddressPolicy);
        if (ip.AddressFamily != AddressFamily.InterNetwork || !ProxyDestinationPolicy.IsPublicAddressCandidate(ip))
            throw new InvalidDataException("PublicIPv4TunnelRequired");
        Step(UpstreamTunnelStep.AdmissionBeforeConnect);
        AssertForwardingCurrent();
        Step(UpstreamTunnelStep.ProxyBeforeConnect);
        upstream.AssertHealthy();
        Step(UpstreamTunnelStep.AddressBeforeConnect);
        destinations.RequireRemotePublicAddress(ip);
        Step(UpstreamTunnelStep.FreshnessBeforeConnect);
        assertFreshResolution?.Invoke();
        Step(UpstreamTunnelStep.LoopbackConnect);
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, CompiledFencePolicy.ProxyPort), token);
            Step(UpstreamTunnelStep.PeerBeforeRequest);
            await AssertTunnelPeerAndRoute(socket,token,"UpstreamRouteBeforeConnectRefused");
            if(requireFreshProxyRoute)
            {
                if(resolver)Interlocked.Increment(ref resolverBeforeConnect);
                else Interlocked.Increment(ref targetBeforeConnect);
            }
            Step(UpstreamTunnelStep.AdmissionBeforeRequest);
            AssertForwardingCurrent();
            var stream = new NetworkStream(socket, ownsSocket: true);
            Step(UpstreamTunnelStep.AddressBeforeRequest);
            destinations.RequireRemotePublicAddress(ip);
            var authority = ip + ":443";
            Step(UpstreamTunnelStep.FreshnessBeforeRequest);
            assertFreshResolution?.Invoke();
            Step(UpstreamTunnelStep.ConnectWrite);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n"), token);
            Step(UpstreamTunnelStep.ConnectReply);
            var reply = await ReadHeader(stream, token);
            var status=UpstreamTunnelAttempt.ParseConnectStatus(reply);
            attempt?.RecordStatus(status);
            if(status!=200)throw new InvalidDataException("UpstreamLiteralConnectRefused");
            Step(UpstreamTunnelStep.PeerAfterReply);
            await AssertTunnelPeerAndRoute(socket,token,"UpstreamRouteAfterConnectRefused");
            if(requireFreshProxyRoute)
            {
                if(resolver)Interlocked.Increment(ref resolverAfterReply);
                else Interlocked.Increment(ref targetAfterReply);
            }
            Step(UpstreamTunnelStep.AdmissionAfterReply);
            AssertForwardingCurrent();
            Step(UpstreamTunnelStep.AddressAfterReply);
            destinations.RequireRemotePublicAddress(ip);
            Step(UpstreamTunnelStep.FreshnessAfterReply);
            assertFreshResolution?.Invoke();
            Step(UpstreamTunnelStep.TunnelReady);
            return stream;
        }
        catch { socket.Dispose(); throw; }
    }

    private async Task AssertTunnelPeerAndRoute(Socket socket,CancellationToken token,string routeFailure)
    {
        upstream.AssertConnectedPeer(socket);
        if(!requireFreshProxyRoute)return;
        var route=await ProxyRouteObservation.Capture(upstream,token);
        route.RequireAllowed(routeFailure);
        upstream.AssertConnectedPeer(socket);
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
