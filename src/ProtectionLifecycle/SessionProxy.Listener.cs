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
}
