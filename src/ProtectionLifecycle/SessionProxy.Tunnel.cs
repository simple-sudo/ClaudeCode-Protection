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
}
