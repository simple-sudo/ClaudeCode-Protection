using System.Diagnostics;

namespace ProtectionLifecycle;

internal enum UpstreamTunnelStep
{
    AdmissionBeforeTunnel, AddressPolicy, AdmissionBeforeConnect, ProxyBeforeConnect, AddressBeforeConnect,
    FreshnessBeforeConnect, LoopbackConnect, PeerBeforeRequest, AdmissionBeforeRequest, AddressBeforeRequest,
    FreshnessBeforeRequest, ConnectWrite, ConnectReply, PeerAfterReply, AdmissionAfterReply, AddressAfterReply,
    FreshnessAfterReply, TunnelReady
}

internal sealed record UpstreamTunnelEvidence(string Step,int? ConnectStatus,int MinimumTtlSeconds,int ResponseAgeSeconds,
    long ElapsedMs,bool TunnelReady);

// Held only by the original owner for the fixed qualification connection.
// The receipt contains no endpoint, response text, credential, or permission.
internal sealed class UpstreamTunnelAttempt(int minimumTtlSeconds,int responseAgeSeconds,long requestStarted)
{
    private int? status;
    internal UpstreamTunnelStep Step {get;set;}=UpstreamTunnelStep.AdmissionBeforeTunnel;

    internal void RecordStatus(int? value)=>status=value;

    internal UpstreamTunnelEvidence Capture()=>new(Step.ToString(),status,minimumTtlSeconds,responseAgeSeconds,
        (long)Stopwatch.GetElapsedTime(requestStarted).TotalMilliseconds,Step==UpstreamTunnelStep.TunnelReady);

    // Preserve the original exact HTTP/1.x 200 rule. Numeric rejection codes
    // are useful to the owner, while the peer's status text stays private.
    internal static int? ParseConnectStatus(string reply)
    {
        var end=reply.IndexOf("\r\n",StringComparison.Ordinal);
        if(end<0)return null;
        var line=reply.AsSpan(0,end);
        if(!line.StartsWith("HTTP/1.1 ",StringComparison.Ordinal) && !line.StartsWith("HTTP/1.0 ",StringComparison.Ordinal))
            return null;
        var status=line[9..];
        if(status.Length<3 || status.Length>3 && status[3]!=' ' ||
            status[0] is <'1' or >'5' || !char.IsAsciiDigit(status[1]) || !char.IsAsciiDigit(status[2]))
            return null;
        return (status[0]-'0')*100+(status[1]-'0')*10+status[2]-'0';
    }
}
