using System.Net;
using System.Net.Sockets;

namespace ClaudeProtection;

// Prevent this application's fixed diagnostic HTTP client from being turned
// into a proxy for arbitrary URLs or local/private-management endpoints.
// THIS IS NOT A FILTER FOR CLAUDE CHILD PROCESSES OR AN AUTHORIZED PROXY GATEWAY.
// A DNS name still requires enforcement against the address actually selected
// by the trusted forwarder; inspecting the URI cannot prevent DNS rebinding.
internal static class DiagnosticNetworkTargetPolicy
{
    private const string ExpectedProxy="http://127.0.0.1:7890/";

    internal static bool IsApprovedDiagnostic(string target,string proxy)
    {
        if(!Uri.TryCreate(proxy,UriKind.Absolute,out var via) ||
           !string.Equals(via.AbsoluteUri,ExpectedProxy,StringComparison.Ordinal) ||
           !Uri.TryCreate(target,UriKind.Absolute,out var destination) ||
           destination.Scheme!=Uri.UriSchemeHttps || destination.Port!=443 ||
           !string.IsNullOrEmpty(destination.UserInfo) ||
           !string.IsNullOrEmpty(destination.Query) ||
           !string.IsNullOrEmpty(destination.Fragment) ||
           DestinationRequiresRestriction(destination.Host))
            return false;

        return (destination.IdnHost=="api.anthropic.com" && destination.AbsolutePath=="/v1/models") ||
               (destination.IdnHost=="www.cloudflare.com" && destination.AbsolutePath=="/cdn-cgi/trace");
    }

    // Returns true for obviously local/nonpublic destinations, and for
    // ambiguous forms that a trusted proxy must not accept by default.
    // False does NOT prove that a DNS hostname resolves only to public IPs.
    internal static bool DestinationRequiresRestriction(string? rawHost)
    {
        if(string.IsNullOrWhiteSpace(rawHost) || rawHost.EndsWith('.',StringComparison.Ordinal) ||
            rawHost.Contains('%') || rawHost.Any(char.IsWhiteSpace))
            return true;
        var host=rawHost.Trim('[',']').ToLowerInvariant();
        if(IPAddress.TryParse(host,out var ip))
            return !IsPublicUnicastCandidate(ip);
        if(Uri.CheckHostName(host)!=UriHostNameType.Dns || !host.Contains('.'))
            return true;
        foreach(var forbidden in new[]{"localhost","local","lan","internal","home.arpa","localdomain",
                     "home","corp","private","invalid","test","example","onion"})
            if(host==forbidden || host.EndsWith("."+forbidden,StringComparison.Ordinal))
                return true;
        return host.StartsWith("wpad.",StringComparison.Ordinal) ||
               host.StartsWith("isatap.",StringComparison.Ordinal);
    }

    private static bool IsPublicUnicastCandidate(IPAddress input)
    {
        if(input.IsIPv4MappedToIPv6)return IsPublicUnicastCandidate(input.MapToIPv4());
        var bytes=input.GetAddressBytes();
        if(input.AddressFamily==AddressFamily.InterNetwork)
        {
            var a=bytes[0];var b=bytes[1];var c=bytes[2];
            return !(a==0 || a==10 || a==127 || a>=224 ||
                a==100 && b is >=64 and <=127 ||
                a==169 && b==254 ||
                a==172 && b is >=16 and <=31 ||
                a==192 && b==168 ||
                a==192 && b==0 && c==0 ||
                a==192 && b==0 && c==2 ||
                a==192 && b==88 && c==99 ||
                a==198 && b is 18 or 19 ||
                a==198 && b==51 && c==100 ||
                a==203 && b==0 && c==113);
        }
        if(input.AddressFamily!=AddressFamily.InterNetworkV6 ||
            input.IsIPv6LinkLocal || input.IsIPv6SiteLocal ||
            input.IsIPv6Multicast || input.IsIPv6Teredo ||
            (bytes[0]&0xe0)!=0x20 ||
            bytes[0]==0x20 && bytes[1]==0x01 && bytes[2]==0x0d && bytes[3]==0xb8)
            return false;
        return true;
    }
}
