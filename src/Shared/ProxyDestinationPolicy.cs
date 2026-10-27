using System.Net;
using System.Net.Sockets;

namespace ClaudeCodeProtection.Security;

// Reusable, non-networking input policy for a FUTURE trusted forwarding path.
// The caller must independently own DNS, bind the selected literal IP at the
// transport layer and deny every alternative route to the original proxy.
// No security claim follows from merely calling this class.
internal static class ProxyDestinationPolicy
{
    internal sealed record PinnedDecision(bool Allowed,string Reason);

    internal static bool IsPublicHostnameCandidate(string? input)
    {
        if(string.IsNullOrEmpty(input) || input.Length>253 ||
           input.EndsWith(".",StringComparison.Ordinal) ||
           input.Any(c=>c>127 || char.IsWhiteSpace(c) || char.IsControl(c) || c=='%' || c=='/' || c=='\\'))
            return false;
        if(IPAddress.TryParse(input,out var literal))
            return IsPublicAddressCandidate(literal);
        var labels=input.Split('.');
        if(labels.Length<2 || labels.Any(label=>label.Length is <1 or >63 ||
            !IsAsciiAlnum(label[0]) || !IsAsciiAlnum(label[^1]) ||
            label.Any(ch=>!IsAsciiAlnum(ch) && ch!='-')))
            return false;
        if(!labels[^1].Any(char.IsLetter))return false; // disallow shortened / numeric IP encodings
        var domain=input.ToLowerInvariant();
        foreach(var suffix in new[]{"localhost","local","lan","home","internal","localdomain",
            "corp","private","invalid","test","example","onion","arpa"})
            if(domain==suffix || domain.EndsWith("."+suffix,StringComparison.Ordinal))
                return false;
        return !domain.StartsWith("wpad.",StringComparison.Ordinal) &&
               !domain.StartsWith("isatap.",StringComparison.Ordinal);
    }

    // A public *candidate* is not evidence of reachability or address
    // provenance; a gateway must bind a chosen address and recheck it.
    internal static bool IsPublicAddressCandidate(IPAddress address)
    {
        if(address.IsIPv4MappedToIPv6)return false; // force canonical IPv4 literals
        var b=address.GetAddressBytes();
        if(address.AddressFamily==AddressFamily.InterNetwork)
        {
            var a=b[0];var second=b[1];var third=b[2];
            return !(a==0 || a==10 || a==127 || a>=224 ||
                (a==100 && second>=64 && second<=127) ||
                (a==169 && second==254) ||
                (a==172 && second>=16 && second<=31) ||
                (a==192 && second==0 && third==0) ||
                (a==192 && second==0 && third==2) ||
                (a==192 && second==88 && third==99) ||
                (a==192 && second==168) ||
                (a==198 && (second==18 || second==19)) ||
                (a==198 && second==51 && third==100) ||
                (a==203 && second==0 && third==113));
        }
        if(address.AddressFamily!=AddressFamily.InterNetworkV6 ||
           address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast ||
           address.IsIPv6Teredo || (b[0]&0xe0)!=0x20 ||
           // transition & documentation ranges are not suitable as remote gateway targets
           (b[0]==0x20 && b[1]==0x01 && b[2]==0x0d && b[3]==0xb8) ||
           (b[0]==0x20 && b[1]==0x01 && b[2]==0x00 && b[3]==0x00) ||
           (b[0]==0x20 && b[1]==0x02) ||
           (b[0]==0x20 && b[1]==0x01 && b[2]>=0x20 && b[2]<=0x2f))
            return false;
        return true;
    }

    // Intended for a trusted forwarder using its OWN verified resolution
    // results. DNS is considered untrusted input even when the queried name
    // looks harmless. The forwarder must connect ONLY to the pinned literal
    // address, preserving the hostname for HTTPS certificate validation.
    internal static PinnedDecision AuthorizePinnedHttps(string? host,int port,
        IReadOnlyList<IPAddress>? resolved,IPAddress? chosen)
    {
        if(port!=443 || !IsPublicHostnameCandidate(host))
            return new(false,"DESTINATION_NAME_OR_PORT_REFUSED");
        if(resolved is null || resolved.Count is <1 or >16 || chosen is null)
            return new(false,"RESOLUTION_MISSING_OR_UNBOUNDED");
        if(resolved.Any(address=>!IsPublicAddressCandidate(address)))
            return new(false,"PRIVATE_OR_SPECIAL_RESOLUTION_REFUSED");
        if(!IsPublicAddressCandidate(chosen) || !resolved.Contains(chosen))
            return new(false,"CHOSEN_ADDRESS_NOT_IN_VERIFIED_RESOLUTION");
        // DNS addresses may be duplicated in legitimate responses. Duplicates
        // do not weaken the selected endpoint invariant.
        return new(true,"CANDIDATE_REQUIRES_TRUSTED_LITERAL_IP_TUNNEL");
    }

    private static bool IsAsciiAlnum(char c)=>
        c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9';
}
