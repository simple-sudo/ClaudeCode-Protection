using System.Text.Json;
using System.Net;
using System.Net.Sockets;

namespace ClaudeCodeProtection.Security;

// Non-networking policy consumed by the owned SessionProxy execution path.
// The caller must independently own DNS, bind the selected literal IP at the
// transport layer and deny every alternative route to the original proxy.
// No security claim follows from merely calling this class.
internal static class ProxyDestinationPolicy
{
    internal sealed record PinnedDecision(bool Allowed,string Reason);

    // The CONNECT authority alone cannot constrain a proxy's TLS sniffing.
    // This validates the complete initial handshake, not a TLS certificate or
    // the upstream's routing behavior. No encrypted-name fallback is accepted.
    internal static void ValidateTlsClientHello(string expectedHost,ReadOnlySpan<byte> message)
    {
        if(!IsPublicHostnameCandidate(expectedHost) || IPAddress.TryParse(expectedHost,out _) || message.Length is <4 or >32768 ||
            message[0]!=1 || ((message[1]<<16)|(message[2]<<8)|message[3])!=message.Length-4)
            throw new InvalidDataException("BoundedClientHelloRequired");
        var body=new HelloReader(message[4..]);
        if(body.U16()!=0x0303)throw new InvalidDataException("ModernTlsClientHelloRequired");
        _=body.Take(32);var session=body.U8();if(session>32)throw new InvalidDataException("TlsSessionIdCapacity");_=body.Take(session);
        var cipherBytes=body.U16();if(cipherBytes<2 || cipherBytes%2!=0)throw new InvalidDataException("TlsCipherVectorInvalid");_=body.Take(cipherBytes);
        if(body.U8()!=1 || body.U8()!=0)throw new InvalidDataException("TlsCompressionRefused");
        var extensionBytes=body.U16();if(extensionBytes!=body.Remaining)throw new InvalidDataException("TlsExtensionVectorInvalid");
        var seen=new HashSet<int>();var serverName=false;
        while(body.Remaining>0)
        {
            var type=body.U16();var size=body.U16();var extension=new HelloReader(body.Take(size));
            if(!seen.Add(type))throw new InvalidDataException("DuplicateTlsExtension");
            if(type is 65037 or 64768 or 65486)throw new InvalidDataException("EncryptedTlsNameUnsupported");
            if(type==0)
            {
                if(extension.U16()!=extension.Remaining || extension.U8()!=0)throw new InvalidDataException("TlsServerNameVectorInvalid");
                var length=extension.U16();var name=extension.Take(length);
                if(length is <1 or >253 || extension.Remaining!=0)throw new InvalidDataException("OneTlsServerNameRequired");
                for(var i=0;i<name.Length;i++)if(name[i] is <33 or >126)throw new InvalidDataException("AsciiTlsServerNameRequired");
                if(!System.Text.Encoding.ASCII.GetString(name).Equals(expectedHost,StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("TlsNameDiffersFromAuthorizedTarget");
                serverName=true;
            }
            if(type==16)
            {
                if(extension.U16()!=extension.Remaining || extension.Remaining==0)throw new InvalidDataException("TlsAlpnVectorInvalid");
                var protocols=new HashSet<string>(StringComparer.Ordinal);
                while(extension.Remaining>0)
                {
                    var protocol=System.Text.Encoding.ASCII.GetString(extension.Take(extension.U8()));
                    if(protocol is not ("http/1.1" or "h2") || !protocols.Add(protocol))throw new InvalidDataException("HttpsAlpnRequired");
                }
            }
        }
        if(!serverName)throw new InvalidDataException("VisibleAuthorizedTlsNameRequired");
    }
    private ref struct HelloReader
    {
        private ReadOnlySpan<byte> bytes;
        internal HelloReader(ReadOnlySpan<byte> bytes){this.bytes=bytes;}
        internal int Remaining=>bytes.Length;
        internal ReadOnlySpan<byte> Take(int count)
        {
            if(count<0 || count>bytes.Length)throw new InvalidDataException("TlsVectorTruncated");
            var result=bytes[..count];bytes=bytes[count..];return result;
        }
        internal int U8()=>Take(1)[0];
        internal int U16(){var value=Take(2);return (value[0]<<8)|value[1];}
    }

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
        if(address is null)return false;
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
           address.ScopeId!=0 || address.IsIPv6Teredo || (b[0]&0xe0)!=0x20 ||
           // transition & documentation ranges are not suitable as remote gateway targets
           (b[0]==0x20 && b[1]==0x01 && b[2]==0x0d && b[3]==0xb8) ||
           (b[0]==0x20 && b[1]==0x01 && b[2]<2) || // special-purpose 2001::/23
           (b[0]==0x20 && b[1]==0x02) ||
           (b[0]==0x3f && b[1]==0xff && (b[2]&0xf0)==0)) // documentation 3fff::/20
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
        // A literal destination cannot borrow a different public name's DNS
        // answer to authorize another endpoint.
        if(IPAddress.TryParse(host,out var literal) &&
            (!literal.Equals(chosen) || resolved.Any(address=>!literal.Equals(address))))
            return new(false,"LITERAL_DESTINATION_ADDRESS_MISMATCH");
        // DNS addresses may be duplicated in legitimate responses. Duplicates
        // do not weaken the selected endpoint invariant.
        return new(true,"CANDIDATE_REQUIRES_TRUSTED_LITERAL_IP_TUNNEL");
    }

    private static bool IsAsciiAlnum(char c)=>
        c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9';
    internal sealed record ConnectRequest(string Host, string Authorization);
    internal static ConnectRequest ParseConnect(string header)
    {
        if(header.Length is <16 or >8192 || !header.EndsWith("\r\n\r\n",StringComparison.Ordinal))
            throw new InvalidDataException("BoundedCompleteConnectHeaderRequired");
        var lines = header.Split("\r\n", StringSplitOptions.None);
        if(lines.Take(lines.Length-2).Any(line=>line.Length==0 || line.Any(ch=>ch<32 || ch>126)))
            throw new InvalidDataException("NonCanonicalConnectHeader");
        var request = lines[0].Split(' ');
        if (request.Length != 3 || request[0] != "CONNECT" || request[2] != "HTTP/1.1" ||
            !request[1].EndsWith(":443", StringComparison.Ordinal)) throw new InvalidDataException("HttpsConnectRequired");
        var host = request[1][..^4];
        if (!ProxyDestinationPolicy.IsPublicHostnameCandidate(host) || host != host.ToLowerInvariant())
            throw new InvalidDataException("CanonicalPublicDestinationRequired");
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1).Where(line => line.Length != 0))
        {
            var colon = line.IndexOf(':');
            if (colon < 1 || !fields.TryAdd(line[..colon], line[(colon + 1)..].Trim()) || fields.Count > 8)
                throw new InvalidDataException("AmbiguousConnectHeaders");
        }
        if (!fields.TryGetValue("Host", out var authority) || authority != request[1] ||
            fields.Keys.Any(key => !new[] { "Host", "Proxy-Authorization", "User-Agent", "Proxy-Connection" }.Contains(key, StringComparer.OrdinalIgnoreCase)) ||
            fields.TryGetValue("Proxy-Connection", out var connection) && !connection.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("ConnectAuthorityOrHeadersRefused");
        return new(host, fields.GetValueOrDefault("Proxy-Authorization", ""));
    }
    internal static IPAddress[] ParseResolution(string host, byte[] bytes)
    {
        if (bytes.Length is < 1 or > 65536) throw new InvalidDataException("ResolverResponseCapacity");
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement; Unique(root);
        if (root.GetProperty("Status").GetInt32() != 0 || root.GetProperty("TC").GetBoolean())
            throw new InvalidDataException("ResolverResponseFailedOrTruncated");
        var questions = root.GetProperty("Question").EnumerateArray().ToArray();
        if (questions.Length != 1) throw new InvalidDataException("ResolverQuestionCount");
        Unique(questions[0]);
        if (DnsName(questions[0].GetProperty("name").GetString()) != host || questions[0].GetProperty("type").GetInt32() != 1)
            throw new InvalidDataException("ResolverQuestionMismatch");
        var answers = root.GetProperty("Answer").EnumerateArray().ToArray();
        if (answers.Length is < 1 or > 24) throw new InvalidDataException("ResolverAnswerCapacity");
        var aliases = new Dictionary<string, string>(StringComparer.Ordinal);
        var addresses = new List<(string Name, IPAddress Address)>();
        foreach (var answer in answers)
        {
            Unique(answer);
            var name = DnsName(answer.GetProperty("name").GetString());
            if (answer.GetProperty("TTL").GetInt64() < 1) throw new InvalidDataException("ResolverExpiredAnswer");
            var type = answer.GetProperty("type").GetInt32();
            var data = answer.GetProperty("data").GetString();
            if (type == 5) { if (!aliases.TryAdd(name, DnsName(data))) throw new InvalidDataException("DuplicateAlias"); }
            else if (type == 1 && IPAddress.TryParse(data, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork &&
                ProxyDestinationPolicy.IsPublicAddressCandidate(ip)) addresses.Add((name, ip));
            else throw new InvalidDataException("PrivateSpecialOrUnsupportedResolverAnswer");
        }
        var terminal = host; var visited = new HashSet<string>(StringComparer.Ordinal);
        while (aliases.TryGetValue(terminal, out var next))
        { if (!visited.Add(terminal) || visited.Count > 8) throw new InvalidDataException("ResolverAliasLoop"); terminal = next; }
        if (aliases.Keys.Any(name => !visited.Contains(name)) || addresses.Count is < 1 or > 16 || addresses.Any(item => item.Name != terminal))
            throw new InvalidDataException("UnrelatedResolverAnswer");
        return addresses.Select(item => item.Address).Distinct().ToArray();
    }
    private static string DnsName(string? input)
    {
        var name = input?.ToLowerInvariant();
        if (name?.EndsWith(".", StringComparison.Ordinal) == true) name = name[..^1];
        if (!ProxyDestinationPolicy.IsPublicHostnameCandidate(name)) throw new InvalidDataException("ResolverNameRefused");
        return name!;
    }
    private static void Unique(JsonElement value)
    {
        var names = value.EnumerateObject().Select(item => item.Name).ToArray();
        if (names.Distinct(StringComparer.Ordinal).Count() != names.Length) throw new InvalidDataException("DuplicateResolverField");
    }
}
