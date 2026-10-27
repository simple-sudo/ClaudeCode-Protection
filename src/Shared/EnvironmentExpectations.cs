using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace ClaudeCodeProtection.Security;

// User intent, not observed evidence or a launch credential. The Broker reads
// these bytes ONLY from its protected state. No current value becomes a default
// target, and no PASS/status/waiver is accepted in this format.
internal sealed class EnvironmentExpectations
{
    internal string SHA256 { get; }
    internal string NetworkPolicySHA256 { get; }
    internal string OwnerSid { get; }
    internal string TimeZoneId { get; }
    internal string UserLocale { get; }
    internal string SystemLocale { get; }
    private EnvironmentExpectations(string hash,string network,string sid,string zone,string user,string system)
    {SHA256=hash;NetworkPolicySHA256=network;OwnerSid=sid;TimeZoneId=zone;UserLocale=user;SystemLocale=system;}
    internal static EnvironmentExpectations Parse(ReadOnlyMemory<byte> bytes,string installationId,string networkPolicySHA256)
    {
        var intent=ReadForMaintenance(bytes,installationId);
        if(!Hex(networkPolicySHA256,64,true) || intent.NetworkPolicySHA256!=networkPolicySHA256)
            throw new InvalidDataException("EnvironmentIntentNotForCurrentNetworkPolicy");
        return intent;
    }
    // Old intent remains inspectable/replaceable by its human owner after a
    // network-policy upgrade. This reader is never used by launch collection.
    internal static EnvironmentExpectations ReadForMaintenance(ReadOnlyMemory<byte> bytes,string installationId)
    {
        if(bytes.Length is <1 or >4096)throw new InvalidDataException("BoundedEnvironmentIntentRequired");
        using var document=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=2});
        var root=document.RootElement;
        var expected=new[]{"SchemaVersion","InstallationId","NetworkPolicySHA256","OwnerSid","TimeZoneId","UserLocale","SystemLocale"};
        var fields=root.EnumerateObject().Select(item=>item.Name).ToArray();
        if(fields.Length!=expected.Length || fields.Distinct(StringComparer.Ordinal).Count()!=expected.Length ||
            expected.Any(name=>!fields.Contains(name,StringComparer.Ordinal)) || root.GetProperty("SchemaVersion").GetInt32()!=1 ||
            !Hex(installationId,32,false) || !Hex(Text(root,"NetworkPolicySHA256"),64,true) || Text(root,"InstallationId")!=installationId)
            throw new InvalidDataException("EnvironmentIntentSchemaOrBindingRefused");
        var sid=Text(root,"OwnerSid");var parts=sid.Split('-');
        if(parts.Length!=8 || parts[0]!="S" || parts[1]!="1" ||
            !(parts[2]=="5" && parts[3]=="21" || parts[2]=="12" && parts[3]=="1") ||
            parts.Skip(4).Any(part=>!uint.TryParse(part,NumberStyles.None,CultureInfo.InvariantCulture,out var value) ||
                part!=value.ToString(CultureInfo.InvariantCulture)))throw new InvalidDataException("ExplicitHumanOwnerSidRequired");
        var zone=Text(root,"TimeZoneId");
        if(zone.Length is <1 or >128 || zone.Any(ch=>!char.IsAsciiLetterOrDigit(ch) && ch is not (' ' or '-' or '+' or '(' or ')' or '_' or '.')))
            throw new InvalidDataException("ExplicitWindowsTimeZoneRequired");
        var user=Locale(Text(root,"UserLocale"));var system=Locale(Text(root,"SystemLocale"));
        return new(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes.Span)),Text(root,"NetworkPolicySHA256"),sid,zone,user,system);
    }
    private static string Text(JsonElement value,string name)=>value.GetProperty(name).GetString()??throw new InvalidDataException("MissingEnvironmentIntentText");
    private static string Locale(string name)
    {
        if(name.Length is <2 or >85 || name.Any(ch=>!char.IsAsciiLetterOrDigit(ch) && ch!='-') ||
            CultureInfo.GetCultureInfo(name).Name!=name)throw new InvalidDataException("CanonicalLocaleRequired");
        return name;
    }
    private static bool Hex(string value,int length,bool upper)=>value.Length==length &&
        value.All(ch=>ch is >= '0' and <= '9' || (upper?ch is >= 'A' and <= 'F':ch is >= 'a' and <= 'f'));
}
