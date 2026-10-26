using System.Reflection;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record RemovalRule(string Presence,string Identity,string Content,string Action);
internal static class RemovalPolicy
{
    private static readonly (int Maximum,IReadOnlyList<RemovalRule> Files,IReadOnlyList<RemovalRule> Directories) Policy=Load();
    internal static int MaximumVersions=>Policy.Maximum;
    private static (int,IReadOnlyList<RemovalRule>,IReadOnlyList<RemovalRule>) Load()
    {
        using var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("ProtectionLifecycle.RemovalProtocol.json")??throw new InvalidDataException("Removal policy missing");
        using var doc=JsonDocument.Parse(stream);var root=doc.RootElement;
        StrictJson.Fields(root,"SchemaVersion","DefaultAction","RecursiveDelete","PreserveUserConfig","PreserveEvidence","MaximumVersions","Files","Directories");
        var maximum=root.GetProperty("MaximumVersions").GetInt32();
        if(root.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(root,"DefaultAction")!="REFUSE" || root.GetProperty("RecursiveDelete").GetBoolean() ||
            !root.GetProperty("PreserveUserConfig").GetBoolean() || !root.GetProperty("PreserveEvidence").GetBoolean() || maximum is <1 or >512)
            throw new InvalidDataException("Unsafe removal policy");
        IReadOnlyList<RemovalRule> Read(string name)
        {
            var rules=new List<RemovalRule>();var seen=new HashSet<(string,string,string)>();
            foreach(var entry in root.GetProperty(name).EnumerateArray())
            {
                StrictJson.Fields(entry,"Presence","Identity","Content","Action");
                var rule=new RemovalRule(StrictJson.Text(entry,"Presence"),StrictJson.Text(entry,"Identity"),StrictJson.Text(entry,"Content"),StrictJson.Text(entry,"Action"));
                var delete=rule.Action=="DELETE" && rule.Presence=="present" && rule.Identity=="same" && rule.Content==(name=="Files"?"same":"empty");
                var skip=rule.Action=="SKIP" && rule.Presence=="absent" && rule.Identity=="not-applicable" && rule.Content=="not-applicable";
                if(!delete && !skip)throw new InvalidDataException("Unreviewed removal authorization");
                if(!seen.Add((rule.Presence,rule.Identity,rule.Content)))throw new InvalidDataException("Ambiguous removal rule");rules.Add(rule);
            }
            return rules.AsReadOnly();
        }
        return (maximum,Read("Files"),Read("Directories"));
    }
    internal static void DemandFile(bool identitySame,bool contentSame)
    {Demand(Policy.Files,"present",identitySame?"same":"changed",contentSame?"same":"changed");}
    internal static void DemandDirectory(bool identitySame,bool empty)
    {Demand(Policy.Directories,"present",identitySame?"same":"changed",empty?"empty":"not-empty");}
    private static void Demand(IReadOnlyList<RemovalRule> rules,string presence,string identity,string content)
    {
        if(rules.SingleOrDefault(r=>r.Presence==presence && r.Identity==identity && r.Content==content)?.Action!="DELETE")
            throw new InvalidDataException("Exact removal policy refused this observation");
    }
}
