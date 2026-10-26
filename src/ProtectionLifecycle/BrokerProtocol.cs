using System.Reflection;
using System.Text.Json;

namespace ProtectionLifecycle;

// Data-only, fixed operations. No commands, scripts, paths, provider/filter GUIDs,
// SIDs, process IDs, URLs, endpoint overrides or activation supplied by a caller.
// The installed fixed quarantine command supplies concrete WFP/Job owners.
// General broker transport authentication and lifecycle adapters remain absent.
internal sealed class BrokerRequest
{
    internal string InstallationId { get; }
    internal string Id { get; }
    internal string Operation { get; }
    internal string? Target { get; }
    private readonly byte[] frozen;
    private BrokerRequest(string installationId,string id,string operation,string? target,byte[] frozen)
    {InstallationId=installationId;Id=id;Operation=operation;Target=target;this.frozen=frozen;}
    internal static BrokerRequest Parse(ReadOnlyMemory<byte> raw)
    {
        if(raw.Length is <1 or >2048) throw new InvalidDataException("Broker request size refused");
        var frozen=raw.ToArray();
        using var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("ProtectionLifecycle.BrokerProtocol.json")
            ??throw new InvalidDataException("Embedded broker protocol missing");
        using var policy=JsonDocument.Parse(stream,new JsonDocumentOptions{MaxDepth=6});
        var specification=policy.RootElement;
        StrictJson.Fields(specification,"SchemaVersion","MaximumBytes","Fields","Operations");
        if(specification.GetProperty("SchemaVersion").GetInt32()!=1 || specification.GetProperty("MaximumBytes").GetInt32()!=2048)
            throw new InvalidDataException("Unexpected broker protocol");
        var fields=specification.GetProperty("Fields").EnumerateArray().Select(f=>f.GetString()??throw new InvalidDataException()).ToArray();
        if(!fields.SequenceEqual(new[]{"SchemaVersion","InstallationId","RequestId","Operation","Target"}))
            throw new InvalidDataException("Broker field surface changed");
        using var doc=JsonDocument.Parse(frozen,new JsonDocumentOptions{MaxDepth=4});
        var root=doc.RootElement;StrictJson.Fields(root,fields);
        if(root.GetProperty("SchemaVersion").GetInt32()!=1) throw new InvalidDataException("Request schema refused");
        var installationId=Identifiers.Hex32(StrictJson.Text(root,"InstallationId"));
        var id=Identifiers.Hex32(StrictJson.Text(root,"RequestId"));
        var operation=StrictJson.Text(root,"Operation");
        var matching=new List<string>();
        foreach(var rule in specification.GetProperty("Operations").EnumerateArray())
        {
            StrictJson.Fields(rule,"Name","Target");
            if(StrictJson.Text(rule,"Name")==operation) matching.Add(StrictJson.Text(rule,"Target"));
        }
        if(matching.Count!=1) throw new InvalidDataException("Unknown/ambiguous broker operation");
        string? target=null;
        if(matching[0]=="none")
        {if(root.GetProperty("Target").ValueKind!=JsonValueKind.Null) throw new InvalidDataException("Operation accepts no target");}
        else if(matching[0] is "operation-id" or "staged-release-id" or "owned-release-id") target=Identifiers.Hex32(StrictJson.Text(root,"Target"));
        else throw new InvalidDataException("Unreviewed target type");
        return new(installationId,id,operation,target,frozen);
    }
    internal string BindOnce(ProtectedState state)
    {
        state.AssertHeld();
        if(state.InstallationId!=InstallationId) throw new InvalidDataException("Request belongs to another installation");
        // CREATE_NEW is the replay barrier; missing-read/access-error is never
        // interpreted as permission to overwrite an old request.
        return state.WriteNew("request-"+Id+".json",frozen);
    }
}
