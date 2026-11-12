namespace ProtectionLifecycle;

using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

internal sealed record OwnedJobIntent(int SchemaVersion,string InstallationId,string JobId,string Release,string ManifestSHA256,string Binding,string Scope,
    [property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)] string? CreatorServiceSid=null)
{
    private const string AtomicBinding="ATOMIC_JOB_LIST_REQUIRED",PrivateScope="JOB_MEMBERS_ONLY",CreatorScope="SESSION_ZERO_CREATOR_JOB_MEMBERS_ONLY";
    internal static string Leaf(string id)=>"job-intent-"+Identifiers.Hex32(id)+".json";
    internal string Alias=>"CPCJob."+Identifiers.Hex32(InstallationId)+"."+Identifiers.Hex32(JobId);
    internal string Name=>CreatorServiceSid is null?Alias+"\\Session":CreatorJobName(InstallationId,JobId);
    internal static string CreatorJobName(string installationId,string jobId)=>@"Global\CPCSessionJob."+Identifiers.Hex32(installationId)+"."+Identifiers.Hex32(jobId);
    internal CreationTag Tag=>CreationTag.For(CreationRole.OwnedJob,JobId);
    internal static OwnedJobIntent ForNewJob(string installationId,string release,string manifest,string? creatorServiceSid)
    {
        if(creatorServiceSid is not null)AssertCreatorSid(creatorServiceSid);
        return new(creatorServiceSid is null?2:3,installationId,Guid.NewGuid().ToString("N"),release,manifest,AtomicBinding,
            creatorServiceSid is null?PrivateScope:CreatorScope,creatorServiceSid);
    }
    internal static OwnedJobIntent Read(ProtectedState state,string id)
    {
        state.AssertHeld();id=Identifiers.Hex32(id);using var doc=JsonDocument.Parse(state.Read(Leaf(id),8192).Bytes,new JsonDocumentOptions{MaxDepth=4});
        return Parse(doc.RootElement,state.InstallationId,id);
    }
    internal static OwnedJobIntent Parse(JsonElement r,string installationId,string id)
    {
        var schema=r.GetProperty("SchemaVersion").GetInt32();
        string[] fields=["SchemaVersion","InstallationId","JobId","Release","ManifestSHA256","Binding","Scope"];
        if(schema is not (2 or 3))throw new InvalidDataException("Unsupported job intent schema");
        StrictJson.Fields(r,schema==3?[..fields,"CreatorServiceSid"]:fields);
        var scope=schema==3?CreatorScope:PrivateScope;
        if(StrictJson.Text(r,"InstallationId")!=installationId || StrictJson.Text(r,"JobId")!=id ||
            StrictJson.Text(r,"Binding")!=AtomicBinding || StrictJson.Text(r,"Scope")!=scope)throw new InvalidDataException("Foreign job intent or unsupported binding");
        var creator=schema==3?StrictJson.Text(r,"CreatorServiceSid"):null;
        if(creator is not null)AssertCreatorSid(creator);
        return new(schema,installationId,id,Identifiers.Hex32(StrictJson.Text(r,"Release")),Identifiers.Hash(StrictJson.Text(r,"ManifestSHA256")),AtomicBinding,scope,creator);
    }
    internal static void AssertCreatorSid(string sid)
    {
        // Service-specific SID only. Reject the shared LocalService and the
        // all-services group, as well as our own synthetic creation tag space.
        var segments=sid.Split('-');
        if(!sid.StartsWith("S-1-5-80-",StringComparison.Ordinal) || segments.Length!=9 ||
            !segments.Skip(4).All(s=>uint.TryParse(s,System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out var value) &&
                s==value.ToString(System.Globalization.CultureInfo.InvariantCulture)) || CreationTag.TryParse(sid) is not null)
            throw new InvalidDataException("Exact creator service SID required");
    }
    internal static IReadOnlyList<OwnedJobIntent> ReadAll(ProtectedState state)
    {
        var leaves=state.ListLeaves("job-intent-");if(leaves.Length>1024)throw new InvalidDataException("Job inventory capacity exceeded; no subset adopted");
        var result=new List<OwnedJobIntent>();
        foreach(var leaf in leaves)
        {
            if(leaf.Length!=48)throw new InvalidDataException("Unexpected job intent name");
            var id=Identifiers.Hex32(leaf.Substring(11,32));if(leaf!=Leaf(id))throw new InvalidDataException("Job intent name differs");
            result.Add(Read(state,id));
        }
        return result.AsReadOnly();
    }
}
