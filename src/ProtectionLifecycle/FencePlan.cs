using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record FenceFilterKey(string Role,string Key);
internal sealed record FenceDocument(int SchemaVersion,string InstallationId,string FenceId,string Release,string ManifestSHA256,
    string PolicySHA256,int ProxyPort,string SubLayerKey,FenceFilterKey[] Filters,string Scope);

// The endpoint is a compiled policy, not a broker/CLI override. Its presence
// does not prove the proxy process, listener or transport is healthy/approved.
internal static class CompiledFencePolicy
{
    internal const int ProxyPort=7890;
    internal static readonly string SHA256=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
        Encoding.ASCII.GetBytes("CPC-FENCE1;ipv4=127.0.0.1;port=7890;protocol=6;ipv6=deny;initial=quarantine-both")));
    internal static readonly IReadOnlyList<string> Roles=Array.AsReadOnly(new[]{"ipv4-address","ipv4-port","ipv4-protocol","ipv6-deny","quarantine-v4","quarantine-v6"});
}
internal sealed class FencePlan
{
    internal FenceDocument Data { get; }
    internal string SHA256 { get; }
    internal Guid SubLayer { get; }
    private readonly Guid[] keys;
    private FencePlan(FenceDocument data,string hash,Guid subLayer,Guid[] keys){Data=data;SHA256=hash;SubLayer=subLayer;this.keys=keys;}
    internal Guid Key(int role)=>keys[role];
    internal static string Leaf(string id)=>"fence-intent-"+Identifiers.Hex32(id)+".json";
    internal string Name(int role)=>"CPC:"+Data.InstallationId+":"+Data.FenceId+":"+(role<0?"layer":CompiledFencePolicy.Roles[role]);
    internal static FencePlan ForObjectContractQualification()
    {
        var data=new FenceDocument(1,Guid.NewGuid().ToString("N"),Guid.NewGuid().ToString("N"),Guid.NewGuid().ToString("N"),new string('0',64),
            CompiledFencePolicy.SHA256,CompiledFencePolicy.ProxyPort,Guid.NewGuid().ToString("N"),
            CompiledFencePolicy.Roles.Select(r=>new FenceFilterKey(r,Guid.NewGuid().ToString("N"))).ToArray(),"QUALIFICATION_UNCOMMITTED_ONLY");
        return new(data,Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(data))),
            Guid.ParseExact(data.SubLayerKey,"N"),data.Filters.Select(f=>Guid.ParseExact(f.Key,"N")).ToArray());
    }
    internal byte[] Marker(int role)=>Encoding.ASCII.GetBytes("CPCF1").Concat(Convert.FromHexString(Data.InstallationId)).Concat(Convert.FromHexString(Data.FenceId))
        .Concat(Convert.FromHexString(SHA256)).Append(checked((byte)(role<0?255:role))).ToArray();
    internal static FencePlan Create(ProtectedState state,VerifiedVersion version)=>Create(state,version,false);
    internal static FencePlan CreateSession(ProtectedState state,VerifiedVersion version)=>Create(state,version,true);
    private static FencePlan Create(ProtectedState state,VerifiedVersion version,bool session)
    {
        state.AssertHeld();version.AssertHeld(state);LifecycleRecovery.AssertNoPending(state);
        var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
        if(current.Release!=version.Package.Release || current.ManifestSHA256!=version.Package.ManifestHash)throw new InvalidDataException("Fence version differs from verified current version");
        if(ReadAll(state).Count>=64)throw new InvalidDataException("Fence inventory full");
        var id=Guid.NewGuid().ToString("N");var data=new FenceDocument(1,state.InstallationId,id,version.Package.Release,version.Package.ManifestHash,
            session?SessionProxy.PolicySHA256:CompiledFencePolicy.SHA256,session?SessionProxy.Port:CompiledFencePolicy.ProxyPort,
            Guid.NewGuid().ToString("N"),CompiledFencePolicy.Roles.Select(r=>new FenceFilterKey(r,Guid.NewGuid().ToString("N"))).ToArray(),"INSTALLATION_PACKAGE_SID_ONLY");
        state.WriteNew(Leaf(id),JsonSerializer.SerializeToUtf8Bytes(data));return Read(state,id);
    }
    private static Guid ParseKey(string text)
    {if(!Guid.TryParseExact(text,"N",out var key) || key==Guid.Empty || text!=key.ToString("N"))throw new InvalidDataException("Invalid fence key");return key;}
    internal static FencePlan Read(ProtectedState state,string id)
    {
        state.AssertHeld();id=Identifiers.Hex32(id);var raw=state.Read(Leaf(id),16384);using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=5});var r=doc.RootElement;
        StrictJson.Fields(r,"SchemaVersion","InstallationId","FenceId","Release","ManifestSHA256","PolicySHA256","ProxyPort","SubLayerKey","Filters","Scope");
        if(r.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(r,"InstallationId")!=state.InstallationId || StrictJson.Text(r,"FenceId")!=id ||
            StrictJson.Text(r,"Scope")!="INSTALLATION_PACKAGE_SID_ONLY")throw new InvalidDataException("Foreign fence plan");
        var port=r.GetProperty("ProxyPort").GetInt32();if(port is <1 or >65535)throw new InvalidDataException("Invalid private fence port");
        var layer=ParseKey(StrictJson.Text(r,"SubLayerKey"));var array=r.GetProperty("Filters");if(array.GetArrayLength()!=6)throw new InvalidDataException("Incomplete fence roles");
        var filters=new List<FenceFilterKey>();var keys=new List<Guid>();var seen=new HashSet<Guid>{layer};var index=0;
        foreach(var entry in array.EnumerateArray())
        {
            StrictJson.Fields(entry,"Role","Key");var role=StrictJson.Text(entry,"Role");var key=ParseKey(StrictJson.Text(entry,"Key"));
            if(role!=CompiledFencePolicy.Roles[index++] || !seen.Add(key))throw new InvalidDataException("Wrong/duplicate fence role or key");
            filters.Add(new(role,key.ToString("N")));keys.Add(key);
        }
        var data=new FenceDocument(1,state.InstallationId,id,Identifiers.Hex32(StrictJson.Text(r,"Release")),Identifiers.Hash(StrictJson.Text(r,"ManifestSHA256")),
            Identifiers.Hash(StrictJson.Text(r,"PolicySHA256")),port,layer.ToString("N"),filters.ToArray(),"INSTALLATION_PACKAGE_SID_ONLY");
        return new(data,raw.SHA256,layer,keys.ToArray()); // Old private policy remains inspectable; never grants activation.
    }
    internal static IReadOnlyList<FencePlan> ReadAll(ProtectedState state)
    {
        var leaves=state.ListLeaves("fence-intent-");if(leaves.Length>64)throw new InvalidDataException("Fence inventory capacity exceeded");
        var result=new List<FencePlan>();var keys=new HashSet<Guid>();
        foreach(var leaf in leaves)
        {
            if(leaf.Length!=50)throw new InvalidDataException("Unexpected fence plan name");var id=Identifiers.Hex32(leaf.Substring(13,32));
            if(leaf!=Leaf(id))throw new InvalidDataException("Fence plan name differs");var plan=Read(state,id);
            foreach(var key in plan.keys.Prepend(plan.SubLayer))if(!keys.Add(key))throw new InvalidDataException("Cross-plan fence key collision");result.Add(plan);
        }
        return result.AsReadOnly();
    }
}
