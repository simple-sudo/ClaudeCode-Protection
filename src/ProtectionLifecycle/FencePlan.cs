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
        state.AssertHeld();id=Identifiers.Hex32(id);return Parse(state,id,state.Read(Leaf(id),16384));
    }
    private static FencePlan Parse(ProtectedState state,string id,BoundBytes raw)
    {
        using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=5});var r=doc.RootElement;
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
    internal static IReadOnlyList<FencePlan> ReadAll(ProtectedState state,bool forNetworkMigration=false)
    {
        if(!forNetworkMigration)AssertNoPendingMigration(state);
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

    // A single, compiled 7890 -> owned-gateway transition. Keep the complete
    // preimage before replacing policy; this receipt never grants launch authority.
    internal sealed record Migration(FencePlan Prior,FencePlan Next,BoundBytes NextBytes,string JournalSHA256);
    private static string MigrationLeaf(string id)=>"fence-migration-"+Identifiers.Hex32(id)+".json";
    private static string MigrationDoneLeaf(string id)=>"fence-migrated-"+Identifiers.Hex32(id)+".json";
    internal static Migration PrepareMigration(ProtectedState state,VerifiedVersion version,string id)
    {
        state.AssertHeld();version.AssertHeld(state);id=Identifiers.Hex32(id);
        if(state.ReadOptional(MigrationLeaf(id)) is null)
        {
            var prior=state.Read(Leaf(id),16384);var plan=Parse(state,id,prior);
            if(plan.Data.PolicySHA256!=CompiledFencePolicy.SHA256 || plan.Data.ProxyPort!=CompiledFencePolicy.ProxyPort)
                throw WfpNative.Contract("OnlyKnownRawProxyPolicyCanMigrate");
            var nextBytes=JsonSerializer.SerializeToUtf8Bytes(plan.Data with {Release=version.Package.Release,
                ManifestSHA256=version.Package.ManifestHash,PolicySHA256=SessionProxy.PolicySHA256,ProxyPort=SessionProxy.Port});
            state.WriteNew(MigrationLeaf(id),JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,FenceId=id,
                PriorSHA256=prior.SHA256,PriorBase64=Convert.ToBase64String(prior.Bytes),
                NextSHA256=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(nextBytes)),NextBase64=Convert.ToBase64String(nextBytes),
                Scope="RAW_PROXY_TO_OWNED_GATEWAY_FULL_QUARANTINE_ONLY"}));
        }
        var migration=ReadMigration(state,id);
        if(migration.Next.Data.Release!=version.Package.Release || migration.Next.Data.ManifestSHA256!=version.Package.ManifestHash ||
            migration.Next.Data.PolicySHA256!=SessionProxy.PolicySHA256 || migration.Next.Data.ProxyPort!=SessionProxy.Port)
            throw WfpNative.Contract("MigrationArtifactOrPolicyChanged");
        return migration;
    }
    private static Migration ReadMigration(ProtectedState state,string id)
    {
        var raw=state.Read(MigrationLeaf(id),65536);using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=3});var r=doc.RootElement;
        StrictJson.Fields(r,"SchemaVersion","InstallationId","FenceId","PriorSHA256","PriorBase64","NextSHA256","NextBase64","Scope");
        if(r.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(r,"InstallationId")!=state.InstallationId ||
            StrictJson.Text(r,"FenceId")!=id || StrictJson.Text(r,"Scope")!="RAW_PROXY_TO_OWNED_GATEWAY_FULL_QUARANTINE_ONLY")
            throw WfpNative.Contract("ForeignFenceMigration");
        BoundBytes Decode(string name)
        {
            var encoded=StrictJson.Text(r,name+"Base64");if(encoded.Length>22000)throw WfpNative.Contract("MigrationImageTooLarge");
            var bytes=Convert.FromBase64String(encoded);if(bytes.Length>16384)throw WfpNative.Contract("MigrationImageTooLarge");
            var hash=Identifiers.Hash(StrictJson.Text(r,name+"SHA256"));
            if(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes))!=hash)throw WfpNative.Contract("MigrationImageHashMismatch");
            return new(bytes,hash);
        }
        var priorBytes=Decode("Prior");var nextBytes=Decode("Next");
        var prior=Parse(state,id,priorBytes);var next=Parse(state,id,nextBytes);
        var selected=Read(state,id).SHA256;
        // Schema 1's completed journal remains readable after a gateway policy
        // upgrade. PrepareMigration separately requires the CURRENT policy for
        // a live migration/recovery; history is never an activation credential.
        if(prior.Data.PolicySHA256!=CompiledFencePolicy.SHA256 || prior.Data.ProxyPort!=CompiledFencePolicy.ProxyPort ||
            next.Data.PolicySHA256==prior.Data.PolicySHA256 || next.Data.ProxyPort!=17891 ||
            prior.SubLayer!=next.SubLayer || !prior.keys.SequenceEqual(next.keys) || prior.SHA256==next.SHA256 ||
            (selected!=prior.SHA256 && selected!=next.SHA256))
            throw WfpNative.Contract("MigrationPolicyKeysOrSelectionDiffer");
        return new(prior,next,nextBytes,raw.SHA256);
    }
    internal static bool HasMigration(ProtectedState state,string id)=>state.ReadOptional(MigrationLeaf(id)) is not null;
    private static byte[] CompletionBytes(ProtectedState state,Migration migration)=>JsonSerializer.SerializeToUtf8Bytes(new {
        SchemaVersion=1,state.InstallationId,FenceId=migration.Next.Data.FenceId,migration.JournalSHA256,
        SelectedSHA256=migration.Next.SHA256,Status="FULL_QUARANTINE_MIGRATED_NOT_LAUNCH_EVIDENCE"});
    internal static void CompleteMigration(ProtectedState state,Migration migration)
    {
        if(Read(state,migration.Next.Data.FenceId).SHA256!=migration.Next.SHA256)throw WfpNative.Contract("MigrationSelectionNotCommitted");
        var leaf=MigrationDoneLeaf(migration.Next.Data.FenceId);var expected=CompletionBytes(state,migration);var old=state.ReadOptional(leaf);
        if(old is null)state.WriteNew(leaf,expected);
        else if(!old.Bytes.AsSpan().SequenceEqual(expected))throw WfpNative.Contract("MigrationCompletionChanged");
    }
    internal static void AssertNoPendingMigration(ProtectedState state)
    {
        var leaves=state.ListLeaves("fence-migration-");if(leaves.Length>64)throw WfpNative.Contract("MigrationInventoryFull");
        foreach(var leaf in leaves)
        {
            if(leaf.Length!=53)throw WfpNative.Contract("UnexpectedMigrationLeaf");
            var id=Identifiers.Hex32(leaf.Substring(16,32));if(leaf!=MigrationLeaf(id))throw WfpNative.Contract("UnexpectedMigrationLeaf");
            var migration=ReadMigration(state,id);var done=state.ReadOptional(MigrationDoneLeaf(id));
            if(Read(state,id).SHA256!=migration.Next.SHA256 || done is null || !done.Bytes.AsSpan().SequenceEqual(CompletionBytes(state,migration)))
                throw WfpNative.Contract("PendingFenceMigrationRequiresExactRecovery");
        }
    }
}
