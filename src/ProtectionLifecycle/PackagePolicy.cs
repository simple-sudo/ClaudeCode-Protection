using System.Security.Cryptography;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record PayloadFile(AssetSpec Asset, long Length, string SHA256);
internal sealed class ReviewedPackage
{
    internal int SchemaVersion { get; }
    internal string Release { get; }
    internal string ManifestHash { get; }
    internal IReadOnlyList<PayloadFile> Files { get; }
    internal ReadOnlyMemory<byte> ManifestBytes { get; }
    private ReviewedPackage(int schema, string release, string hash, IReadOnlyList<PayloadFile> files, byte[] frozen)
    { SchemaVersion=schema; Release = release; ManifestHash = hash; Files = files; ManifestBytes = frozen; }
    internal static ReviewedPackage FromBootstrap(BootstrapApproval approval)
    {
        approval.AssertHeld();
        var raw=approval.Manifest;
        if (raw.Length is < 1 or > PackagePolicy.MaxManifestBytes) throw new InvalidDataException("Manifest size refused");
        var frozen = raw.ToArray(); // Hash and parse the same privately captured bytes.
        var validated = PackagePolicy.ParsePinned(frozen, approval.ManifestHash);
        return new(validated.SchemaVersion, validated.Release, validated.ManifestHash, validated.Files, frozen);
    }
    internal void AssertSameManifest(ReadOnlyMemory<byte> raw)
    {
        if(!raw.Span.SequenceEqual(ManifestBytes.Span))throw new InvalidDataException("Source package changed");
    }
    internal static ReviewedPackage FromOwnedState(ProtectedState state,string release,ReadOnlyMemory<byte> raw)
    {
        // Historical authorization comes from protected administrator state,
        // never the publicly readable version marker or a supplied digest.
        var receipt=OwnedReleaseReceipt.Read(state,release);
        if(raw.Length is <1 or >PackagePolicy.MaxManifestBytes) throw new InvalidDataException("Stored manifest size refused");
        var frozen=raw.ToArray();
        var data=PackagePolicy.ValidateOwned(frozen,receipt);
        return new(data.SchemaVersion,data.Release,data.ManifestHash,data.Files,frozen);
    }
}

internal static class PackagePolicy
{
    // The independently pinned bootstrap embeds the complete approval AFTER
    // payload compilation. This library is itself a payload asset: embedding
    // the payload-manifest digest here would be circular. No sidecar/CLI digest
    // is an authority; BootstrapApproval requires the protected fixed host.
    // Explicit incident retirement/no-restoration boundary, not a malware
    // signature or a vendor false-positive determination. Applies to all names.
    private static readonly HashSet<string> RetiredIncidentArtifacts=new(StringComparer.Ordinal) {
        "10C687554CDF8BBA56D2680784850F1F7C321D17F339FC1E41EB3F2C885010E6"
    };
    internal const int MaxManifestBytes = PackageAssetCatalog.MaxManifestBytes;
    internal const long MaxPackageBytes = 256L * 1024 * 1024;
    internal static (string Release,string ManifestHash,IReadOnlyList<PayloadFile> Files,int SchemaVersion) ValidateOwned(ReadOnlyMemory<byte> raw,OwnedReleaseReceipt receipt)
    {
        var parsed=ParsePinned(raw,receipt.ManifestSHA256);
        if(parsed.Release!=receipt.Release) throw new InvalidDataException("Stored manifest belongs to another release");
        return parsed;
    }

    internal static (string Release,string ManifestHash,IReadOnlyList<PayloadFile> Files,int SchemaVersion) ParsePinned(ReadOnlyMemory<byte> raw, string trustedDigest)
    {
        _ = Identifiers.Hash(trustedDigest);
        if (raw.Length is < 1 or > MaxManifestBytes) throw new InvalidDataException("Manifest size refused");
        var digest = Convert.ToHexString(SHA256.HashData(raw.Span));
        if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(digest), Convert.FromHexString(trustedDigest)))
            throw new InvalidDataException("Package differs from reviewed identity");
        using var doc = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 8 });
        var root = doc.RootElement;
        StrictJson.Fields(root, "SchemaVersion", "Scope", "Release", "Files");
        var schema=root.GetProperty("SchemaVersion").GetInt32();
        if (root.GetProperty("Scope").GetString() != "UNACTIVATED_PRODUCT") throw new InvalidDataException("Manifest scope refused");
        var release = Identifiers.Hex32(StrictJson.Text(root, "Release"));
        var files=ParseInventory(root.GetProperty("Files"),schema,"Asset");
        if(files.Any(file=>RetiredIncidentArtifacts.Contains(file.SHA256)))
            throw new InvalidDataException("Retired incident artifact cannot be installed or restored");
        return (release,digest,files,schema);
    }
    internal static IReadOnlyList<PayloadFile> ParseInventory(JsonElement array,int schema,string identifier)
    {
        var catalog=PackageAssetCatalog.ForSchema(schema);
        if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() != catalog.Count) throw new InvalidDataException("Exact asset set required");
        var files = new List<PayloadFile>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        long total = 0;
        foreach (var entry in array.EnumerateArray())
        {
            StrictJson.Fields(entry,identifier,"Length","SHA256");
            var id = StrictJson.Text(entry,identifier);
            var spec = catalog.SingleOrDefault(s => s.Id == id) ?? throw new InvalidDataException("Unknown asset identifier");
            if (!seen.Add(id)) throw new InvalidDataException("Duplicate asset");
            var size = entry.GetProperty("Length").GetInt64();
            var assetHash=Identifiers.Hash(StrictJson.Text(entry,"SHA256"));
            if(!spec.Matches(size,assetHash))throw new InvalidDataException("Asset bytes outside reviewed policy");
            // The exact, once-only official image has its own compiled byte
            // bound. All other assets still share the historical package budget.
            if(spec!=PackageAssetCatalog.OfficialClaudeImage)total = checked(total + size);
            if (total > MaxPackageBytes) throw new InvalidDataException("Package size refused");
            files.Add(new(spec,size,assetHash));
        }
        return files.AsReadOnly();
    }
}

internal static class StrictJson
{
    internal static void Fields(JsonElement node, params string[] fields)
    {
        if (node.ValueKind != JsonValueKind.Object) throw new InvalidDataException("JSON object required");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in node.EnumerateObject())
            if (!fields.Contains(property.Name, StringComparer.Ordinal) || !seen.Add(property.Name))
                throw new InvalidDataException("Unknown or duplicate JSON property");
        if (seen.Count != fields.Length) throw new InvalidDataException("Missing JSON property");
    }
    internal static string Text(JsonElement node, string name)
    {
        var value = node.GetProperty(name);
        if (value.ValueKind != JsonValueKind.String) throw new InvalidDataException("String property required");
        return value.GetString() ?? throw new InvalidDataException("Null string refused");
    }
}
