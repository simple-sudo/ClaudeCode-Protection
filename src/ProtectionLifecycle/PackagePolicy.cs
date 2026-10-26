using System.Security.Cryptography;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record AssetSpec(string Id, string Path);
internal sealed record PayloadFile(AssetSpec Asset, long Length, string SHA256);
internal sealed class ReviewedPackage
{
    internal string Release { get; }
    internal string ManifestHash { get; }
    internal IReadOnlyList<PayloadFile> Files { get; }
    internal ReadOnlyMemory<byte> ManifestBytes { get; }
    private ReviewedPackage(string release, string hash, IReadOnlyList<PayloadFile> files, byte[] frozen)
    { Release = release; ManifestHash = hash; Files = files; ManifestBytes = frozen; }
    internal static ReviewedPackage FromBytes(ReadOnlyMemory<byte> raw)
    {
        if (raw.Length is < 1 or > PackagePolicy.MaxManifestBytes) throw new InvalidDataException("Manifest size refused");
        var frozen = raw.ToArray(); // Hash and parse the same privately captured bytes.
        var validated = PackagePolicy.ValidateAuthorized(frozen);
        return new(validated.Release, validated.ManifestHash, validated.Files, frozen);
    }
    internal static ReviewedPackage FromOwnedState(ProtectedState state,string release,ReadOnlyMemory<byte> raw)
    {
        // Historical authorization comes from protected administrator state,
        // never the publicly readable version marker or a supplied digest.
        var receipt=OwnedReleaseReceipt.Read(state,release);
        if(raw.Length is <1 or >PackagePolicy.MaxManifestBytes) throw new InvalidDataException("Stored manifest size refused");
        var frozen=raw.ToArray();
        var data=PackagePolicy.ValidateOwned(frozen,receipt);
        return new(data.Release,data.ManifestHash,data.Files,frozen);
    }
}

internal static class PackagePolicy
{
    // This value must be built into a specifically reviewed one-shot bootstrap.
    // A user-writable sidecar, environment value, CLI hash or manifest cannot
    // populate it. No approved package exists in the current static phase.
    private static readonly string? ApprovedManifestSHA256 = null;
    // Explicit incident retirement/no-restoration boundary, not a malware
    // signature or a vendor false-positive determination. Applies to all names.
    private static readonly HashSet<string> RetiredIncidentArtifacts=new(StringComparer.Ordinal) {
        "10C687554CDF8BBA56D2680784850F1F7C321D17F339FC1E41EB3F2C885010E6"
    };
    internal const int MaxManifestBytes = 64 * 1024;
    internal const long MaxAssetBytes = 128L * 1024 * 1024;
    internal const long MaxPackageBytes = 256L * 1024 * 1024;
    internal static readonly IReadOnlyList<AssetSpec> Catalog = Array.AsReadOnly(new[] {
        new AssetSpec("daily-exe", "bin/current/ClaudeProtection.exe"),
        new AssetSpec("daily-dll", "bin/current/ClaudeProtection.dll"),
        new AssetSpec("daily-deps", "bin/current/ClaudeProtection.deps.json"),
        new AssetSpec("daily-runtime", "bin/current/ClaudeProtection.runtimeconfig.json"),
        new AssetSpec("daily-reader", "bin/current/Read-Environment.ps1"),
        new AssetSpec("center-exe", "bin/center/ProtectionCenter.exe"),
        new AssetSpec("center-dll", "bin/center/ProtectionCenter.dll"),
        new AssetSpec("center-deps", "bin/center/ProtectionCenter.deps.json"),
        new AssetSpec("center-runtime", "bin/center/ProtectionCenter.runtimeconfig.json"),
        new AssetSpec("broker-exe", "bin/admin/ProtectionBroker.exe"),
        new AssetSpec("broker-dll", "bin/admin/ProtectionBroker.dll"),
        new AssetSpec("broker-deps", "bin/admin/ProtectionBroker.deps.json"),
        new AssetSpec("broker-runtime", "bin/admin/ProtectionBroker.runtimeconfig.json"),
        new AssetSpec("broker-lifecycle", "bin/admin/ProtectionLifecycle.dll")
    });

    // Future local bootstrap authorization must bind this assembly and all its
    // dependencies before any elevated execution. Pinning the payload alone
    // does not authenticate a mutable bootstrap or resolve the AV incident.
    internal static ReviewedPackage Authorize(ReadOnlyMemory<byte> raw) => ReviewedPackage.FromBytes(raw);
    internal static (string Release, string ManifestHash, IReadOnlyList<PayloadFile> Files) ValidateAuthorized(ReadOnlyMemory<byte> raw)
    {
        if (ApprovedManifestSHA256 is not { } expected)
            throw new InvalidOperationException("NO_REVIEWED_PACKAGE: installation remains unavailable");
        return ParsePinned(raw, expected);
    }
    internal static (string Release,string ManifestHash,IReadOnlyList<PayloadFile> Files) ValidateOwned(ReadOnlyMemory<byte> raw,OwnedReleaseReceipt receipt)
    {
        var parsed=ParsePinned(raw,receipt.ManifestSHA256);
        if(parsed.Release!=receipt.Release) throw new InvalidDataException("Stored manifest belongs to another release");
        return parsed;
    }

    private static (string Release, string ManifestHash, IReadOnlyList<PayloadFile> Files) ParsePinned(ReadOnlyMemory<byte> raw, string trustedDigest)
    {
        _ = Identifiers.Hash(trustedDigest);
        if (raw.Length is < 1 or > MaxManifestBytes) throw new InvalidDataException("Manifest size refused");
        var digest = Convert.ToHexString(SHA256.HashData(raw.Span));
        if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(digest), Convert.FromHexString(trustedDigest)))
            throw new InvalidDataException("Package differs from reviewed identity");
        using var doc = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 8 });
        var root = doc.RootElement;
        StrictJson.Fields(root, "SchemaVersion", "Scope", "Release", "Files");
        if (root.GetProperty("SchemaVersion").GetInt32() != 1 ||
            root.GetProperty("Scope").GetString() != "UNACTIVATED_PRODUCT") throw new InvalidDataException("Manifest scope/schema refused");
        var release = Identifiers.Hex32(StrictJson.Text(root, "Release"));
        var array = root.GetProperty("Files");
        if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() != Catalog.Count) throw new InvalidDataException("Exact asset set required");
        var files = new List<PayloadFile>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        long total = 0;
        foreach (var entry in array.EnumerateArray())
        {
            StrictJson.Fields(entry, "Asset", "Length", "SHA256");
            var id = StrictJson.Text(entry, "Asset");
            var spec = Catalog.SingleOrDefault(s => s.Id == id) ?? throw new InvalidDataException("Unknown asset identifier");
            if (!seen.Add(id)) throw new InvalidDataException("Duplicate asset");
            var size = entry.GetProperty("Length").GetInt64();
            if (size is < 1 or > MaxAssetBytes) throw new InvalidDataException("Payload size refused");
            total = checked(total + size);
            if (total > MaxPackageBytes) throw new InvalidDataException("Package size refused");
            var assetHash=Identifiers.Hash(StrictJson.Text(entry,"SHA256"));
            if(RetiredIncidentArtifacts.Contains(assetHash))throw new InvalidDataException("Retired incident artifact cannot be installed or restored");
            files.Add(new(spec,size,assetHash));
        }
        return (release, digest, files.AsReadOnly());
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
