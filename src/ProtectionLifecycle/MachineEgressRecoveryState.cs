using System.Net;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record MachineEgressProbeIntent(int SchemaVersion, Guid InstallationId, Guid Release,
    string ManifestSHA256, Guid SubLayerKey, Guid V4Key, Guid V6Key,
    uint V4Interface, string V4Receiver, uint V6Interface, string V6Receiver)
{
    internal const string Prefix = "machine-egress-probe-intent-";
    internal string Leaf => Prefix + SubLayerKey.ToString("N") + ".json";
    internal string ClosedLeaf => "machine-egress-probe-closed-" + SubLayerKey.ToString("N") + ".json";
    internal string PreparedLeaf => "machine-egress-probe-prepared-" + SubLayerKey.ToString("N") + ".json";

    internal MachineEgressProbePolicy Policy() => new(SubLayerKey, V4Key, V6Key, V4Interface,
        IPAddress.Parse(V4Receiver), V6Interface, IPAddress.Parse(V6Receiver));

    internal byte[] Encode() => JsonSerializer.SerializeToUtf8Bytes(this);

    internal static MachineEgressProbeIntent Decode(byte[] bytes, Guid installation, string leaf)
    {
        if (bytes.Length is 0 or > 4096) throw new InvalidDataException("MachineEgressIntentSize");
        var intent = JsonSerializer.Deserialize<MachineEgressProbeIntent>(bytes);
        if (intent is null || intent.SchemaVersion != 1 || intent.InstallationId != installation ||
            installation == Guid.Empty || intent.Release == Guid.Empty ||
            intent.ManifestSHA256 is not { Length: 64 } || !intent.ManifestSHA256.All(Uri.IsHexDigit) ||
            intent.ManifestSHA256 != intent.ManifestSHA256.ToUpperInvariant() ||
            intent.Leaf != leaf || !bytes.AsSpan().SequenceEqual(intent.Encode()))
            throw new InvalidDataException("MachineEgressIntentBinding");
        _ = intent.Policy();
        return intent;
    }
}

internal readonly record struct MachineEgressObjects(ushort Weight, ulong V4Id, ulong V6Id,
    string LayerSecuritySHA256, string V4SecuritySHA256, string V6SecuritySHA256);

internal sealed record MachineEgressPrepared(int SchemaVersion, string IntentSHA256, MachineEgressObjects Objects)
{
    internal byte[] Encode() => JsonSerializer.SerializeToUtf8Bytes(this);

    internal static void AssertMatches(byte[]? bytes, string digest, MachineEgressObjects actual)
    {
        if (actual.V4Id == 0 || actual.V6Id == 0 || actual.V4Id == actual.V6Id ||
            bytes is null || !bytes.AsSpan().SequenceEqual(new MachineEgressPrepared(1, digest, actual).Encode()))
            throw new InvalidDataException("MachineEgressPreparedObjectsDiffer");
    }
}

internal static class MachineEgressRecoveryState
{
    // The writer creates/deletes all three objects atomically. A partial
    // inventory is drift, including when all remaining objects match.
    internal static bool Select(bool sublayerPresent, bool ipv4Present, bool ipv6Present)
    {
        if (sublayerPresent != ipv4Present || sublayerPresent != ipv6Present)
            throw new InvalidDataException("MachineEgressProbePartialInventory");
        return sublayerPresent;
    }

    internal static byte[] ClosedReceipt(MachineEgressProbeIntent intent, string digest) =>
        JsonSerializer.SerializeToUtf8Bytes(new
        {
            SchemaVersion = 1,
            intent.InstallationId,
            intent.SubLayerKey,
            IntentSHA256 = digest,
            Status = "EXACT_PROBE_OBJECTS_ABSENT"
        });
}
