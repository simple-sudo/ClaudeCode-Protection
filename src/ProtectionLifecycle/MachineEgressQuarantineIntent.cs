using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record MachineEgressQuarantineIntent(int SchemaVersion, Guid InstallationId, Guid Release,
    string ManifestSHA256, Guid SubLayerKey, Guid OutboundV4, Guid OutboundV6, Guid ForwardV4, Guid ForwardV6)
{
    internal const string Prefix = "machine-quarantine-intent-";
    internal string Leaf => Prefix + SubLayerKey.ToString("N") + ".json";
    internal string PreparedLeaf => "machine-quarantine-prepared-" + SubLayerKey.ToString("N") + ".json";
    internal string ClosedLeaf => "machine-quarantine-closed-" + SubLayerKey.ToString("N") + ".json";

    internal MachineEgressQuarantinePolicy Policy() =>
        new(InstallationId, SubLayerKey, OutboundV4, OutboundV6, ForwardV4, ForwardV6);

    internal byte[] Encode() => JsonSerializer.SerializeToUtf8Bytes(this);

    internal static MachineEgressQuarantineIntent Decode(byte[] bytes, Guid installationId, string leaf)
    {
        if (bytes.Length is 0 or > 4096) throw new InvalidDataException("MachineQuarantineIntentSize");
        var intent = JsonSerializer.Deserialize<MachineEgressQuarantineIntent>(bytes);
        if (intent is null || intent.SchemaVersion != 1 || intent.InstallationId != installationId ||
            intent.Release == Guid.Empty || intent.ManifestSHA256 is not { Length: 64 } ||
            !intent.ManifestSHA256.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F') ||
            intent.Leaf != leaf || !bytes.AsSpan().SequenceEqual(intent.Encode()))
            throw new InvalidDataException("MachineQuarantineIntentBinding");
        _ = intent.Policy();
        return intent;
    }

    internal byte[] Prepared(string digest, MachineEgressQuarantineObservation observation) =>
        JsonSerializer.SerializeToUtf8Bytes(new { SchemaVersion = 1, SubLayerKey, IntentSHA256 = digest, Observation = observation });

    internal void AssertPrepared(byte[]? record, string digest, MachineEgressQuarantineObservation observation)
    {
        if (record is null || !record.AsSpan().SequenceEqual(Prepared(digest, observation)))
            throw new InvalidDataException("MachineQuarantinePreparedObjectsDiffer");
    }

    internal byte[] Closed(string digest) => JsonSerializer.SerializeToUtf8Bytes(new
    {
        SchemaVersion = 1, InstallationId, SubLayerKey, IntentSHA256 = digest, Status = "EXACT_QUARANTINE_OBJECTS_ABSENT"
    });
}
