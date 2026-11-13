using System.Security.Cryptography;
using System.Text;
using ProtectionLifecycle;

internal static class MachineEgressRecoveryCases
{
    internal static void Run()
    {
        var intent = new MachineEgressProbeIntent(1, Guid.NewGuid(), Guid.NewGuid(), new string('A', 64),
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 18, "192.0.2.130", 22, "2001:db8::5");
        var bytes = intent.Encode();
        Require(MachineEgressProbeIntent.Decode(bytes, intent.InstallationId, intent.Leaf) == intent);
        Reject(() => _ = MachineEgressProbeIntent.Decode(bytes, Guid.NewGuid(), intent.Leaf));
        Reject(() => _ = MachineEgressProbeIntent.Decode(bytes, intent.InstallationId, intent.Leaf + ".json"));
        foreach (var invalid in new[]
        {
            intent with { SchemaVersion = 2 },
            intent with { Release = Guid.Empty },
            intent with { ManifestSHA256 = new string('a', 64) },
            intent with { V4Key = intent.V6Key },
            intent with { V4Receiver = "127.0.0.1" },
            intent with { V6Interface = 0 }
        })
            Reject(() => _ = MachineEgressProbeIntent.Decode(invalid.Encode(), intent.InstallationId, intent.Leaf));
        var duplicate = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(bytes).Insert(1, "\"SchemaVersion\":1,"));
        Reject(() => _ = MachineEgressProbeIntent.Decode(duplicate, intent.InstallationId, intent.Leaf));

        for (var mask = 0; mask < 8; mask++)
        {
            bool Select() => MachineEgressRecoveryState.Select((mask & 1) != 0, (mask & 2) != 0, (mask & 4) != 0);
            if (mask is 0 or 7) Require(Select() == (mask == 7));
            else Reject(() => _ = Select());
        }

        var digest = Convert.ToHexString(SHA256.HashData(bytes));
        var receipt = MachineEgressRecoveryState.ClosedReceipt(intent, digest);
        Require(receipt.AsSpan().SequenceEqual(MachineEgressRecoveryState.ClosedReceipt(intent, digest)));
        Require(!receipt.AsSpan().SequenceEqual(MachineEgressRecoveryState.ClosedReceipt(intent, new string('B', 64))));
        Require(!receipt.AsSpan().SequenceEqual(MachineEgressRecoveryState.ClosedReceipt(intent with { SubLayerKey = Guid.NewGuid() }, digest)));
        var observed = new MachineEgressObjects(100, 200, 300, digest, digest, digest);
        var prepared = new MachineEgressPrepared(1, digest, observed).Encode();
        MachineEgressPrepared.AssertMatches(prepared, digest, observed);
        Reject(() => MachineEgressPrepared.AssertMatches(null, digest, observed));
        Reject(() => MachineEgressPrepared.AssertMatches(prepared, digest, observed with { V4Id = 400 }));
        Reject(() => MachineEgressPrepared.AssertMatches(prepared, digest, observed with { Weight = 101 }));
        Reject(() => MachineEgressPrepared.AssertMatches(prepared, digest, observed with { V6SecuritySHA256 = new string('B', 64) }));
        Reject(() => MachineEgressPrepared.AssertMatches(prepared, new string('B', 64), observed));
        Console.WriteLine("PASS machine egress recovery intent, receipt binding and complete inventory decisions (managed only)");
    }

    private static void Reject(Action action)
    {
        try { action(); }
        catch (Exception error) when (error is ArgumentException or InvalidDataException) { return; }
        throw new InvalidOperationException("Machine egress recovery accepted invalid evidence");
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("Machine egress recovery fixture mismatch");
    }
}
