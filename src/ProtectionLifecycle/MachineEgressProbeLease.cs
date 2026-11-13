using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace ProtectionLifecycle;

// Internal qualification owner. The ProtectedState lease serializes callers.
// Closing an engine handle is never treated as removal of persistent objects.
internal static class MachineEgressProbeLease
{
    internal static MachineEgressFlowResult[] RunDeliveryTrial(ProtectedState state, VerifiedVersion version,
        MachineEgressProbeIntent intent, IMachineEgressDeliveryTrial trial, CancellationToken cancellation)
    {
        ProtectedSession.AssertSystemTestingAllowed();
        return MachineEgressDeliveryRun.Execute(intent.SubLayerKey, trial,
            () => Observe(state, version, intent), () => Apply(state, version, intent),
            () => Recover(state, version, intent.SubLayerKey), cancellation);
    }

    internal static MachineEgressProbeIntent Plan(ProtectedState state, VerifiedVersion version,
        uint v4Interface, IPAddress v4Receiver, uint v6Interface, IPAddress v6Receiver)
    {
        ArgumentNullException.ThrowIfNull(v4Receiver);
        ArgumentNullException.ThrowIfNull(v6Receiver);
        AssertCurrent(state, version);
        var intent = new MachineEgressProbeIntent(1, Guid.ParseExact(state.InstallationId, "N"),
            Guid.ParseExact(version.Package.Release, "N"), version.Package.ManifestHash,
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), v4Interface, v4Receiver.ToString(), v6Interface, v6Receiver.ToString());
        _ = intent.Policy();
        return intent;
    }

    internal static void Apply(ProtectedState state, VerifiedVersion version, MachineEgressProbeIntent intent)
    {
        ProtectedSession.AssertSystemTestingAllowed();
        ProtectedState.RequireAdministrator();
        AssertCurrent(state, version);
        AssertIntentVersion(state, version, intent);
        LifecycleRecovery.AssertNoPending(state);
        using var jobs = RegisteredJobSet.OpenForMaintenance(state);
        jobs.AssertClosedAdmissionsForNetworkMaintenance();

        var bytes = intent.Encode();
        _ = MachineEgressProbeIntent.Decode(bytes, intent.InstallationId, intent.Leaf);
        var policy = intent.Policy();
        using var engine = WfpNative.Open();
        _ = MachineEgressProbePolicy.ReadPacketLayer(engine, AddressFamily.InterNetwork);
        _ = MachineEgressProbePolicy.ReadPacketLayer(engine, AddressFamily.InterNetworkV6);
        var prepared = WfpNative.Transaction(engine, false, () =>
        {
            AssertCurrent(state, version);
            jobs.AssertClosedAdmissionsForNetworkMaintenance();
            MachineEgressProbeTransaction.AssertAbsentInTransaction(engine, policy);
            if (state.ReadOptional(intent.PreparedLeaf) is not null || state.ReadOptional(intent.ClosedLeaf) is not null)
                throw WfpNative.Contract("MachineEgressProbePlanAlreadyUsed");
            // Publish after verifying absence and before the first kernel add.
            // If the process stops after this point the record stays pending.
            var digest = state.WriteNew(intent.Leaf, bytes);
            var objects = MachineEgressProbeTransaction.AddAndReadInTransaction(engine, policy);
            state.WriteNew(intent.PreparedLeaf, new MachineEgressPrepared(1, digest, objects).Encode());
            return objects;
        });
        if (WfpNative.Transaction(engine, true, () => MachineEgressProbeTransaction.ReadOwnedInTransaction(engine, policy)) != prepared)
            throw WfpNative.Contract("CommittedMachineEgressProbeReadbackMismatch");
    }

    internal static MachineEgressPolicyObservation Observe(ProtectedState state, VerifiedVersion version,
        MachineEgressProbeIntent intent)
    {
        ProtectedSession.AssertSystemTestingAllowed();
        ProtectedState.RequireAdministrator();
        var started = Stopwatch.GetTimestamp();
        AssertCurrent(state, version);
        AssertIntentVersion(state, version, intent);
        var bytes = intent.Encode();
        var digest = Convert.ToHexString(SHA256.HashData(bytes));
        var record = state.ReadOptional(intent.Leaf);
        if (record is not null && (record.SHA256 != digest || !record.Bytes.AsSpan().SequenceEqual(bytes)))
            throw WfpNative.Contract("MachineEgressObservationIntentDiffers");

        var closed = ClosedReceiptPresent(state, intent, MachineEgressRecoveryState.ClosedReceipt(intent, digest));
        var prepared = state.ReadOptional(intent.PreparedLeaf)?.Bytes;
        using var engine = WfpNative.Open();
        var objects = WfpNative.Transaction(engine, true,
            () => MachineEgressProbeTransaction.ReadOwnedInTransaction(engine, intent.Policy()));
        var result = MachineEgressRecoveryState.Observe(objects, record is not null, closed, prepared, digest);
        return new(intent.SubLayerKey, result, started, Stopwatch.GetTimestamp(),
            result == MachineEgressPolicyState.ExactBlock ? objects : null);
    }

    internal static void Recover(ProtectedState state, VerifiedVersion version, Guid operation)
    {
        ProtectedSession.AssertSystemTestingAllowed();
        ProtectedState.RequireAdministrator();
        AssertCurrent(state, version);
        using var jobs = RegisteredJobSet.OpenForMaintenance(state);
        jobs.AssertClosedAdmissionsForNetworkMaintenance();

        var leaf = MachineEgressProbeIntent.Prefix + operation.ToString("N") + ".json";
        var (intent, digest) = Read(state, leaf);
        AssertIntentVersion(state, version, intent);

        var policy = intent.Policy();
        var expectedReceipt = MachineEgressRecoveryState.ClosedReceipt(intent, digest);
        using var engine = WfpNative.Open();
        if (ClosedReceiptPresent(state, intent, expectedReceipt))
        {
            // A replay of a closed operation cannot delete objects that
            // appeared later, even if the original keys were reused.
            WfpNative.Transaction(engine, true, () => MachineEgressProbeTransaction.AssertAbsentInTransaction(engine, policy));
            return;
        }

        WfpNative.Transaction(engine, false, () =>
        {
            AssertCurrent(state, version);
            jobs.AssertClosedAdmissionsForNetworkMaintenance();
            if (state.Read(leaf, 4096).SHA256 != digest)
                throw WfpNative.Contract("MachineEgressRecoveryIntentChanged");
            if (MachineEgressProbeTransaction.ReadOwnedInTransaction(engine, policy) is { } objects)
            {
                MachineEgressPrepared.AssertMatches(state.ReadOptional(intent.PreparedLeaf)?.Bytes, digest, objects);
                foreach (var family in new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 })
                {
                    var key = policy.FilterKey(family);
                    WfpNative.Check(WfpNative.FwpmFilterDeleteByKey0(engine, in key), "DeleteExactMachineEgressProbeFilter");
                }
                var layer = policy.SubLayerKey;
                WfpNative.Check(WfpNative.FwpmSubLayerDeleteByKey0(engine, in layer), "DeleteExactMachineEgressProbeSubLayer");
            }
            return MachineEgressProbeTransaction.AssertAbsentInTransaction(engine, policy);
        });
        WfpNative.Transaction(engine, true, () => MachineEgressProbeTransaction.AssertAbsentInTransaction(engine, policy));
        state.WriteNew(intent.ClosedLeaf, expectedReceipt);
    }

    internal static void AssertNoPending(ProtectedState state)
    {
        foreach (var leaf in state.ListLeaves(MachineEgressProbeIntent.Prefix))
        {
            var (intent, digest) = Read(state, leaf);
            if (!ClosedReceiptPresent(state, intent, MachineEgressRecoveryState.ClosedReceipt(intent, digest)))
                throw WfpNative.Contract("MachineEgressProbeRequiresExactRecovery");
        }
    }

    private static bool ClosedReceiptPresent(ProtectedState state, MachineEgressProbeIntent intent, byte[] expected)
    {
        var receipt = state.ReadOptional(intent.ClosedLeaf);
        if (receipt is null) return false;
        if (!receipt.Bytes.AsSpan().SequenceEqual(expected))
            throw WfpNative.Contract("MachineEgressRecoveryReceiptDiffers");
        return true;
    }

    private static (MachineEgressProbeIntent Intent, string Digest) Read(ProtectedState state, string leaf)
    {
        var record = state.Read(leaf, 4096);
        return (MachineEgressProbeIntent.Decode(record.Bytes, Guid.ParseExact(state.InstallationId, "N"), leaf), record.SHA256);
    }

    private static void AssertCurrent(ProtectedState state, VerifiedVersion version)
    {
        version.AssertHeld(state);
        var pointer = CurrentPointer.Parse(state.Read("current.json", 4096), state.InstallationId);
        if (pointer.Release != version.Package.Release || pointer.ManifestSHA256 != version.Package.ManifestHash ||
            pointer.Activation != "INACTIVE")
            throw WfpNative.Contract("MachineEgressProbeRequiresCurrentInactiveVersion");
    }

    private static void AssertIntentVersion(ProtectedState state, VerifiedVersion version, MachineEgressProbeIntent intent)
    {
        if (intent.InstallationId.ToString("N") != state.InstallationId ||
            intent.Release.ToString("N") != version.Package.Release || intent.ManifestSHA256 != version.Package.ManifestHash)
            throw WfpNative.Contract("MachineEgressProbeArtifactDiffers");
    }
}
