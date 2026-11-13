namespace ProtectionLifecycle;

// Owns only the deny-only full-machine transaction. The installed state
// lock serializes it with other management operations.
internal static class MachineEgressQuarantineLease
{
    internal static Guid Apply(ProtectedState state, VerifiedVersion version)
    {
        ProtectedSession.AssertSystemTestingAllowed();
        ProtectedState.RequireAdministrator();
        AssertCurrent(state, version);
        LifecycleRecovery.AssertNoPending(state);
        using var jobs = RegisteredJobSet.OpenForMaintenance(state);
        jobs.AssertClosedAdmissionsForNetworkMaintenance();

        var intent = new MachineEgressQuarantineIntent(1, Guid.ParseExact(state.InstallationId, "N"),
            Guid.ParseExact(version.Package.Release, "N"), version.Package.ManifestHash,
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
        var policy = intent.Policy();
        using var engine = WfpNative.Open();
        var digest = WfpNative.Transaction(engine, false, () =>
        {
            AssertCurrent(state, version);
            jobs.AssertClosedAdmissionsForNetworkMaintenance();
            AssertAbsent(engine, policy);
            if (state.ReadOptional(intent.PreparedLeaf) is not null || state.ReadOptional(intent.ClosedLeaf) is not null)
                throw WfpNative.Contract("MachineQuarantinePlanAlreadyUsed");
            var intentDigest = state.WriteNew(intent.Leaf, intent.Encode());
            using var arena = new WfpNative.Arena();
            using var descriptor = new WfpNative.Descriptor();
            var layer = policy.DefineSubLayer(arena);
            WfpNative.Check(WfpNative.FwpmSubLayerAdd0(engine, in layer, descriptor.Pointer), "AddMachineQuarantineSubLayer");
            var ids = new ulong[policy.FilterCount];
            for (var role = 0; role < ids.Length; role++)
            {
                var filter = policy.DefineFilter(role, arena);
                WfpNative.Check(WfpNative.FwpmFilterAdd0(engine, in filter, descriptor.Pointer, out ids[role]),
                    "AddMachineQuarantineFilter");
            }
            var observed = RequireObserved(MachineEgressQuarantineReadback.ReadInTransaction(engine, policy));
            if (!ids.SequenceEqual(observed.FilterIds)) throw WfpNative.Contract("MachineQuarantineAssignedIdsDiffer");
            state.WriteNew(intent.PreparedLeaf, intent.Prepared(intentDigest, observed));
            return intentDigest;
        });
        intent.AssertPrepared(state.ReadOptional(intent.PreparedLeaf)?.Bytes, digest,
            RequireObserved(MachineEgressQuarantineReadback.Read(engine, policy)));
        return intent.SubLayerKey;
    }

    internal static void Recover(ProtectedState state, VerifiedVersion version, Guid operation)
    {
        ProtectedSession.AssertSystemTestingAllowed();
        ProtectedState.RequireAdministrator();
        AssertCurrent(state, version);
        using var jobs = RegisteredJobSet.OpenForMaintenance(state);
        jobs.AssertClosedAdmissionsForNetworkMaintenance();
        var leaf = MachineEgressQuarantineIntent.Prefix + operation.ToString("N") + ".json";
        var (intent, digest) = Read(state, leaf);
        if (intent.Release.ToString("N") != version.Package.Release || intent.ManifestSHA256 != version.Package.ManifestHash)
            throw WfpNative.Contract("MachineQuarantineRecoveryArtifactDiffers");
        var policy = intent.Policy();
        var receipt = intent.Closed(digest);
        using var engine = WfpNative.Open();
        if (IsClosed(state, intent, receipt))
        {
            WfpNative.Transaction(engine, true, () => AssertAbsent(engine, policy));
            return;
        }

        WfpNative.Transaction(engine, false, () =>
        {
            AssertCurrent(state, version);
            jobs.AssertClosedAdmissionsForNetworkMaintenance();
            if (state.Read(leaf, 4096).SHA256 != digest) throw WfpNative.Contract("MachineQuarantineRecoveryIntentChanged");
            if (MachineEgressQuarantineReadback.ReadInTransaction(engine, policy) is { } objects)
            {
                intent.AssertPrepared(state.ReadOptional(intent.PreparedLeaf)?.Bytes, digest, objects);
                for (var role = 0; role < policy.FilterCount; role++)
                {
                    var key = policy.FilterKey(role);
                    WfpNative.Check(WfpNative.FwpmFilterDeleteByKey0(engine, in key), "DeleteExactMachineQuarantineFilter");
                }
                var keyOfLayer = policy.SubLayerKey;
                WfpNative.Check(WfpNative.FwpmSubLayerDeleteByKey0(engine, in keyOfLayer), "DeleteExactMachineQuarantineSubLayer");
            }
            return AssertAbsent(engine, policy);
        });
        WfpNative.Transaction(engine, true, () => AssertAbsent(engine, policy));
        state.WriteNew(intent.ClosedLeaf, receipt);
    }

    internal static void AssertNoPending(ProtectedState state)
    {
        foreach (var leaf in state.ListLeaves(MachineEgressQuarantineIntent.Prefix))
        {
            var (intent, digest) = Read(state, leaf);
            if (!IsClosed(state, intent, intent.Closed(digest)))
                throw WfpNative.Contract("MachineQuarantineRequiresExactRecovery");
        }
    }

    private static bool AssertAbsent(SafeWfpEngine engine, MachineEgressQuarantinePolicy policy) =>
        MachineEgressQuarantineReadback.ReadInTransaction(engine, policy) is null
            ? true : throw WfpNative.Contract("MachineQuarantineObjectsStillPresent");

    private static MachineEgressQuarantineObservation RequireObserved(MachineEgressQuarantineObservation? observation) =>
        observation ?? throw WfpNative.Contract("MachineQuarantineObjectsMissing");

    private static bool IsClosed(ProtectedState state, MachineEgressQuarantineIntent intent, byte[] expected)
    {
        var record = state.ReadOptional(intent.ClosedLeaf);
        if (record is null) return false;
        if (!record.Bytes.AsSpan().SequenceEqual(expected)) throw WfpNative.Contract("MachineQuarantineClosedReceiptDiffers");
        return true;
    }

    private static (MachineEgressQuarantineIntent Intent, string Digest) Read(ProtectedState state, string leaf)
    {
        var record = state.Read(leaf, 4096);
        return (MachineEgressQuarantineIntent.Decode(record.Bytes, Guid.ParseExact(state.InstallationId, "N"), leaf), record.SHA256);
    }

    private static void AssertCurrent(ProtectedState state, VerifiedVersion version)
    {
        version.AssertHeld(state);
        var pointer = CurrentPointer.Parse(state.Read("current.json", 4096), state.InstallationId);
        if (pointer.Release != version.Package.Release || pointer.ManifestSHA256 != version.Package.ManifestHash)
            throw WfpNative.Contract("MachineQuarantineRequiresCurrentVersion");
    }
}
