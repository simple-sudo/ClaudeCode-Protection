using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ProtectionLifecycle;

internal static class MachineEgressQuarantineCases
{
    internal static void Run()
    {
        var keys = Enumerable.Range(0, 6).Select(_ => Guid.NewGuid()).ToArray();
        var policy = new MachineEgressQuarantinePolicy(keys[0], keys[1], keys[2], keys[3], keys[4], keys[5]);
        var foreign = new MachineEgressQuarantinePolicy(Guid.NewGuid(), keys[1], keys[2], keys[3], keys[4], keys[5]);
        using var arena = new WfpNative.Arena();
        var subLayer = policy.DefineSubLayer(arena);
        Require(policy.MatchesSubLayer(subLayer) && !foreign.MatchesSubLayer(subLayer));
        var layers = new[]
        {
            new Guid("1e5c9fae-8a84-4135-a331-950b54229ecd"),
            new Guid("a3b3ab6b-3564-488c-9117-f34e82142763"),
            new Guid("a82acc24-4ee1-4ee1-b465-fd1d25cb10a4"),
            new Guid("7b964818-19c7-493a-b71f-832c3684d28c")
        };
        Require(policy.FilterCount == layers.Length);
        for (var role = 0; role < layers.Length; role++)
        {
            var filter = policy.DefineFilter(role, arena);
            Require(filter.Layer == layers[role] && filter.Key == keys[role + 2] &&
                policy.MatchesFilter(role, filter) && !foreign.MatchesFilter(role, filter));
            filter.Flags |= WfpNative.Indexed;
            Require(policy.MatchesFilter(role, filter));
            var drifted = filter;
            drifted.Flags |= 0x20;
            Require(!policy.MatchesFilter(role, drifted));
            drifted = filter;
            drifted.Action.Type = 0x1002;
            Require(!policy.MatchesFilter(role, drifted));
            drifted = filter;
            drifted.Layer = WfpNative.ConnectV4;
            Require(!policy.MatchesFilter(role, drifted));
            if (role < 2)
            {
                Require(filter.ConditionCount == 1);
                var loopback = Marshal.PtrToStructure<WfpNative.Condition>(filter.Conditions);
                Require(loopback.Field == new Guid("632ce23b-5167-435c-86d7-e903684aa80c") &&
                    loopback.Match == 8 && loopback.Value.Type == WfpNative.UInt32 && loopback.Value.U32 == 1);
                loopback.Value.U32 = 3;
                drifted = filter;
                drifted.Conditions = arena.Conditions([loopback]);
                Require(!policy.MatchesFilter(role, drifted));
            }
            else
            {
                Require(filter.ConditionCount == 0 && filter.Conditions == IntPtr.Zero);
                drifted = filter;
                drifted.ConditionCount = 1;
                drifted.Conditions = arena.Conditions([new() { Field = WfpNative.RemoteAddress }]);
                Require(!policy.MatchesFilter(role, drifted));
            }
        }
        VerifyRecords(keys);
        Console.WriteLine("PASS dual-stack machine quarantine, exact readback and recovery records (managed only)");
    }

    private static void VerifyRecords(Guid[] keys)
    {
        var intent = new MachineEgressQuarantineIntent(1, keys[0], Guid.NewGuid(), new string('A', 64),
            keys[1], keys[2], keys[3], keys[4], keys[5]);
        var bytes = intent.Encode();
        var digest = Convert.ToHexString(SHA256.HashData(bytes));
        Require(MachineEgressQuarantineIntent.Decode(bytes, keys[0], intent.Leaf) == intent);
        Refuse(() => _ = MachineEgressQuarantineIntent.Decode(bytes, Guid.NewGuid(), intent.Leaf));
        Refuse(() => _ = MachineEgressQuarantineIntent.Decode(bytes, keys[0], intent.Leaf + ".json"));
        var repeatedKey = intent with { ForwardV6 = intent.ForwardV4 };
        Refuse(() => _ = MachineEgressQuarantineIntent.Decode(repeatedKey.Encode(), keys[0], intent.Leaf));

        var observation = new MachineEgressQuarantineObservation(500, [1, 2, 3, 4],
            [digest, digest, digest, digest, digest]);
        var prepared = intent.Prepared(digest, observation);
        intent.AssertPrepared(prepared, digest, observation);
        Refuse(() => intent.AssertPrepared(null, digest, observation));
        Refuse(() => intent.AssertPrepared(prepared, digest, observation with { FilterIds = [1, 2, 3] }));
        Refuse(() => intent.AssertPrepared(prepared, digest, observation with { FilterIds = [2, 1, 3, 4] }));
        Refuse(() => intent.AssertPrepared(prepared, digest, observation with { SubLayerWeight = 501 }));
        Refuse(() => intent.AssertPrepared(prepared, digest, observation with
        {
            SecurityHashes = [digest, digest, digest, digest, new string('B', 64)]
        }));
        Require(!intent.Closed(digest).AsSpan().SequenceEqual(intent.Closed(new string('B', 64))));
        Require(!intent.Closed(digest).AsSpan().SequenceEqual(prepared));
    }

    private static void Refuse(Action action)
    {
        try { action(); }
        catch (Exception error) when (error is InvalidDataException or ArgumentException) { return; }
        throw new InvalidDataException("Machine egress quarantine accepted mismatched ownership evidence");
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidDataException("Machine egress quarantine fixture mismatch");
    }
}
