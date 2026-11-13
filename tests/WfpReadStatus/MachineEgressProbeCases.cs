using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using ProtectionLifecycle;

internal static class MachineEgressProbeCases
{
    internal static int ReadLayers()
    {
        var layers = new List<object>();
        try
        {
            using var engine = WfpNative.Open();
            foreach (var family in new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 })
            {
                var (layerId, interfaceType, remoteAddressType) = MachineEgressProbePolicy.ReadPacketLayer(engine, family);
                layers.Add(new { Family = family.ToString(), LayerId = layerId, InterfaceType = interfaceType, RemoteAddressType = remoteAddressType });
            }
            Console.WriteLine(JsonSerializer.Serialize(new { Scope = "READ_ONLY_MACHINE_EGRESS_LAYER_FIELDS", Layers = layers }));
            return 0;
        }
        catch (Exception error)
        {
            Console.WriteLine(JsonSerializer.Serialize(new { Scope = "READ_ONLY_MACHINE_EGRESS_LAYER_FIELDS", Layers = layers,
                Failures = WfpNative.Describe(error) }));
            return 2;
        }
    }

    internal static void Run()
    {
        var layerKey = Guid.NewGuid();
        var v4Key = Guid.NewGuid();
        var v6Key = Guid.NewGuid();
        var v4 = IPAddress.Parse("192.0.2.130");
        var v6 = IPAddress.Parse("2001:db8::5");
        var policy = new MachineEgressProbePolicy(layerKey, v4Key, v6Key, 18, v4, 22, v6);
        using var arena = new WfpNative.Arena();
        var layer = policy.DefineSubLayer(arena);
        Require(policy.MatchesSubLayer(layer), "owned persistent sublayer");
        var alteredLayer = layer;
        alteredLayer.Flags = 0;
        Require(!policy.MatchesSubLayer(alteredLayer), "nonpersistent sublayer");

        var ipv4 = policy.DefineFilter(AddressFamily.InterNetwork, arena);
        var ipv6 = policy.DefineFilter(AddressFamily.InterNetworkV6, arena);
        VerifyPolicy(policy, AddressFamily.InterNetwork, ipv4, 18, v4.GetAddressBytes(), arena);
        VerifyPolicy(policy, AddressFamily.InterNetworkV6, ipv6, 22, v6.GetAddressBytes(), arena);
        Require(!policy.MatchesFilter(AddressFamily.InterNetwork, ipv6), "cross-family rule");
        var different = new MachineEgressProbePolicy(layerKey, v4Key, v6Key, 18, v4, 23, v6);
        Require(!different.MatchesSubLayer(layer) && !different.MatchesFilter(AddressFamily.InterNetwork, ipv4),
            "marker binds the whole dual-stack plan, including the other interface");

        foreach (var bad in new[] { "0.0.0.0", "127.0.0.2", "169.254.1.2", "224.0.0.1", "255.255.255.255", "::ffff:192.0.2.130" })
            Reject(() => _ = new MachineEgressProbePolicy(layerKey, v4Key, v6Key, 18, IPAddress.Parse(bad), 22, v6));
        foreach (var bad in new[] { "::", "::1", "ff02::1", "fe80::42", "2001:db8::5%22", "::ffff:192.0.2.130", "192.0.2.130" })
            Reject(() => _ = new MachineEgressProbePolicy(layerKey, v4Key, v6Key, 18, v4, 22, IPAddress.Parse(bad)));
        Reject(() => _ = new MachineEgressProbePolicy(layerKey, layerKey, v6Key, 18, v4, 22, v6));
        Reject(() => _ = new MachineEgressProbePolicy(layerKey, Guid.Empty, v6Key, 18, v4, 22, v6));
        Reject(() => _ = new MachineEgressProbePolicy(layerKey, v4Key, v6Key, 18, v4, 0, v6));
        Console.WriteLine("PASS dual-stack machine egress probe policy and drift checks (managed only)");
    }

    private static void VerifyPolicy(MachineEgressProbePolicy policy, AddressFamily family, WfpNative.Filter filter,
        uint expectedIndex, byte[] address, WfpNative.Arena arena)
    {
        var expectedLayer = family == AddressFamily.InterNetwork
            ? new Guid("1e5c9fae-8a84-4135-a331-950b54229ecd") : new Guid("a3b3ab6b-3564-488c-9117-f34e82142763");
        Require(filter.Layer == expectedLayer && filter.Action.Type == WfpNative.Block, "outbound packet block layer");
        Require(policy.MatchesFilter(family, filter), "exact block matches");

        var adapter = Marshal.PtrToStructure<WfpNative.Condition>(filter.Conditions);
        var remote = Marshal.PtrToStructure<WfpNative.Condition>(filter.Conditions + Marshal.SizeOf<WfpNative.Condition>());
        Require(adapter.Value.Type == WfpNative.UInt32 && adapter.Value.U32 == expectedIndex, "exact interface index");
        if (family == AddressFamily.InterNetwork)
            Require(remote.Value.Type == WfpNative.UInt32 && remote.Value.U32 == 0xc0000282, "IPv4 WFP host-order scalar");
        else
            Require(remote.Value.Type == 11 && WfpNative.BlobMatches(new() { Size = 16, Data = remote.Value.Pointer }, address),
                "IPv6 exact 16-byte destination");

        var changed = filter;
        changed.Flags |= WfpNative.Indexed;
        changed.Conditions = arena.Conditions(new[] { remote, adapter });
        Require(policy.MatchesFilter(family, changed), "BFE indexed flag and condition reordering");
        changed.Flags |= 0x20;
        Require(!policy.MatchesFilter(family, changed), "disabled rule");
        changed = filter;
        changed.ConditionCount = 1;
        Require(!policy.MatchesFilter(family, changed), "widened rule");
        changed = filter;
        changed.Action.Type = 0x1002;
        Require(!policy.MatchesFilter(family, changed), "permit action");
        changed = filter;
        changed.Layer = WfpNative.ConnectV4;
        Require(!policy.MatchesFilter(family, changed), "ALE rule substitution");
        changed = filter;
        adapter.Value.U32++;
        changed.Conditions = arena.Conditions(new[] { adapter, remote });
        Require(!policy.MatchesFilter(family, changed), "interface drift");
        adapter.Value.U32--;
        remote.Match = WfpNative.NotEqual;
        changed.Conditions = arena.Conditions(new[] { adapter, remote });
        Require(!policy.MatchesFilter(family, changed), "inverted destination");
        remote.Match = WfpNative.Equal;
        remote.Value = family == AddressFamily.InterNetwork
            ? new() { Type = WfpNative.UInt32, U32 = 0xc0000283 }
            : new() { Type = 11, Pointer = arena.Bytes(IPAddress.Parse("2001:db8::6").GetAddressBytes()).Data };
        changed.Conditions = arena.Conditions(new[] { adapter, remote });
        Require(!policy.MatchesFilter(family, changed), "destination drift");
    }

    private static void Reject(Action create)
    {
        try { create(); }
        catch (ArgumentException) { return; }
        throw new InvalidOperationException("Unsafe machine egress probe scope accepted");
    }

    private static void Require(bool accepted, string reason)
    {
        if (!accepted) throw new InvalidOperationException("Machine egress probe policy: " + reason);
    }
}
