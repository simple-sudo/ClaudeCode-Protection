using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using ProtectionLifecycle;

internal static class MachineProxyEndpointCases
{
    internal static void Run()
    {
        VerifyStableSelection();
        var generation = Guid.NewGuid();
        var identity = new ProxyProcessIdentity(55, 123456, new string('A', 64), "fixture-file");
        var route = new string('B', 64);
        var v4 = new MachineProxyEndpoint("1.1.1.1", 443, ProtocolType.Tcp, 42);
        var v6 = new MachineProxyEndpoint("2606:4700:4700::1111", 443, ProtocolType.Udp, 43);
        var current = new MachineProxyRouteBinding(identity, route, 100, 100);
        MachineProxyEndpointLease NewLease() => new(generation, current, [v4, v6], 101, 200);
        var lease = NewLease();
        Require(lease.Allows(generation, current, v4, 101));
        Require(lease.Allows(generation, current, v6, 199));
        foreach (var mismatch in new[]
        {
            v4 with { Address = "1.0.0.1" },
            v4 with { Port = 80 },
            v4 with { Protocol = ProtocolType.Udp },
            v4 with { InterfaceLuid = 43 }
        })
            Require(!lease.Allows(generation, current, mismatch, 199));
        Require(!lease.Allows(generation, current, v4, 200));
        Require(!lease.Allows(generation, current, v4, 199));

        foreach (var replaced in new ProxyProcessIdentity?[]
        {
            null, identity with { CreatedFileTime = 123457 }, identity with { Pid = 56 },
            identity with { DiskImageSHA256 = route }, identity with { FileIdentity = "replacement-file" }
        })
        {
            lease = NewLease();
            Require(!lease.Allows(generation, replaced is null ? null : current with { Process = replaced }, v4, 101));
            Require(!lease.Allows(generation, current, v4, 102));
        }
        lease = NewLease();
        Require(!lease.Allows(Guid.NewGuid(), current, v4, 101));
        Require(!lease.Allows(generation, current, v4, 102));
        lease = NewLease();
        Require(!lease.Allows(generation, null, v4, 101));
        Require(!lease.Allows(generation, current, v4, 102));
        lease = NewLease();
        Require(lease.Allows(generation, current, v4, 102));
        Require(!lease.Allows(generation, current, v4, 101));
        Require(!lease.Allows(generation, current, v4, 103));
        lease = NewLease();
        Require(!lease.Allows(generation, current with { Digest = identity.DiskImageSHA256 }, v4, 101));
        Require(!lease.Allows(generation, current, v4, 102));
        lease = NewLease();
        Require(!lease.Allows(generation, current with { Finished = 102 }, v4, 101));
        lease = NewLease();
        Require(lease.Allows(generation, current with { Finished = 110 }, v4, 110));
        Require(!lease.Allows(generation, current, v4, 111));
        lease = new(generation, current, [v4], 101, 101 + 5 * Stopwatch.Frequency);
        Require(!lease.Allows(generation, current, v4, 101 + 3 * Stopwatch.Frequency));

        foreach (var bad in new[]
        {
            v4 with { Address = "localhost" }, v4 with { Address = "127.0.0.1" },
            v4 with { Address = "::ffff:1.1.1.1" }, v6 with { Address = v6.Address + "%1" },
            v4 with { Port = 0 }, v4 with { InterfaceLuid = 0 }, v4 with { Protocol = ProtocolType.Icmp }
        })
            Refuse(() => _ = new MachineProxyEndpointLease(generation, current, [bad], 100, 200));
        Refuse(() => _ = new MachineProxyEndpointLease(generation, current, [v4, v4], 100, 200));
        Refuse(() => _ = new MachineProxyEndpointLease(generation, current, [v4], 100, 101 + 30 * Stopwatch.Frequency));
        Refuse(() => _ = new MachineProxyEndpointLease(generation, current with { Finished = 101 }, [v4], 100, 200));
        Console.WriteLine("PASS exact machine proxy endpoint lease binding and revocation (managed only)");
    }

    private static void VerifyStableSelection()
    {
        var config = "{\"mode\":\"global\"}"u8.ToArray();
        byte[] Inventory(string selected, int delay, string fallback = "REJECT") => JsonSerializer.SerializeToUtf8Bytes(new
        {
            proxies = new Dictionary<string, object>
            {
                ["GLOBAL"] = new Dictionary<string, object>
                {
                    ["name"] = "GLOBAL", ["type"] = "Selector", ["now"] = selected, ["all"] = new[] { "A", "B" },
                    ["emptyFallback"] = fallback, ["dialer-proxy"] = ""
                },
                ["A"] = new Dictionary<string, object> { ["name"] = "A", ["type"] = "Vless", ["dialer-proxy"] = "", ["delay"] = delay },
                ["B"] = new Dictionary<string, object> { ["name"] = "B", ["type"] = "Trojan", ["dialer-proxy"] = "" },
                ["REJECT"] = new Dictionary<string, object> { ["name"] = "REJECT", ["type"] = "Reject", ["dialer-proxy"] = "" }
            }
        });
        var first = Inventory("A", 1);
        var stable = ProxyRouteObservation.EvaluateStableSelection(config, first, Inventory("A", 9), config);
        Require(stable.AllowsRoutePrecheck && stable.SelectionDigest is { Length: 64 });
        Require(!JsonSerializer.Serialize(stable).Contains(stable.SelectionDigest!, StringComparison.Ordinal));
        var changed = ProxyRouteObservation.EvaluateStableSelection(config, first, Inventory("B", 1), config);
        Require(!changed.AllowsRoutePrecheck && changed.SelectionDigest is null &&
            changed.Status == "CONTROLLER_SELECTION_CHANGED_DURING_SNAPSHOT");
        Require(!ProxyRouteObservation.EvaluateStableSelection(config, first, Inventory("A", 1, "DIRECT"), config).AllowsRoutePrecheck);
        Require(!ProxyRouteObservation.EvaluateStableSelection(config, first, first,
            Encoding.UTF8.GetBytes("{\"mode\":\"rule\"}")).AllowsRoutePrecheck);
        Require(!ProxyRouteObservation.EvaluateStableSelection(config, first, [], config).AllowsRoutePrecheck);
    }

    private static void Refuse(Action action)
    {
        try { action(); }
        catch (ArgumentException) { return; }
        throw new InvalidDataException("Machine proxy endpoint lease accepted invalid scope");
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidDataException("Machine proxy endpoint lease fixture mismatch");
    }
}
