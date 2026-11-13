using System.Diagnostics;
using System.Net.Sockets;
using ProtectionLifecycle;

internal static class MachineProxyEndpointCases
{
    internal static void Run()
    {
        var generation = Guid.NewGuid();
        var identity = new ProxyProcessIdentity(55, 123456, new string('A', 64), "fixture-file");
        var route = new string('B', 64);
        var v4 = new MachineProxyEndpoint("1.1.1.1", 443, ProtocolType.Tcp, 42);
        var v6 = new MachineProxyEndpoint("2606:4700:4700::1111", 443, ProtocolType.Udp, 43);
        MachineProxyEndpointLease NewLease() => new(generation, identity, route, [v4, v6], 100, 200);
        var lease = NewLease();
        Require(lease.Allows(generation, identity, route, v4, 100));
        Require(lease.Allows(generation, identity, route, v6, 199));
        foreach (var mismatch in new[]
        {
            v4 with { Address = "1.0.0.1" },
            v4 with { Port = 80 },
            v4 with { Protocol = ProtocolType.Udp },
            v4 with { InterfaceLuid = 43 }
        })
            Require(!lease.Allows(generation, identity, route, mismatch, 199));
        Require(!lease.Allows(generation, identity, route, v4, 200));
        Require(!lease.Allows(generation, identity, route, v4, 199));

        foreach (var replaced in new ProxyProcessIdentity?[]
        {
            null, identity with { CreatedFileTime = 123457 }, identity with { Pid = 56 },
            identity with { DiskImageSHA256 = route }, identity with { FileIdentity = "replacement-file" }
        })
        {
            lease = NewLease();
            Require(!lease.Allows(generation, replaced, route, v4, 101));
            Require(!lease.Allows(generation, identity, route, v4, 102));
        }
        lease = NewLease();
        Require(!lease.Allows(Guid.NewGuid(), identity, route, v4, 101));
        Require(!lease.Allows(generation, identity, route, v4, 102));
        lease = NewLease();
        Require(!lease.Allows(generation, identity, null, v4, 101));
        Require(!lease.Allows(generation, identity, route, v4, 102));
        lease = NewLease();
        Require(lease.Allows(generation, identity, route, v4, 102));
        Require(!lease.Allows(generation, identity, route, v4, 101));
        Require(!lease.Allows(generation, identity, route, v4, 103));

        foreach (var bad in new[]
        {
            v4 with { Address = "localhost" }, v4 with { Address = "127.0.0.1" },
            v4 with { Address = "::ffff:1.1.1.1" }, v6 with { Address = v6.Address + "%1" },
            v4 with { Port = 0 }, v4 with { InterfaceLuid = 0 }, v4 with { Protocol = ProtocolType.Icmp }
        })
            Refuse(() => _ = new MachineProxyEndpointLease(generation, identity, route, [bad], 100, 200));
        Refuse(() => _ = new MachineProxyEndpointLease(generation, identity, route, [v4, v4], 100, 200));
        Refuse(() => _ = new MachineProxyEndpointLease(generation, identity, route, [v4], 100, 101 + 30 * Stopwatch.Frequency));
        Console.WriteLine("PASS exact machine proxy endpoint lease binding and revocation (managed only)");
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
