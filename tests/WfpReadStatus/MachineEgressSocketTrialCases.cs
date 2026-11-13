using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using ProtectionLifecycle;

internal static class MachineEgressSocketTrialCases
{
    internal static void Run()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var receivers = new LoopbackCollectors();
        var v4 = receivers.Endpoint(IPAddress.Loopback, (uint)NetworkInterface.LoopbackInterfaceIndex);
        var v6 = receivers.Endpoint(IPAddress.IPv6Loopback, (uint)NetworkInterface.IPv6LoopbackInterfaceIndex);
        foreach (var endpoint in new[] { v4, v6 })
        {
            var route = MachineEgressRouteReader.Read(endpoint);
            Require(route.InterfaceIndex == endpoint.InterfaceIndex && route.InterfaceLuid != 0 &&
                route.Source.Equals(endpoint.Source) && route.Prefix.Equals(endpoint.Receiver) &&
                route.PrefixLength == (endpoint.Source.AddressFamily == AddressFamily.InterNetwork ? 32 : 128));
            try
            {
                _ = MachineEgressRouteReader.Read(endpoint with { InterfaceIndex = uint.MaxValue });
                throw new Exception("Unknown interface accepted");
            }
            catch (System.ComponentModel.Win32Exception) { }
        }
        try
        {
            _ = MachineEgressRouteReader.Read(v4 with { Source = IPAddress.Parse("192.0.2.5") });
            throw new Exception("Unassigned source accepted");
        }
        catch (System.ComponentModel.Win32Exception) { }
        using var trial = new MachineEgressSocketTrial(v4, v6, receivers);
        var intent = new MachineEgressProbeIntent(1, Guid.NewGuid(), Guid.NewGuid(), new string('A', 64),
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), v4.InterfaceIndex, v4.Receiver.ToString(),
            v6.InterfaceIndex, v6.Receiver.ToString());
        trial.AssertPlan(intent);
        try
        {
            trial.AssertPlan(intent with { V6Interface = v6.InterfaceIndex + 1 });
            throw new Exception("Policy interface drift accepted");
        }
        catch (InvalidDataException) { }

        var before = new MachineEgressPolicyObservation(intent.SubLayerKey, MachineEgressPolicyState.Absent, 0, 1);
        var baseline = trial.Measure(MachineEgressDeliveryPhase.Baseline, before, deadline.Token);
        var enforced = trial.Measure(MachineEgressDeliveryPhase.Enforced, before, deadline.Token);
        var restored = trial.Measure(MachineEgressDeliveryPhase.Restored, before, deadline.Token);
        var final = trial.Finish(deadline.Token);
        Require(final.Count == 24 && final.All(e => e.ReceiverReceipts == 1 && !e.PhysicalObservationComplete));
        foreach (var flow in MachineEgressDeliveryRun.Flows)
        {
            var first = baseline.Single(s => s.Flow == flow).Socket;
            var second = enforced.Single(s => s.Flow == flow).Socket;
            var third = restored.Single(s => s.Flow == flow).Socket;
            Require((first.SocketId == second.SocketId) == flow.Existing);
            Require(third.SocketId != first.SocketId && third.SocketId != second.SocketId);
        }
        Console.WriteLine("PASS actual Windows socket trial with 24 independent loopback receipts");
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidDataException("Machine egress socket trial fixture mismatch");
    }

    private sealed class LoopbackCollectors : IMachineEgressCollectors, IDisposable
    {
        private readonly Dictionary<(AddressFamily Family, ProtocolType Protocol), Socket> sockets = new();
        private readonly Dictionary<IPEndPoint, Socket> peers = new();
        private readonly List<MachineEgressPacketEvidence> receipts = new();
        private MachineEgressTransmission? expected;

        internal MachineEgressTrialEndpoint Endpoint(IPAddress address, uint index)
        {
            return new(address, address, index, Bind(ProtocolType.Tcp), Bind(ProtocolType.Udp));

            ushort Bind(ProtocolType protocol)
            {
                var tcp = protocol == ProtocolType.Tcp;
                var socket = new Socket(address.AddressFamily, tcp ? SocketType.Stream : SocketType.Dgram, protocol);
                sockets.Add((address.AddressFamily, protocol), socket);
                socket.ExclusiveAddressUse = true;
                if (address.AddressFamily == AddressFamily.InterNetworkV6) socket.DualMode = false;
                socket.Bind(new IPEndPoint(address, 0));
                if (tcp) socket.Listen(8);
                return (ushort)((IPEndPoint)socket.LocalEndPoint!).Port;
            }
        }

        public void Expect(MachineEgressTransmission transmission, CancellationToken cancellation)
        {
            Require(expected is null && transmission.Source.Port > 0 && transmission.Route.InterfaceLuid != 0 &&
                transmission.Route.Source.Equals(transmission.Source.Address));
            expected = transmission;
        }

        public MachineEgressPacketEvidence Read(Guid marker, MachineEgressSendResult send, CancellationToken cancellation)
        {
            var transmission = expected ?? throw new InvalidDataException("Expected tuple missing");
            expected = null;
            Require(transmission.Marker == marker && send.Attempt.Marker == marker &&
                send.Attempt.ReachedSocketCall && send.Error is null && !send.TimedOut);
            var listener = sockets[(transmission.Flow.Family, transmission.Flow.Protocol)];
            Require(Equals(listener.LocalEndPoint, transmission.Destination));
            var read = new byte[17];
            if (transmission.Flow.Protocol == ProtocolType.Tcp)
            {
                var reuse = transmission.Phase == MachineEgressDeliveryPhase.Enforced && transmission.Flow.Existing;
                if (!reuse)
                {
                    var peer = listener.AcceptAsync(cancellation).AsTask().GetAwaiter().GetResult();
                    // Keep only the baseline peer for reuse in the enforced phase.
                    if (transmission.Phase == MachineEgressDeliveryPhase.Baseline && transmission.Flow.Existing)
                        peers.Add(transmission.Source, peer);
                    else
                    {
                        using (peer) ReadTcp(peer);
                        return Record();
                    }
                }
                ReadTcp(peers[transmission.Source]);
            }
            else
            {
                var packet = listener.ReceiveFromAsync(read.AsMemory(), SocketFlags.None,
                    new IPEndPoint(transmission.Source.Address, 0), cancellation).AsTask().GetAwaiter().GetResult();
                Require(packet.ReceivedBytes == 16 && Equals(packet.RemoteEndPoint, transmission.Source));
            }
            return Record();

            void ReadTcp(Socket peer)
            {
                Require(Equals(peer.RemoteEndPoint, transmission.Source));
                using var stream = new NetworkStream(peer, ownsSocket: false);
                stream.ReadExactlyAsync(read.AsMemory(0, 16), cancellation).AsTask().GetAwaiter().GetResult();
            }

            MachineEgressPacketEvidence Record()
            {
                Require(read.AsSpan(0, 16).SequenceEqual(marker.ToByteArray()));
                var evidence = new MachineEgressPacketEvidence(marker, 0, 1, false, true, null);
                receipts.Add(evidence);
                return evidence;
            }
        }

        public IReadOnlyList<MachineEgressPacketEvidence> Finish(CancellationToken cancellation) => receipts.ToArray();

        public void Dispose()
        {
            foreach (var peer in peers.Values) peer.Dispose();
            foreach (var socket in sockets.Values) socket.Dispose();
        }
    }
}
