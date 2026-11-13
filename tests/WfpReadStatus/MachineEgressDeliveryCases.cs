using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using ProtectionLifecycle;

internal static class MachineEgressDeliveryCases
{
    internal static async Task RunAsync()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        foreach (var address in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
        foreach (var protocol in new[] { ProtocolType.Tcp, ProtocolType.Udp })
        foreach (var existing in new[] { true, false })
        {
            var flow = new MachineEgressFlow(address.AddressFamily, protocol, existing);
            var receipts = await ObserveLoopbackAsync(address, flow, deadline.Token);
            var baseline = receipts[0];
            var enforced = receipts[1];
            var restored = receipts[2];
            var operation = Guid.NewGuid();
            var objects = new MachineEgressObjects(100, 200, 300, "fixture", "fixture", "fixture");
            var filterId = flow.Family == AddressFamily.InterNetwork ? objects.V4Id : objects.V6Id;
            var attempts = new[]
            {
                Attempt(MachineEgressDeliveryPhase.Baseline, baseline, operation),
                Attempt(MachineEgressDeliveryPhase.Enforced, enforced, operation, objects),
                Attempt(MachineEgressDeliveryPhase.Restored, restored, operation)
            };
            var delivery = receipts.Select(r => new MachineEgressPacketEvidence(r.Marker, 0, 1, false, true, null)).ToArray();
            Require(MachineEgressDeliveryEvidence.Evaluate(flow, attempts, delivery) ==
                MachineEgressDeliveryVerdict.DeliveredWhileEnforced, "receiver-only positive observation refutes zero delivery");
            Require(MachineEgressDeliveryEvidence.Evaluate(flow, attempts, [delivery[1]]) ==
                MachineEgressDeliveryVerdict.DeliveredWhileEnforced, "positive observation survives missing controls");

            // Synthetic WFP and capture evidence exercises the verdict rules.
            // The actual loopback run above delivered every marker.
            var blocked = new[]
            {
                delivery[0] with { PhysicalPackets = 1, PhysicalObservationComplete = true },
                delivery[1] with { ReceiverReceipts = 0, PhysicalObservationComplete = true, WfpDropFilterId = filterId },
                delivery[2] with { PhysicalPackets = 1, PhysicalObservationComplete = true }
            };
            Require(MachineEgressDeliveryEvidence.Evaluate(flow, attempts, blocked) ==
                MachineEgressDeliveryVerdict.BlockObserved, "complete matched evidence");
            foreach (var uncertain in new[]
            {
                blocked[1] with { WfpDropFilterId = null },
                blocked[1] with { WfpDropFilterId = filterId + 1 },
                blocked[1] with { PhysicalObservationComplete = false },
                blocked[1] with { ReceiverObservationComplete = false },
                blocked[1] with { Marker = Guid.NewGuid() },
                blocked[1] with { Marker = baseline.Marker }
            })
                RequireUnknown(flow, attempts, [blocked[0], uncertain, blocked[2]]);

            RequireUnknown(flow, attempts, [blocked[0] with { ReceiverReceipts = 0 }, blocked[1], blocked[2]]);
            RequireUnknown(flow, attempts, [blocked[0], blocked[1], blocked[2] with { PhysicalPackets = 0 }]);
            RequireUnknown(flow, [attempts[0], attempts[1] with { ReachedSocketCall = false }, attempts[2]], blocked);
            foreach (var invalidAfter in new[]
            {
                attempts[1].PolicyAfter with { State = MachineEgressPolicyState.Unknown },
                attempts[1].PolicyAfter with { Operation = Guid.NewGuid() },
                attempts[1].PolicyAfter with { Objects = objects with { V4Id = 400 } },
                attempts[1].PolicyAfter with { Started = enforced.Finished - 1 }
            })
                RequireUnknown(flow, [attempts[0], attempts[1] with { PolicyAfter = invalidAfter }, attempts[2]], blocked);
            RequireUnknown(flow, [attempts[0], attempts[1] with { Started = attempts[0].Finished }, attempts[2]], blocked);
            RequireUnknown(flow, [attempts[0] with
            {
                PolicyAfter = attempts[0].PolicyAfter with { Finished = attempts[1].PolicyBefore.Started + 1 }
            }, attempts[1], attempts[2]], blocked);
            RequireUnknown(flow, [attempts[0], attempts[1], attempts[2] with { SocketId = attempts[1].SocketId }], blocked);
            RequireUnknown(flow with { Existing = !flow.Existing }, attempts, blocked);
            Require(MachineEgressDeliveryEvidence.Evaluate(flow, attempts, [blocked[0],
                blocked[1] with { PhysicalPackets = 1 }, blocked[2]]) ==
                MachineEgressDeliveryVerdict.DeliveredWhileEnforced, "physical observation refutes zero delivery");
        }
        Console.WriteLine("PASS 8 dual-stack loopback delivery controls and machine egress verdict cases");
    }

    private static MachineEgressAttempt Attempt(MachineEgressDeliveryPhase phase, Receipt receipt,
        Guid operation, MachineEgressObjects? objects = null)
    {
        var state = objects.HasValue ? MachineEgressPolicyState.ExactBlock : MachineEgressPolicyState.Absent;
        return new(phase, receipt.Marker, receipt.SocketId, receipt.Started, receipt.Finished, true,
            new(operation, state, receipt.Started - 1, receipt.Started, objects),
            new(operation, state, receipt.Finished, receipt.Finished + 1, objects));
    }

    private static async Task<Receipt[]> ObserveLoopbackAsync(IPAddress address, MachineEgressFlow flow, CancellationToken token)
    {
        var stream = flow.Protocol == ProtocolType.Tcp;
        var type = stream ? SocketType.Stream : SocketType.Dgram;
        using var receiver = new Socket(flow.Family, type, flow.Protocol) { ExclusiveAddressUse = true };
        if (flow.Family == AddressFamily.InterNetworkV6) receiver.DualMode = false;
        receiver.Bind(new IPEndPoint(address, 0));
        if (stream) receiver.Listen(3);
        using var first = new Socket(flow.Family, type, flow.Protocol);
        using var second = flow.Existing ? null : new Socket(flow.Family, type, flow.Protocol);
        using var last = new Socket(flow.Family, type, flow.Protocol);

        await first.ConnectAsync(receiver.LocalEndPoint!, token);
        using var firstPeer = stream ? await receiver.AcceptAsync(token) : null;
        var firstId = Guid.NewGuid();
        var baseline = await Observe(first, firstPeer, firstId);
        Receipt enforced;
        if (second is null)
        {
            enforced = await Observe(first, firstPeer, firstId);
        }
        else
        {
            await second.ConnectAsync(receiver.LocalEndPoint!, token);
            using var secondPeer = stream ? await receiver.AcceptAsync(token) : null;
            enforced = await Observe(second, secondPeer, Guid.NewGuid());
        }
        await last.ConnectAsync(receiver.LocalEndPoint!, token);
        using var lastPeer = stream ? await receiver.AcceptAsync(token) : null;
        var restored = await Observe(last, lastPeer, Guid.NewGuid());
        return [baseline, enforced, restored];

        async Task<Receipt> Observe(Socket sender, Socket? accepted, Guid socketId)
        {
            var marker = Guid.NewGuid();
            var bytes = marker.ToByteArray();
            var read = new byte[17];
            var started = Stopwatch.GetTimestamp();
            if (accepted is not null)
            {
                using var output = new NetworkStream(sender, ownsSocket: false);
                using var input = new NetworkStream(accepted, ownsSocket: false);
                await output.WriteAsync(bytes, token);
                await input.ReadExactlyAsync(read.AsMemory(0, 16), token);
            }
            else
            {
                Require(await sender.SendAsync(bytes, SocketFlags.None, token) == bytes.Length, "complete datagram submitted");
                var observed = await receiver.ReceiveFromAsync(read, SocketFlags.None,
                    new IPEndPoint(address, 0), token);
                Require(observed.ReceivedBytes == bytes.Length && Equals(observed.RemoteEndPoint, sender.LocalEndPoint),
                    "independent datagram receipt binds sender");
            }
            Require(read.AsSpan(0, 16).SequenceEqual(bytes), "receiver observed exact marker");
            return new(marker, socketId, started, Stopwatch.GetTimestamp());
        }
    }

    private static void RequireUnknown(MachineEgressFlow flow, MachineEgressAttempt[] attempts, MachineEgressPacketEvidence[] observations) =>
        Require(MachineEgressDeliveryEvidence.Evaluate(flow, attempts, observations) == MachineEgressDeliveryVerdict.Unknown,
            "incomplete or mismatched evidence stays unknown");

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException("Machine egress delivery: " + message);
    }

    private sealed record Receipt(Guid Marker, Guid SocketId, long Started, long Finished);
}
