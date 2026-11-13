using System.Net;
using System.Net.NetworkInformation;
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
        await VerifyFailedSenderAsync(deadline.Token);
        Console.WriteLine("PASS 8 dual-stack loopback delivery controls and machine egress verdict cases");
    }

    private static async Task VerifyFailedSenderAsync(CancellationToken token)
    {
        using var reserved = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            ExclusiveAddressUse = true
        };
        reserved.Bind(new IPEndPoint(IPAddress.Loopback, 0)); // Keep the port reserved without listening.
        using var sender = new MachineEgressSender(IPAddress.Loopback, (IPEndPoint)reserved.LocalEndPoint!,
            (uint)NetworkInterface.LoopbackInterfaceIndex, ProtocolType.Tcp);
        var local = sender.Local;
        var result = await sender.SendAsync(Guid.NewGuid(), token);
        Require(result.Error == SocketError.ConnectionRefused && !result.TimedOut && result.Attempt.ReachedSocketCall &&
            Equals(local, sender.Local), "connection refusal is recorded independently of delivery");
        try
        {
            _ = await sender.SendAsync(Guid.NewGuid(), token);
            throw new InvalidDataException("Failed sender reused");
        }
        catch (InvalidOperationException error) when (error.Message == "MachineEgressFailedSocketCannotBeReused") { }
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
        var destination = (IPEndPoint)receiver.LocalEndPoint!;
        var index = checked((uint)(flow.Family == AddressFamily.InterNetwork
            ? NetworkInterface.LoopbackInterfaceIndex : NetworkInterface.IPv6LoopbackInterfaceIndex));
        using var first = new MachineEgressSender(address, destination, index, flow.Protocol);
        using var second = flow.Existing ? null : new MachineEgressSender(address, destination, index, flow.Protocol);
        using var last = new MachineEgressSender(address, destination, index, flow.Protocol);

        var firstLocal = first.Local;
        var (baseline, firstPeer) = await Observe(first, firstLocal, null);
        using var heldFirstPeer = firstPeer;
        Receipt enforced;
        if (second is null)
        {
            (enforced, _) = await Observe(first, firstLocal, heldFirstPeer);
        }
        else
        {
            var (receipt, peer) = await Observe(second, second.Local, null);
            using var heldSecondPeer = peer;
            enforced = receipt;
        }
        var (restored, lastPeer) = await Observe(last, last.Local, null);
        using var heldLastPeer = lastPeer;
        return [baseline, enforced, restored];

        async Task<(Receipt Receipt, Socket? Peer)> Observe(MachineEgressSender sender, IPEndPoint local, Socket? accepted)
        {
            var marker = Guid.NewGuid();
            var sent = await sender.SendAsync(marker, token);
            Require(sent.Error is null && !sent.TimedOut && sent.Attempt.ReachedSocketCall && Equals(sender.Local, local),
                "bounded sender completed using its original tuple");
            var read = new byte[17];
            var newPeer = stream && accepted is null ? await receiver.AcceptAsync(token) : null;
            try
            {
                var peer = accepted ?? newPeer;
                if (peer is not null)
                {
                    Require(Equals(peer.RemoteEndPoint, local), "independent TCP receipt binds pre-connect tuple");
                    using var input = new NetworkStream(peer, ownsSocket: false);
                    await input.ReadExactlyAsync(read.AsMemory(0, 16), token);
                }
                else
                {
                    var observed = await receiver.ReceiveFromAsync(read, SocketFlags.None, new IPEndPoint(address, 0), token);
                    Require(observed.ReceivedBytes == 16 && Equals(observed.RemoteEndPoint, local),
                        "independent datagram receipt binds pre-send tuple");
                }
                Require(read.AsSpan(0, 16).SequenceEqual(marker.ToByteArray()), "receiver observed exact marker");
                var attempt = sent.Attempt;
                return (new(marker, attempt.SocketId, attempt.Started, attempt.Finished), newPeer);
            }
            catch
            {
                newPeer?.Dispose();
                throw;
            }
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
