using System.Net.Sockets;

namespace ProtectionLifecycle;

internal sealed record MachineEgressSocketAttempt(Guid Marker, Guid SocketId, long Started, long Finished, bool ReachedSocketCall);
internal sealed record MachineEgressDeliverySample(MachineEgressFlow Flow, MachineEgressSocketAttempt Socket,
    MachineEgressPacketEvidence Evidence);
internal sealed record MachineEgressFlowResult(MachineEgressFlow Flow, MachineEgressDeliveryVerdict Verdict);

// The fixed trial owner supplies the sender and independent collectors.
internal interface IMachineEgressDeliveryTrial
{
    IReadOnlyList<MachineEgressDeliverySample> Measure(MachineEgressDeliveryPhase phase,
        MachineEgressPolicyObservation before, CancellationToken cancellation);
    IReadOnlyList<MachineEgressPacketEvidence> Finish(CancellationToken cancellation);
}

internal static class MachineEgressDeliveryRun
{
    internal static IReadOnlyList<MachineEgressFlow> Flows { get; } = Array.AsReadOnly(
        (from family in new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 }
         from protocol in new[] { ProtocolType.Tcp, ProtocolType.Udp }
         from existing in new[] { false, true }
         select new MachineEgressFlow(family, protocol, existing)).ToArray());

    internal static MachineEgressFlowResult[] Execute(Guid operation, IMachineEgressDeliveryTrial trial,
        Func<MachineEgressPolicyObservation> observe, Action apply, Action restore, CancellationToken cancellation)
    {
        var flows = Flows;
        var markers = new HashSet<Guid>();
        var baseline = Measure(MachineEgressDeliveryPhase.Baseline, MachineEgressPolicyState.Absent);
        if (baseline.Values.Any(item => !item.Attempt.ReachedSocketCall || item.Attempt.SocketId == Guid.Empty ||
            item.Attempt.Started < 0 || item.Attempt.Finished <= item.Attempt.Started ||
            !MachineEgressDeliveryEvidence.Brackets(item.Attempt, operation, MachineEgressPolicyState.Absent) ||
            item.Evidence.PhysicalPackets <= 0 || item.Evidence.ReceiverReceipts <= 0 ||
            !item.Evidence.PhysicalObservationComplete || !item.Evidence.ReceiverObservationComplete ||
            item.Evidence.WfpDropFilterId.HasValue))
            throw new InvalidDataException("MachineEgressBaselineNotConfirmed");

        cancellation.ThrowIfCancellationRequested();
        apply(); // A failed apply leaves its original journal for exact recovery.
        Dictionary<MachineEgressFlow, (MachineEgressAttempt Attempt, MachineEgressPacketEvidence Evidence)> enforced;
        try
        {
            enforced = Measure(MachineEgressDeliveryPhase.Enforced, MachineEgressPolicyState.ExactBlock);
        }
        catch (Exception trialFailure)
        {
            try { restore(); }
            catch (Exception cleanupFailure) { throw new AggregateException(trialFailure, cleanupFailure); }
            throw;
        }
        restore();

        var restored = Measure(MachineEgressDeliveryPhase.Restored, MachineEgressPolicyState.Absent);
        var final = trial.Finish(cancellation).ToDictionary(e => e.Marker);
        if (final.Keys.Any(marker => !markers.Contains(marker)) ||
            final.Values.Any(e => e.PhysicalPackets < 0 || e.ReceiverReceipts < 0))
            throw new InvalidDataException("MachineEgressFinalEvidenceMismatch");

        return flows.Select(flow =>
        {
            var samples = new[] { baseline[flow], enforced[flow], restored[flow] };
            var evidence = samples.Select(s =>
            {
                var latest = final.GetValueOrDefault(s.Attempt.Marker) ?? new MachineEgressPacketEvidence(
                    s.Attempt.Marker, 0, 0, false, false, null);
                // Preserve positives reported before the final collection.
                return latest with
                {
                    PhysicalPackets = Math.Max(s.Evidence.PhysicalPackets, latest.PhysicalPackets),
                    ReceiverReceipts = Math.Max(s.Evidence.ReceiverReceipts, latest.ReceiverReceipts)
                };
            }).ToArray();
            return new MachineEgressFlowResult(flow,
                MachineEgressDeliveryEvidence.Evaluate(flow, samples.Select(s => s.Attempt).ToArray(), evidence));
        }).ToArray();

        Dictionary<MachineEgressFlow, (MachineEgressAttempt Attempt, MachineEgressPacketEvidence Evidence)> Measure(
            MachineEgressDeliveryPhase phase, MachineEgressPolicyState expected)
        {
            cancellation.ThrowIfCancellationRequested();
            var before = observe();
            if (operation == Guid.Empty || before.Operation != operation || before.State != expected)
                throw new InvalidDataException("MachineEgressUnexpectedPolicyBeforePhase");
            var samples = trial.Measure(phase, before, cancellation).ToArray();
            var after = observe();
            var result = new Dictionary<MachineEgressFlow, (MachineEgressAttempt, MachineEgressPacketEvidence)>();
            foreach (var sample in samples)
            {
                var socket = sample.Socket;
                if (socket.Marker == Guid.Empty || socket.Marker != sample.Evidence.Marker || !markers.Add(socket.Marker))
                    throw new InvalidDataException("MachineEgressTrialMarkerMismatch");
                if (sample.Evidence.PhysicalPackets < 0 || sample.Evidence.ReceiverReceipts < 0)
                    throw new InvalidDataException("MachineEgressTrialCountsInvalid");
                var attempt = new MachineEgressAttempt(phase, socket.Marker, socket.SocketId, socket.Started,
                    socket.Finished, socket.ReachedSocketCall, before, after);
                result.Add(sample.Flow, (attempt, sample.Evidence));
            }
            if (result.Count != flows.Count || flows.Any(flow => !result.ContainsKey(flow)))
                throw new InvalidDataException("MachineEgressTrialFlowInventoryMismatch");
            return result;
        }
    }
}
