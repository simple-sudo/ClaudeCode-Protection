using System.Net.Sockets;

namespace ProtectionLifecycle;

internal enum MachineEgressDeliveryPhase { Baseline, Enforced, Restored }
internal enum MachineEgressDeliveryVerdict { BlockObserved, DeliveredWhileEnforced, Unknown }
internal enum MachineEgressPolicyState { Absent, ExactBlock, Unknown }

internal readonly record struct MachineEgressFlow(AddressFamily Family, ProtocolType Protocol, bool Existing);

// One owner-controlled timebase for the sender and WFP observations. The
// receiver correlates by marker, so its clock need not match the owner's.
internal sealed record MachineEgressAttempt(
    MachineEgressDeliveryPhase Phase, Guid Marker, Guid SocketId, long Started, long Finished,
    bool ReachedSocketCall, MachineEgressPolicyState PolicyBefore, MachineEgressPolicyState PolicyAfter);

// Counts include late observations through the end of the run. Physical
// packets and WFP drops must be attributed to the attempt's exact flow,
// including packets without a payload marker (e.g. a new TCP SYN). A capture
// or receiver that lost coverage can still report a positive observation.
internal sealed record MachineEgressPacketEvidence(Guid Marker, int PhysicalPackets, int ReceiverReceipts,
    bool PhysicalObservationComplete, bool ReceiverObservationComplete, bool ExactWfpDropObserved);

internal static class MachineEgressDeliveryEvidence
{
    internal static MachineEgressDeliveryVerdict Evaluate(MachineEgressFlow flow,
        IReadOnlyList<MachineEgressAttempt> attempts, IReadOnlyList<MachineEgressPacketEvidence> observations)
    {
        if (flow.Family is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6) ||
            flow.Protocol is not (ProtocolType.Tcp or ProtocolType.Udp) || attempts.Count != 3)
            return MachineEgressDeliveryVerdict.Unknown;

        var baseline = attempts[0];
        var enforced = attempts[1];
        var restored = attempts[2];
        if (baseline.Phase != MachineEgressDeliveryPhase.Baseline ||
            enforced.Phase != MachineEgressDeliveryPhase.Enforced ||
            restored.Phase != MachineEgressDeliveryPhase.Restored ||
            attempts.Any(a => a.Marker == Guid.Empty || a.SocketId == Guid.Empty) ||
            attempts.Select(a => a.Marker).Distinct().Count() != 3)
            return MachineEgressDeliveryVerdict.Unknown;

        // A matched positive observation refutes the zero-delivery claim even
        // when other collectors failed or a positive control did not finish.
        if (observations.Any(o => o.Marker == enforced.Marker && (o.PhysicalPackets > 0 || o.ReceiverReceipts > 0)))
            return MachineEgressDeliveryVerdict.DeliveredWhileEnforced;

        if (observations.Count != 3 || observations.Select(o => o.Marker).Distinct().Count() != 3 ||
            observations.Any(o => o.PhysicalPackets < 0 || o.ReceiverReceipts < 0) ||
            attempts.Any(a => !a.ReachedSocketCall || a.Started < 0 || a.Finished <= a.Started) ||
            baseline.Finished >= enforced.Started || enforced.Finished >= restored.Started ||
            (baseline.SocketId == enforced.SocketId) != flow.Existing ||
            restored.SocketId == enforced.SocketId || restored.SocketId == baseline.SocketId)
            return MachineEgressDeliveryVerdict.Unknown;

        foreach (var attempt in attempts)
        {
            var observation = observations.SingleOrDefault(o => o.Marker == attempt.Marker);
            var expectBlocked = attempt.Phase == MachineEgressDeliveryPhase.Enforced;
            var required = expectBlocked ? MachineEgressPolicyState.ExactBlock : MachineEgressPolicyState.Absent;
            if (attempt.PolicyBefore != required || attempt.PolicyAfter != required || observation is null ||
                !observation.PhysicalObservationComplete || !observation.ReceiverObservationComplete)
                return MachineEgressDeliveryVerdict.Unknown;

            if (expectBlocked
                ? !observation.ExactWfpDropObserved
                : observation.ExactWfpDropObserved || observation.PhysicalPackets == 0 || observation.ReceiverReceipts == 0)
                return MachineEgressDeliveryVerdict.Unknown;
        }
        return MachineEgressDeliveryVerdict.BlockObserved;
    }
}
