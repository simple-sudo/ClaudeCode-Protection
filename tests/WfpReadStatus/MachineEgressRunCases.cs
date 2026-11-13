using System.Net.Sockets;
using ProtectionLifecycle;

internal static class MachineEgressRunCases
{
    internal static void Run()
    {
        var complete = new Trial();
        Require(complete.Execute().Count(r => r.Verdict == MachineEgressDeliveryVerdict.BlockObserved) == 8);
        Require(complete.Trace.SequenceEqual(["Baseline", "Apply", "Enforced", "Restore", "Restored", "Finish"]));

        var failedBaseline = new Trial { IncompleteBaseline = true };
        Refuse(failedBaseline);
        Require(failedBaseline.Trace.SequenceEqual(["Baseline"]));

        var failedApply = new Trial { ApplyFailure = true };
        Refuse(failedApply);
        Require(failedApply.Trace.SequenceEqual(["Baseline", "Apply"]));

        var cancelled = new Trial { CancelAfterApply = true };
        try { _ = cancelled.Execute(); throw new InvalidOperationException("Cancellation lost"); }
        catch (OperationCanceledException) { }
        Require(cancelled.Trace.SequenceEqual(["Baseline", "Apply", "Restore"]));

        var bothFailed = new Trial { EnforcedFailure = true, RestoreFailure = true };
        try { _ = bothFailed.Execute(); throw new InvalidOperationException("Failures lost"); }
        catch (AggregateException error) { Require(error.InnerExceptions.Count == 2); }
        Require(bothFailed.Trace.SequenceEqual(["Baseline", "Apply", "Enforced", "Restore"]));

        var lostCoverage = new Trial { DropFinalCoverage = true };
        Require(lostCoverage.Execute().All(r => r.Verdict == MachineEgressDeliveryVerdict.Unknown));
        var delivered = new Trial { ReportEnforcedDelivery = true, DropFinalCoverage = true };
        Require(delivered.Execute().All(r => r.Verdict == MachineEgressDeliveryVerdict.DeliveredWhileEnforced));
        Console.WriteLine("PASS machine egress trial ordering, recovery paths and final evidence (managed fixture)");
    }

    private static void Refuse(Trial trial)
    {
        try { _ = trial.Execute(); }
        catch (InvalidDataException) { return; }
        throw new InvalidOperationException("Machine egress trial should have failed");
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidDataException("Machine egress trial fixture mismatch");
    }

    private sealed class Trial : IMachineEgressDeliveryTrial
    {
        private readonly Guid operation = Guid.NewGuid();
        private readonly MachineEgressObjects objects = new(100, 200, 300, "fixture", "fixture", "fixture");
        private readonly Dictionary<MachineEgressFlow, Guid> existingSockets = new();
        private readonly List<MachineEgressPacketEvidence> final = new();
        private long clock = 100;
        private bool applied;
        internal List<string> Trace { get; } = new();
        internal bool IncompleteBaseline { get; init; }
        internal bool ApplyFailure { get; init; }
        internal bool CancelAfterApply { get; init; }
        internal bool EnforcedFailure { get; init; }
        internal bool RestoreFailure { get; init; }
        internal bool DropFinalCoverage { get; init; }
        internal bool ReportEnforcedDelivery { get; init; }

        internal MachineEgressFlowResult[] Execute()
        {
            using var cancel = new CancellationTokenSource();
            return MachineEgressDeliveryRun.Execute(operation, this, Observe, Apply, Restore, cancel.Token);

            void Apply()
            {
                Trace.Add("Apply");
                if (ApplyFailure) throw new InvalidDataException("ApplyFixtureFailure");
                applied = true;
                if (CancelAfterApply) cancel.Cancel();
            }

            void Restore()
            {
                Trace.Add("Restore");
                if (RestoreFailure) throw new IOException("RestoreFixtureFailure");
                applied = false;
            }
        }

        private MachineEgressPolicyObservation Observe() =>
            new(operation, applied ? MachineEgressPolicyState.ExactBlock : MachineEgressPolicyState.Absent,
                clock++, clock++, applied ? objects : null);

        public IReadOnlyList<MachineEgressDeliverySample> Measure(MachineEgressDeliveryPhase phase, CancellationToken cancellation)
        {
            Trace.Add(phase.ToString());
            var enforced = phase == MachineEgressDeliveryPhase.Enforced;
            if (enforced && EnforcedFailure) throw new IOException("EnforcedFixtureFailure");
            var samples = new List<MachineEgressDeliverySample>();
            foreach (var family in new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 })
            foreach (var protocol in new[] { ProtocolType.Tcp, ProtocolType.Udp })
            foreach (var existing in new[] { false, true })
            {
                var flow = new MachineEgressFlow(family, protocol, existing);
                var socket = enforced && existing ? existingSockets[flow] : Guid.NewGuid();
                if (phase == MachineEgressDeliveryPhase.Baseline && existing) existingSockets.Add(flow, socket);
                var marker = Guid.NewGuid();
                var count = enforced ? 0 : 1;
                var complete = phase != MachineEgressDeliveryPhase.Baseline || !IncompleteBaseline;
                ulong? drop = enforced ? (family == AddressFamily.InterNetwork ? objects.V4Id : objects.V6Id) : null;
                var evidence = new MachineEgressPacketEvidence(marker, count, count, complete, complete, drop);
                if (!DropFinalCoverage || !enforced) final.Add(evidence);
                var preliminary = enforced && ReportEnforcedDelivery ? evidence with { ReceiverReceipts = 1 } : evidence;
                samples.Add(new(flow, new(marker, socket, clock++, clock++, true), preliminary));
            }
            return samples;
        }

        public IReadOnlyList<MachineEgressPacketEvidence> Finish(CancellationToken cancellation)
        {
            Trace.Add("Finish");
            return final;
        }
    }
}
