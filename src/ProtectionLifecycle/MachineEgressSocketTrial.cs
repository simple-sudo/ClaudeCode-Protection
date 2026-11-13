using System.Net;
using System.Net.Sockets;

namespace ProtectionLifecycle;

internal sealed record MachineEgressTrialEndpoint(IPAddress Source, IPAddress Receiver, uint InterfaceIndex,
    ushort TcpPort, ushort UdpPort);

internal sealed record MachineEgressTransmission(MachineEgressDeliveryPhase Phase, MachineEgressFlow Flow,
    Guid Marker, MachineEgressRoute Route, IPEndPoint Source, IPEndPoint Destination, MachineEgressPolicyObservation PolicyBefore);

internal interface IMachineEgressCollectors
{
    void Expect(MachineEgressTransmission transmission, CancellationToken cancellation);
    MachineEgressPacketEvidence Read(Guid marker, MachineEgressSendResult send, CancellationToken cancellation);
    IReadOnlyList<MachineEgressPacketEvidence> Finish(CancellationToken cancellation);
}

// Owns the actual senders; the independent collectors receive a tuple before
// any socket I/O and cannot select or change the targets.
internal sealed class MachineEgressSocketTrial : IMachineEgressDeliveryTrial, IDisposable
{
    private readonly MachineEgressTrialEndpoint v4, v6;
    private readonly IMachineEgressCollectors collectors;
    private readonly Dictionary<MachineEgressFlow, MachineEgressSender> baseline = new();
    private MachineEgressRoute? baselineV4, baselineV6;
    private MachineEgressRouteWatch? routeWatch;
    private int nextPhase;
    private bool disposed;

    internal MachineEgressSocketTrial(MachineEgressTrialEndpoint v4, MachineEgressTrialEndpoint v6,
        IMachineEgressCollectors collectors)
    {
        this.v4 = Freeze(v4, AddressFamily.InterNetwork);
        this.v6 = Freeze(v6, AddressFamily.InterNetworkV6);
        this.collectors = collectors ?? throw new ArgumentNullException(nameof(collectors));
    }

    internal void AssertPlan(MachineEgressProbeIntent intent)
    {
        if (v4.InterfaceIndex != intent.V4Interface || v6.InterfaceIndex != intent.V6Interface ||
            !v4.Receiver.Equals(IPAddress.Parse(intent.V4Receiver)) ||
            !v6.Receiver.Equals(IPAddress.Parse(intent.V6Receiver)))
            throw new InvalidDataException("MachineEgressTrialTargetDiffersFromPolicy");
    }

    public IReadOnlyList<MachineEgressDeliverySample> Measure(MachineEgressDeliveryPhase phase,
        MachineEgressPolicyObservation before, CancellationToken cancellation)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if ((int)phase != nextPhase || nextPhase >= 3)
            throw new InvalidOperationException("MachineEgressSocketTrialPhaseOutOfOrder");
        nextPhase++;
        if (phase == MachineEgressDeliveryPhase.Baseline)
        {
            routeWatch = new MachineEgressRouteWatch();
            baselineV4 = MachineEgressRouteReader.Read(v4);
            baselineV6 = MachineEgressRouteReader.Read(v6);
        }
        var samples = new List<MachineEgressDeliverySample>();
        // Keep the other sockets bound until the phase ends so a later probe
        // in the phase cannot reuse their local ports.
        var temporary = new List<MachineEgressSender>();
        try
        {
            foreach (var flow in MachineEgressDeliveryRun.Flows)
            {
                cancellation.ThrowIfCancellationRequested();
                var endpoint = flow.Family == AddressFamily.InterNetwork ? v4 : v6;
                var route = flow.Family == AddressFamily.InterNetwork ? baselineV4! : baselineV6!;
                AssertRoute(endpoint, route);
                var port = flow.Protocol == ProtocolType.Tcp ? endpoint.TcpPort : endpoint.UdpPort;
                var destination = new IPEndPoint(endpoint.Receiver, port);
                MachineEgressSender sender;
                if (phase == MachineEgressDeliveryPhase.Enforced && flow.Existing)
                {
                    sender = baseline[flow];
                }
                else
                {
                    sender = new MachineEgressSender(endpoint.Source, destination, endpoint.InterfaceIndex, flow.Protocol);
                    if (phase == MachineEgressDeliveryPhase.Baseline) baseline.Add(flow, sender);
                    else temporary.Add(sender);
                }

                var marker = Guid.NewGuid();
                collectors.Expect(new(phase, flow, marker, route with
                {
                    Source = Copy(route.Source), Prefix = Copy(route.Prefix), NextHop = Copy(route.NextHop)
                }, sender.Local,
                    new IPEndPoint(new IPAddress(endpoint.Receiver.GetAddressBytes()), port), before), cancellation);
                AssertRoute(endpoint, route);
                var sent = sender.SendAsync(marker, cancellation).GetAwaiter().GetResult();
                var observed = collectors.Read(marker, sent, cancellation);
                AssertRoute(endpoint, route);
                samples.Add(new(flow, sent.Attempt, observed));
                if (phase == MachineEgressDeliveryPhase.Baseline && (sent.Error.HasValue || sent.TimedOut))
                    throw new IOException("MachineEgressBaselineSocketCallFailed");
            }
            return samples;
        }
        finally
        {
            foreach (var sender in temporary) sender.Dispose();
            if (phase == MachineEgressDeliveryPhase.Enforced) StopSending();
        }
    }

    internal void AssertBaselineRoutes()
    {
        AssertRoute(v4, baselineV4 ?? throw new InvalidOperationException("MachineEgressBaselineV4Missing"));
        AssertRoute(v6, baselineV6 ?? throw new InvalidOperationException("MachineEgressBaselineV6Missing"));
    }

    private void AssertRoute(MachineEgressTrialEndpoint endpoint, MachineEgressRoute baseline)
    {
        routeWatch!.AssertUnchanged();
        if (MachineEgressRouteReader.Read(endpoint) != baseline)
            throw new InvalidDataException("MachineEgressTrialRouteChanged");
        routeWatch.AssertUnchanged();
    }

    private static IPAddress Copy(IPAddress address) => address.AddressFamily == AddressFamily.InterNetwork
        ? new(address.GetAddressBytes()) : new(address.GetAddressBytes(), address.ScopeId);

    public IReadOnlyList<MachineEgressPacketEvidence> Finish(CancellationToken cancellation)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (nextPhase != 3) throw new InvalidOperationException("MachineEgressSocketTrialIncomplete");
        nextPhase++;
        var evidence = collectors.Finish(cancellation);
        AssertBaselineRoutes();
        routeWatch!.Complete();
        return evidence;
    }

    public void Dispose()
    {
        disposed = true;
        try { StopSending(); }
        finally { routeWatch?.Dispose(); }
    }

    internal void StopSending()
    {
        foreach (var sender in baseline.Values) sender.Dispose();
        baseline.Clear();
    }

    private static MachineEgressTrialEndpoint Freeze(MachineEgressTrialEndpoint endpoint, AddressFamily family)
    {
        if (endpoint.Source.AddressFamily != family || endpoint.Receiver.AddressFamily != family ||
            endpoint.InterfaceIndex == 0 || endpoint.TcpPort == 0 || endpoint.UdpPort == 0 ||
            (family == AddressFamily.InterNetworkV6 && (endpoint.Source.ScopeId != 0 || endpoint.Receiver.ScopeId != 0)))
            throw new ArgumentException("MachineEgressTrialEndpointInvalid");
        return endpoint with
        {
            Source = new IPAddress(endpoint.Source.GetAddressBytes()),
            Receiver = new IPAddress(endpoint.Receiver.GetAddressBytes())
        };
    }
}
