using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace ProtectionLifecycle;

internal sealed record MachineEgressSendResult(MachineEgressSocketAttempt Attempt, SocketError? Error, bool TimedOut);

// A single bound test flow. The owner can capture the exact tuple before a
// TCP SYN and reuse this instance for the established-flow control.
internal sealed class MachineEgressSender : IDisposable
{
    // IP_UNICAST_IF and IPV6_UNICAST_IF in the Windows SDK.
    private const SocketOptionName UnicastInterface = (SocketOptionName)31;
    private readonly Socket socket;
    private readonly IPEndPoint destination;
    private readonly IPEndPoint local;
    private readonly bool tcp;
    private readonly Guid id = Guid.NewGuid();
    private bool attempted;
    private bool established;

    internal IPEndPoint Local => new(local.Address, local.Port);

    internal MachineEgressSender(IPAddress source, IPEndPoint destination, uint interfaceIndex, ProtocolType protocol)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (source.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6) ||
            source.AddressFamily != destination.AddressFamily || destination.Port == 0 || interfaceIndex == 0 ||
            source.Equals(IPAddress.Any) || source.Equals(IPAddress.IPv6Any) ||
            destination.Address.Equals(IPAddress.Any) || destination.Address.Equals(IPAddress.IPv6Any) ||
            source.IsIPv4MappedToIPv6 || destination.Address.IsIPv4MappedToIPv6 ||
            IPAddress.IsLoopback(source) != IPAddress.IsLoopback(destination.Address) ||
            protocol is not (ProtocolType.Tcp or ProtocolType.Udp))
            throw new ArgumentException("MachineEgressSenderTupleInvalid");
        var ipv4 = source.AddressFamily == AddressFamily.InterNetwork;
        if (!ipv4 && (source.ScopeId != 0 || destination.Address.ScopeId != 0))
            throw new ArgumentException("MachineEgressSenderScopedAddressRefused");

        this.destination = new(new IPAddress(destination.Address.GetAddressBytes()), destination.Port);
        tcp = protocol == ProtocolType.Tcp;
        socket = new(source.AddressFamily, tcp ? SocketType.Stream : SocketType.Dgram, protocol);
        try
        {
            socket.ExclusiveAddressUse = true;
            if (!ipv4) socket.DualMode = false;
            var index = unchecked((int)interfaceIndex);
            socket.SetSocketOption(ipv4 ? SocketOptionLevel.IP : SocketOptionLevel.IPv6,
                UnicastInterface, ipv4 ? IPAddress.HostToNetworkOrder(index) : index);
            socket.Bind(new IPEndPoint(source, 0));
            local = (IPEndPoint)(socket.LocalEndPoint ?? throw new InvalidDataException("MachineEgressLocalEndpointMissing"));
            if (!local.Address.Equals(source) || local.Port == 0)
                throw new InvalidDataException("MachineEgressLocalEndpointChanged");
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    internal async Task<MachineEgressSendResult> SendAsync(Guid marker, CancellationToken cancellation)
    {
        if (marker == Guid.Empty) throw new ArgumentException("MachineEgressMarkerMissing", nameof(marker));
        cancellation.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(3));
        var payload = marker.ToByteArray();
        if (attempted && !established)
            throw new InvalidOperationException("MachineEgressFailedSocketCannotBeReused");
        var firstAttempt = !attempted;
        attempted = true;
        established = false;
        var started = Stopwatch.GetTimestamp();
        try
        {
            if (firstAttempt) await socket.ConnectAsync(destination, deadline.Token).ConfigureAwait(false);
            if (!Equals(socket.LocalEndPoint, local) || !Equals(socket.RemoteEndPoint, destination))
                throw new InvalidDataException("MachineEgressConnectedTupleChanged");
            if (tcp)
            {
                using var stream = new NetworkStream(socket, ownsSocket: false);
                await stream.WriteAsync(payload, deadline.Token).ConfigureAwait(false);
            }
            else if (await socket.SendAsync(payload, SocketFlags.None, deadline.Token).ConfigureAwait(false) != payload.Length)
            {
                throw new IOException("MachineEgressDatagramIncomplete");
            }
            established = true;
            return Finish(null, false);
        }
        catch (SocketException error)
        {
            cancellation.ThrowIfCancellationRequested();
            return Finish(error.SocketErrorCode, false);
        }
        catch (IOException error) when (error.InnerException is SocketException socketError)
        {
            cancellation.ThrowIfCancellationRequested();
            return Finish(socketError.SocketErrorCode, false);
        }
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested && deadline.IsCancellationRequested)
        {
            return Finish(null, true);
        }

        MachineEgressSendResult Finish(SocketError? error, bool timedOut) =>
            new(new(marker, id, started, Stopwatch.GetTimestamp(), true), error, timedOut);
    }

    public void Dispose() => socket.Dispose();
}
