using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

internal enum MachineEgressFrameResult { Unrelated, Matched, Indeterminate }

// Classifies Ethernet bytes from an independently identified physical egress
// capture point. It does not establish the capture point, direction or loss.
internal sealed class MachineEgressFrameMatch
{
    private readonly byte[] source, destination;
    private readonly ushort sourcePort, destinationPort;
    private readonly byte protocol;

    internal MachineEgressFrameMatch(IPEndPoint source, IPEndPoint destination, ProtocolType protocol)
    {
        if (source.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6) ||
            source.AddressFamily != destination.AddressFamily || source.Port == 0 || destination.Port == 0 ||
            protocol is not (ProtocolType.Tcp or ProtocolType.Udp) ||
            IPAddress.IsLoopback(source.Address) || IPAddress.IsLoopback(destination.Address) ||
            source.Address.Equals(IPAddress.Any) || source.Address.Equals(IPAddress.IPv6Any) ||
            destination.Address.Equals(IPAddress.Any) || destination.Address.Equals(IPAddress.IPv6Any) ||
            source.Address.IsIPv4MappedToIPv6 || destination.Address.IsIPv4MappedToIPv6)
            throw new ArgumentException("Invalid machine egress capture tuple");
        this.source = source.Address.GetAddressBytes();
        this.destination = destination.Address.GetAddressBytes();
        sourcePort = (ushort)source.Port;
        destinationPort = (ushort)destination.Port;
        this.protocol = (byte)protocol;
    }

    internal MachineEgressFrameResult Classify(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 14) return MachineEgressFrameResult.Indeterminate;
        var type = U16(frame[12..]);
        var payload = frame[14..];
        for (var tags = 0; type is 0x8100 or 0x88a8; tags++)
        {
            if (tags == 2 || payload.Length < 4) return MachineEgressFrameResult.Indeterminate;
            type = U16(payload[2..]);
            payload = payload[4..];
        }
        return type switch
        {
            0x0800 when source.Length == 4 => IPv4(payload),
            0x86dd when source.Length == 16 => IPv6(payload),
            // The selected diagnostic capture uses Ethernet II framing.
            < 0x0600 => MachineEgressFrameResult.Indeterminate,
            _ => MachineEgressFrameResult.Unrelated
        };
    }

    private MachineEgressFrameResult IPv4(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 20 || packet[0] >> 4 != 4) return MachineEgressFrameResult.Indeterminate;
        if (!packet.Slice(12, 4).SequenceEqual(source) || !packet.Slice(16, 4).SequenceEqual(destination))
            return MachineEgressFrameResult.Unrelated;
        if (packet[9] != protocol) return MachineEgressFrameResult.Unrelated;
        var headerLength = (packet[0] & 15) * 4;
        var totalLength = U16(packet[2..]);
        if (headerLength < 20 || totalLength < headerLength || packet.Length < headerLength ||
            (U16(packet[6..]) & 0x9fff) != 0)
            return MachineEgressFrameResult.Indeterminate;
        return Transport(packet[..Math.Min(totalLength, packet.Length)][headerLength..], totalLength - headerLength);
    }

    private MachineEgressFrameResult IPv6(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 40 || packet[0] >> 4 != 6) return MachineEgressFrameResult.Indeterminate;
        if (!packet.Slice(8, 16).SequenceEqual(source) || !packet.Slice(24, 16).SequenceEqual(destination))
            return MachineEgressFrameResult.Unrelated;
        var payloadLength = U16(packet[4..]);
        if (payloadLength == 0) return MachineEgressFrameResult.Indeterminate;
        var next = packet[6];
        var remaining = (int)payloadLength;
        var payload = packet.Slice(40, Math.Min(remaining, packet.Length - 40));
        for (var headers = 0; next is 0 or 60 or 44; headers++)
        {
            if (headers == 8 || payload.Length < 8 || (next == 0 && headers != 0))
                return MachineEgressFrameResult.Indeterminate;
            var length = next == 44 ? 8 : (payload[1] + 1) * 8;
            // Later fragments cannot be attributed to ports without reassembly.
            if (length > payload.Length || (next == 44 && (U16(payload[2..]) & 0xfffe) != 0))
                return MachineEgressFrameResult.Indeterminate;
            next = payload[0];
            payload = payload[length..];
            remaining -= length;
        }
        if (next == protocol) return Transport(payload, remaining);
        return next is 6 or 17 or 58 or 59
            ? MachineEgressFrameResult.Unrelated : MachineEgressFrameResult.Indeterminate;
    }

    private MachineEgressFrameResult Transport(ReadOnlySpan<byte> transport, int declaredLength)
    {
        if (transport.Length < 4) return MachineEgressFrameResult.Indeterminate;
        if (U16(transport) != sourcePort || U16(transport[2..]) != destinationPort)
            return MachineEgressFrameResult.Unrelated;
        if (protocol == (byte)ProtocolType.Tcp)
        {
            if (transport.Length < 20) return MachineEgressFrameResult.Indeterminate;
            var headerLength = (transport[12] >> 4) * 4;
            if (headerLength < 20 || headerLength > transport.Length) return MachineEgressFrameResult.Indeterminate;
        }
        else if (transport.Length < 8 || U16(transport[4..]) < 8 || U16(transport[4..]) > declaredLength)
        {
            return MachineEgressFrameResult.Indeterminate;
        }
        return MachineEgressFrameResult.Matched;
    }

    private static ushort U16(ReadOnlySpan<byte> bytes) => BinaryPrimitives.ReadUInt16BigEndian(bytes);
}
