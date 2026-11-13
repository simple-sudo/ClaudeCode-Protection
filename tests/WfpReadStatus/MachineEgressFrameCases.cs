using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

internal static class MachineEgressFrameCases
{
    internal static void Run()
    {
        var v4Source = IPAddress.Parse("192.0.2.5");
        var v4Destination = IPAddress.Parse("198.51.100.2");
        var v6Source = IPAddress.Parse("2001:db8::5");
        var v6Destination = IPAddress.Parse("2001:db8::2");
        foreach (var (source, destination) in new[] { (v4Source, v4Destination), (v6Source, v6Destination) })
        foreach (var protocol in new[] { ProtocolType.Tcp, ProtocolType.Udp })
        {
            var match = new MachineEgressFrameMatch(new(source, 45123), new(destination, 33445), protocol);
            var ipv4 = source.AddressFamily == AddressFamily.InterNetwork;
            var plain = Frame(source, destination, protocol, vlan: false, extension: false);
            var tagged = Frame(source, destination, protocol, vlan: true, extension: !ipv4);
            Require(match.Classify(plain), MachineEgressFrameResult.Matched);
            Require(match.Classify(tagged), MachineEgressFrameResult.Matched);
            Require(match.Classify(Frame(destination, source, protocol, vlan: false, extension: false)),
                MachineEgressFrameResult.Unrelated);
            VerifyCaptureWindow(match, plain);

            var transport = 14 + (ipv4 ? 20 : 40);
            Require(match.Classify(plain.AsSpan(0, transport + 3)), MachineEgressFrameResult.Indeterminate);
            Require(match.Classify(plain.AsSpan(0, plain.Length - 1)), MachineEgressFrameResult.Indeterminate);
            var changed = (byte[])plain.Clone();
            U16(changed.AsSpan(transport + 2), 33446);
            Require(match.Classify(changed), MachineEgressFrameResult.Unrelated);
            if (ipv4)
            {
                changed = (byte[])plain.Clone();
                U16(changed.AsSpan(20), 1); // Non-initial fragment.
                Require(match.Classify(changed), MachineEgressFrameResult.Indeterminate);
                U16(changed.AsSpan(20), 0x2000); // First fragment, header still available.
                Require(match.Classify(changed), MachineEgressFrameResult.Matched);
            }
            else
            {
                var ip = 18;
                var nextHeader = ip + 6;
                var extension = ip + 40;
                changed = (byte[])tagged.Clone();
                changed[nextHeader] = 44;
                U16(changed.AsSpan(extension + 2), 8);
                Require(match.Classify(changed), MachineEgressFrameResult.Indeterminate);
                U16(changed.AsSpan(extension + 2), 0);
                Require(match.Classify(changed), MachineEgressFrameResult.Matched);
                U16(changed.AsSpan(extension + 2), 1);
                Require(match.Classify(changed), MachineEgressFrameResult.Matched);
                changed[nextHeader] = 43;
                Require(match.Classify(changed), MachineEgressFrameResult.Indeterminate);
            }
        }
        Console.WriteLine("PASS physical Ethernet tuple matching fixtures, including payload-free TCP SYN");
    }

    private static void VerifyCaptureWindow(MachineEgressFrameMatch match, byte[] frame)
    {
        var capture = new MachineEgressCaptureWindow(18, 100, 200, match);
        var outbound = new MachineEgressCaptureFrame(18, 150, MachineEgressCaptureDirection.Outbound, frame);
        capture.Observe(outbound with { Component = 25 });
        capture.Observe(outbound with { Timestamp = 201 });
        capture.Observe(outbound with { Direction = MachineEgressCaptureDirection.Inbound });
        Check(capture.MatchedFrames == 0 && capture.IsComplete(99, 200, 0));
        Check(!capture.IsComplete(101, 200, 0) && !capture.IsComplete(100, 199, 0));
        Check(!capture.IsComplete(100, 200, 1) && !capture.IsComplete(100, 200, null));
        capture.Observe(outbound);
        capture.Observe(outbound with { Direction = MachineEgressCaptureDirection.Unknown });
        Check(capture.MatchedFrames == 1 && !capture.IsComplete(100, 200, 0));

        var truncated = new MachineEgressCaptureWindow(18, 100, 200, match);
        truncated.Observe(outbound with { Ethernet = frame.AsMemory(0, 20) });
        Check(truncated.MatchedFrames == 0 && !truncated.IsComplete(100, 200, 0));
        var unattributed = new MachineEgressCaptureWindow(18, 100, 200, match);
        unattributed.Observe(outbound with { Component = 0 });
        Check(unattributed.MatchedFrames == 0 && !unattributed.IsComplete(100, 200, 0));

        static void Check(bool condition)
        {
            if (!condition) throw new InvalidDataException("Physical capture window evidence mismatch");
        }
    }

    private static byte[] Frame(IPAddress source, IPAddress destination, ProtocolType protocol, bool vlan, bool extension)
    {
        var ipv4 = source.AddressFamily == AddressFamily.InterNetwork;
        var linkLength = vlan ? 18 : 14;
        var ipLength = ipv4 ? 20 : 40;
        var extensionLength = extension ? 8 : 0;
        var transportLength = protocol == ProtocolType.Tcp ? 20 : 8;
        var frame = new byte[linkLength + ipLength + extensionLength + transportLength];
        if (vlan) U16(frame.AsSpan(12), 0x8100);
        U16(frame.AsSpan(linkLength - 2), ipv4 ? (ushort)0x0800 : (ushort)0x86dd);
        var ip = frame.AsSpan(linkLength);
        if (ipv4)
        {
            ip[0] = 0x45;
            U16(ip[2..], (ushort)ip.Length);
            ip[9] = (byte)protocol;
            source.GetAddressBytes().CopyTo(ip[12..]);
            destination.GetAddressBytes().CopyTo(ip[16..]);
        }
        else
        {
            ip[0] = 0x60;
            U16(ip[4..], (ushort)(ip.Length - 40));
            ip[6] = extension ? (byte)60 : (byte)protocol;
            source.GetAddressBytes().CopyTo(ip[8..]);
            destination.GetAddressBytes().CopyTo(ip[24..]);
            if (extension) ip[40] = (byte)protocol;
        }
        var transport = ip[(ipLength + extensionLength)..];
        U16(transport, 45123);
        U16(transport[2..], 33445);
        if (protocol == ProtocolType.Tcp)
        {
            transport[12] = 0x50;
            transport[13] = 2; // SYN, without any application bytes.
        }
        else U16(transport[4..], 8);
        return frame;
    }

    private static void Require(MachineEgressFrameResult actual, MachineEgressFrameResult expected)
    {
        if (actual != expected) throw new InvalidDataException($"Ethernet fixture expected {expected}, observed {actual}");
    }

    private static void U16(Span<byte> bytes, ushort value) => BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
}
