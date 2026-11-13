using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace WfpExistingEvents;

internal static class MachineEgressDropCases
{
    internal static void Run()
    {
        Native.Layout();
        foreach (var (local, remote, version) in new[]
        {
            (IPAddress.Parse("192.0.2.5"), IPAddress.Parse("198.51.100.2"), 0u),
            (IPAddress.Parse("2001:db8::5"), IPAddress.Parse("2001:db8::2"), 1u)
        })
        foreach (var protocol in new[] { ProtocolType.Tcp, ProtocolType.Udp })
        {
            var selection = new MachineEgressDropSelection(new(local, 45123), new(remote, 33445),
                protocol, 17, 561, 100, 200);
            var item = Marshal.AllocHGlobal(120);
            var payload = Marshal.AllocHGlobal(56);
            try
            {
                Marshal.Copy(new byte[120], 0, item, 120);
                Marshal.Copy(new byte[56], 0, payload, 56);
                Marshal.WriteInt64(item, 0, 150);
                Marshal.WriteInt32(item, 8, 0x11f);
                Marshal.WriteInt32(item, 12, (int)version);
                Marshal.WriteByte(item, 16, (byte)protocol);
                WriteAddress(item + 20, local);
                WriteAddress(item + 36, remote);
                Marshal.WriteInt16(item, 52, unchecked((short)45123));
                Marshal.WriteInt16(item, 54, unchecked((short)33445));
                Marshal.WriteInt32(item, 104, 3);
                Marshal.WriteIntPtr(item, 112, payload);
                Marshal.WriteInt64(payload, 0, 561);
                Marshal.WriteInt16(payload, 8, 17);
                Marshal.WriteInt32(payload, 24, 0x3901);
                Require(selection.Matches(item), "exact outbound drop");

                foreach (var flag in new[] { 1, 2, 4, 8, 16, 256 })
                    Mismatch(() => Marshal.WriteInt32(item, 8, 0x11f & ~flag), () => Marshal.WriteInt32(item, 8, 0x11f));
                Mismatch(() => Marshal.WriteInt64(item, 0, 99), () => Marshal.WriteInt64(item, 0, 150));
                Mismatch(() => Marshal.WriteInt64(item, 0, 201), () => Marshal.WriteInt64(item, 0, 150));
                Mismatch(() => Marshal.WriteInt32(item, 12, 2), () => Marshal.WriteInt32(item, 12, (int)version));
                Mismatch(() => Marshal.WriteByte(item, 16, 1), () => Marshal.WriteByte(item, 16, (byte)protocol));
                Mismatch(() => WriteAddress(item + 20, remote), () => WriteAddress(item + 20, local));
                Mismatch(() => WriteAddress(item + 36, local), () => WriteAddress(item + 36, remote));
                Mismatch(() => Marshal.WriteInt16(item, 52, 10), () => Marshal.WriteInt16(item, 52, unchecked((short)45123)));
                Mismatch(() => Marshal.WriteInt16(item, 54, 10), () => Marshal.WriteInt16(item, 54, unchecked((short)33445)));
                Mismatch(() => Marshal.WriteInt32(item, 104, 6), () => Marshal.WriteInt32(item, 104, 3));
                Mismatch(() => Marshal.WriteInt64(payload, 0, 562), () => Marshal.WriteInt64(payload, 0, 561));
                Mismatch(() => Marshal.WriteInt16(payload, 8, 18), () => Marshal.WriteInt16(payload, 8, 17));
                Mismatch(() => Marshal.WriteInt32(payload, 24, 0x3900), () => Marshal.WriteInt32(payload, 24, 0x3901));
                Mismatch(() => Marshal.WriteInt32(payload, 28, 1), () => Marshal.WriteInt32(payload, 28, 0));
            }
            finally
            {
                Marshal.FreeHGlobal(payload);
                Marshal.FreeHGlobal(item);
            }

            void Mismatch(Action change, Action restore)
            {
                change();
                Require(!selection.Matches(item), "unrelated or incomplete drop refused");
                restore();
            }
        }
        Console.WriteLine("PASS dual-stack WFP drop selection and native event layout fixtures");
    }

    private static void WriteAddress(IntPtr pointer, IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        if (bytes.Length == 4) Marshal.WriteInt32(pointer, unchecked((int)BinaryPrimitives.ReadUInt32BigEndian(bytes)));
        else Marshal.Copy(bytes, 0, pointer, bytes.Length);
    }

    private static void Require(bool accepted, string reason)
    {
        if (!accepted) throw new InvalidDataException("Machine egress drop: " + reason);
    }
}
