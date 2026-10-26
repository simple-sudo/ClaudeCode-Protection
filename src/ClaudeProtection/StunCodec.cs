using System.Buffers.Binary;
using System.Net;

namespace ClaudeProtection;

// Offline RFC 5389 parser only. No direct UDP traffic is sent by this component.
internal static class StunCodec
{
    internal static IPAddress? Parse(ReadOnlySpan<byte> packet, ReadOnlySpan<byte> transaction)
    {
        if (transaction.Length != 12 || packet.Length < 20) return null;
        if (BinaryPrimitives.ReadUInt16BigEndian(packet) != 0x0101 || BinaryPrimitives.ReadUInt32BigEndian(packet[4..]) != 0x2112a442) return null;
        int length = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
        if (length % 4 != 0 || packet.Length != 20 + length || !packet.Slice(8, 12).SequenceEqual(transaction)) return null;
        for (int position = 20; position < packet.Length;)
        {
            if (position + 4 > packet.Length) return null;
            int type = BinaryPrimitives.ReadUInt16BigEndian(packet[position..]);
            int size = BinaryPrimitives.ReadUInt16BigEndian(packet[(position + 2)..]);
            int next = position + 4 + ((size + 3) & ~3);
            if (next > packet.Length) return null;
            var value = packet.Slice(position + 4, size);
            if (type is 0x0020 or 0x0001)
            {
                if (size < 4 || value[0] != 0) return null;
                int addressLength = value[1] == 1 ? 4 : value[1] == 2 ? 16 : 0;
                if (addressLength == 0 || size != addressLength + 4) return null;
                var address = value.Slice(4, addressLength).ToArray();
                if (type == 0x0020)
                {
                    var mask = packet.Slice(4, 16);
                    for (int i = 0; i < address.Length; i++) address[i] ^= mask[i];
                }
                return new IPAddress(address);
            }
            position = next;
        }
        return null;
    }
}
