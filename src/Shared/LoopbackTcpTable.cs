using System.Buffers.Binary;

namespace ClaudeCodeProtection.Security;

// Decodes the bounded IPv4 TCP_TABLE_OWNER_PID_ALL snapshot returned by
// GetExtendedTcpTable. A listener observation never identifies an accepted
// connection: the latter must match both endpoints in the reverse direction.
internal static class LoopbackTcpTable
{
    internal static uint FindOwner(ReadOnlySpan<byte> table,int localPort,int? remotePort)
    {
        if(table.Length is <4 or >1024*1024 || localPort is <1 or >65535 || remotePort is <1 or >65535)
            throw new InvalidDataException("LoopbackOwnerTableBounds");
        var count=BinaryPrimitives.ReadUInt32LittleEndian(table);
        if(count>(table.Length-4)/24)throw new InvalidDataException("LoopbackOwnerTableBounds");
        uint owner=0;var matches=0;
        for(var i=0;i<count;i++)
        {
            var row=table.Slice(checked(4+i*24),24);
            if(BinaryPrimitives.ReadUInt32LittleEndian(row)!=(remotePort is null?2u:5u) ||
                BinaryPrimitives.ReadUInt32LittleEndian(row[4..])!=0x0100007f ||
                BinaryPrimitives.ReadUInt16BigEndian(row[8..])!=localPort ||
                remotePort is not null && (BinaryPrimitives.ReadUInt32LittleEndian(row[12..])!=0x0100007f ||
                    BinaryPrimitives.ReadUInt16BigEndian(row[16..])!=remotePort))continue;
            matches++;owner=BinaryPrimitives.ReadUInt32LittleEndian(row[20..]);
        }
        if(matches!=1 || owner==0)throw new InvalidDataException("UniqueLoopbackTcpOwnerRequired");
        return owner;
    }
}
