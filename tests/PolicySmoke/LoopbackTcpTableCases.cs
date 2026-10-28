using System.Buffers.Binary;
using ClaudeCodeProtection.Security;

internal static class LoopbackTcpTableCases
{
    internal static void Run()
    {
        const int proxy=7890,client=43210;const uint held=101,foreign=202;
        var listener=Row(2,proxy,0,held);
        // A restored trusted listener must not bless an already accepted socket
        // owned by the process that temporarily replaced it.
        var swapped=Table(listener,Row(5,proxy,client,foreign));
        Check(LoopbackTcpTable.FindOwner(swapped,proxy,null)==held,"trusted listener observation");
        Check(LoopbackTcpTable.FindOwner(swapped,proxy,client)==foreign,"accepted peer differs despite trusted listener");
        var valid=Table(listener,Row(5,proxy,client,held),Row(5,proxy,client+1,foreign),Row(5,client,proxy,foreign));
        Check(LoopbackTcpTable.FindOwner(valid,proxy,client)==held,"exact reverse established tuple");
        foreach(var wrong in new[]{Row(5,proxy+1,client,held),Row(5,proxy,client+1,held),
            Row(2,proxy,client,held),Row(8,proxy,client,held),Row(5,proxy,client,0)})
            Refuse(Table(listener,wrong),proxy,client);
        foreach(var offset in new[]{4,12})
        {
            var wrong=Row(5,proxy,client,held);wrong[offset]=127;wrong[offset+3]=2;
            Refuse(Table(listener,wrong),proxy,client);
        }
        Refuse(Table(Row(5,proxy,client,held),Row(5,proxy,client,foreign)),proxy,client);
        Refuse(Table(listener,listener),proxy,null);
        Refuse(Array.Empty<byte>(),proxy,client);Refuse(new byte[1024*1024+1],proxy,client);
        var truncated=Table(Row(5,proxy,client,held));BinaryPrimitives.WriteUInt32LittleEndian(truncated,2);
        Refuse(truncated,proxy,client);
        Refuse(Table(listener),0,null);Refuse(Table(listener),65536,null);Refuse(Table(listener),proxy,-1);
    }
    private static byte[] Row(uint state,int local,int remote,uint pid)
    {
        var row=new byte[24];BinaryPrimitives.WriteUInt32LittleEndian(row,state);
        BinaryPrimitives.WriteUInt32LittleEndian(row.AsSpan(4),0x0100007f);
        BinaryPrimitives.WriteUInt16BigEndian(row.AsSpan(8),(ushort)local);
        BinaryPrimitives.WriteUInt32LittleEndian(row.AsSpan(12),0x0100007f);
        BinaryPrimitives.WriteUInt16BigEndian(row.AsSpan(16),(ushort)remote);
        BinaryPrimitives.WriteUInt32LittleEndian(row.AsSpan(20),pid);return row;
    }
    private static byte[] Table(params byte[][] rows)
    {
        var bytes=new byte[4+24*rows.Length];BinaryPrimitives.WriteUInt32LittleEndian(bytes,(uint)rows.Length);
        for(var i=0;i<rows.Length;i++)rows[i].CopyTo(bytes,4+i*24);return bytes;
    }
    private static void Refuse(byte[] bytes,int local,int? remote)
    {
        try{LoopbackTcpTable.FindOwner(bytes,local,remote);}catch(InvalidDataException){return;}
        throw new InvalidOperationException("TCP ownership case unexpectedly accepted");
    }
    private static void Check(bool condition,string reason)
    {if(!condition)throw new InvalidOperationException("TCP ownership: "+reason);}
}
