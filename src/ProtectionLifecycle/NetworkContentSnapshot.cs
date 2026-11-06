using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace ProtectionLifecycle;

// Trusted-side decoding of retained IP Helper buffers. Never dereferences an
// exported address, loads code, grants access, or issues an admission decision.
internal static class NetworkContentSnapshot
{
    internal sealed record Address(string Value,uint ScopeId,int? PrefixLength);
    internal sealed record Adapter(uint IfIndex,string Name,string Description,string FriendlyName,string DnsSuffix,
        string Mac,uint Type,uint Status,uint Ipv6Index,Address[] Unicast,Address[] Dns,Address[] Gateways);
    internal sealed record Tcp(uint State,string LocalAddress,uint LocalScopeId,int LocalPort,
        string? RemoteAddress,uint? RemoteScopeId,int? RemotePort,uint Pid);

    internal static Tcp[] DecodeTcp(byte[] bytes,uint family)
    {
        if(bytes.Length is <4 or >262144 || family is not (2 or 23))throw Bad("TcpBoundsOrFamily");
        var count=U32(bytes,0);var stride=family==2?24:56;
        // SDK SIZEOF_TCPTABLE_OWNER_PID/SIZEOF_TCP6TABLE_OWNER_PID includes
        // ALIGN_SIZE (8) beyond the counted rows. Native GetExtendedTcpTable
        // returned exactly that length in the retained real host reference.
        // Keep supporting packed retained fixtures, and reject every other
        // length. Padding is retained in the raw evidence, never decoded as a
        // row or used as a privacy/actor observation.
        var rowsEnd=4+(long)count*stride;
        if(count>(bytes.Length-4)/stride || bytes.Length!=rowsEnd && bytes.Length!=rowsEnd+8)throw Bad("TcpCountOrTrailingBytes");
        var result=new Tcp[count];
        for(int i=0;i<result.Length;i++)
        {
            int p=4+i*stride;uint state=U32(bytes,p+(family==2?0:48));
            if(state is <1 or >12)throw Bad("TcpState");
            bool listener=state==2;
            result[i]=family==2
                ?new(state,Ip(bytes,p+4,4),0,Port(bytes,p+8),listener?null:Ip(bytes,p+12,4),listener?null:0,listener?null:Port(bytes,p+16),U32(bytes,p+20))
                :new(state,Ip(bytes,p,16),Big32(bytes,p+16),Port(bytes,p+20),listener?null:Ip(bytes,p+24,16),listener?null:Big32(bytes,p+40),listener?null:Port(bytes,p+44),U32(bytes,p+52));
        }
        return result;
    }

    // Explicit x64 ABI. Unknown architectures/layouts must remain UNKNOWN.
    internal static Adapter[] DecodeAdapters(byte[] bytes,ulong originalBase,int pointerSize)
    {
        if(pointerSize!=8 || bytes.Length is <112 or >262144 || originalBase==0 || originalBase>ulong.MaxValue-(ulong)bytes.Length)
            throw Bad("AdapterAbiOrBuffer");
        var buffer=new RelativeBuffer(bytes,originalBase);var result=new List<Adapter>();
        var seen=new HashSet<int>();int p=0;
        while(true)
        {
            if(!seen.Add(p) || seen.Count>512)throw Bad("AdapterCycleOrCount");
            uint length=U32(bytes,p);if(length<112 || length>bytes.Length-p)throw Bad("AdapterLength");
            var macLength=U32(bytes,p+88);if(macLength>8)throw Bad("MacLength");
            result.Add(new(U32(bytes,p+4),buffer.Text(p+16,false),buffer.Text(p+64,true),buffer.Text(p+72,true),buffer.Text(p+56,true),
                Convert.ToHexString(bytes.AsSpan(p+80,(int)macLength)),U32(bytes,p+100),U32(bytes,p+104),U32(bytes,p+108),
                buffer.Addresses(p+24,true),buffer.Addresses(p+48,false),length>=216?buffer.Addresses(p+208,false):Array.Empty<Address>()));
            int? next=buffer.Pointer(p+8,112);if(next is null)break;p=next.Value;
        }
        return result.ToArray();
    }

    private sealed class RelativeBuffer(byte[] bytes,ulong origin)
    {
        internal int? Pointer(int location,int minimum)
        {
            Check(bytes,location,8);ulong pointer=BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(location,8));
            if(pointer==0)return null;
            if(pointer<origin || pointer-origin>(ulong)bytes.Length || (ulong)minimum>(ulong)bytes.Length-(pointer-origin))throw Bad("PointerOutsideRetainedBuffer");
            return (int)(pointer-origin);
        }
        internal string Text(int location,bool unicode)
        {
            int? start=Pointer(location,unicode?2:1);if(start is null)return "";
            int step=unicode?2:1;int p=start.Value;
            for(int n=0;n<=2048;n++,p+=step)
            {
                Check(bytes,p,step);
                if(bytes[p]==0 && (!unicode || bytes[p+1]==0))
                    return unicode?new UnicodeEncoding(false,false,true).GetString(bytes,start.Value,p-start.Value)
                        :new UTF8Encoding(false,true).GetString(bytes,start.Value,p-start.Value);
            }
            throw Bad("StringNotTerminatedWithinLimit");
        }
        internal Address[] Addresses(int location,bool unicast)
        {
            var result=new List<Address>();var seen=new HashSet<int>();var p=Pointer(location,32);
            while(p is int row)
            {
                if(!seen.Add(row) || seen.Count>2048)throw Bad("AddressCycleOrCount");
                uint length=U32(bytes,row);if(length<32 || length>bytes.Length-row || unicast && length<57)throw Bad("AddressNodeLength");
                int size=checked((int)U32(bytes,row+24));var address=Pointer(row+16,size);
                if(address is null)throw Bad("NullSocketAddress");
                int a=address.Value;Check(bytes,a,2);int family=BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(a,2));
                int? prefix=unicast?bytes[row+56]:null;
                if(family==2 && size>=16 && prefix is not >32)result.Add(new(Ip(bytes,a+4,4),0,prefix));
                else if(family==23 && size>=28 && prefix is not >128)result.Add(new(Ip(bytes,a+8,16),U32(bytes,a+24),prefix));
                else throw Bad("SocketAddressFamilySizeOrPrefix");
                p=Pointer(row+8,32);
            }
            return result.ToArray();
        }
    }
    private static int Port(byte[] bytes,int p){Check(bytes,p,4);return BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(p,2));}
    private static uint Big32(byte[] bytes,int p){Check(bytes,p,4);return BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(p,4));}
    private static uint U32(byte[] bytes,int p){Check(bytes,p,4);return BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(p,4));}
    private static string Ip(byte[] bytes,int p,int size){Check(bytes,p,size);return new IPAddress(bytes.AsSpan(p,size)).ToString();}
    private static void Check(byte[] bytes,int p,int size){if(p<0 || size<0 || p>bytes.Length-size)throw Bad("FieldOutsideRetainedBuffer");}
    private static InvalidDataException Bad(string reason)=>new("NetworkContent:"+reason);
}
