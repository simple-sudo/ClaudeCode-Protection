using System.Buffers.Binary;
using System.Text.Json;
using ProtectionLifecycle;

if(args.Length==2 && args[0]=="reference"){HostReference.Run(Path.GetFullPath(args[1]));return 0;}
if(args.Length==3 && args[0]=="decode")
{
    // Only consumes retained data. Input is untrusted, never a live pointer.
    if(new FileInfo(args[1]).Length is <1 or >524288)throw new InvalidDataException("Retained capture size bounds");
    using var json=JsonDocument.Parse(File.ReadAllBytes(args[1]));var r=json.RootElement;
    object output;
    if(!r.GetProperty("Complete").GetBoolean() || r.GetProperty("Phase").GetString()!="COMPLETE_BUFFER" || r.GetProperty("ReadStatus").GetUInt32()!=0)
        output=new {Status="UNKNOWN_OR_READ_FAILED_NOT_PRIVACY_PASS"};
    else
    {
        var bytes=Convert.FromBase64String(r.GetProperty("RawBase64").GetString()!);
        if(r.GetProperty("API").GetString()=="GetAdaptersAddresses")
            output=NetworkContentSnapshot.DecodeAdapters(bytes,Convert.ToUInt64(r.GetProperty("BufferBase").GetString()![2..],16),8);
        else if(r.GetProperty("API").GetString()=="GetExtendedTcpTable")output=NetworkContentSnapshot.DecodeTcp(bytes,r.GetProperty("Family").GetUInt32());
        else throw new InvalidDataException("Unknown retained API");
    }
    using var file=new FileStream(args[2],FileMode.CreateNew,FileAccess.Write,FileShare.None);
    file.Write(JsonSerializer.SerializeToUtf8Bytes(output,new JsonSerializerOptions{WriteIndented=true}));return 0;
}
if(args.Length!=1 || args[0]!="selftest")return 125;
int passed=0;
void Check(bool condition){if(!condition)throw new Exception("Decoder assertion failed");passed++;}
void Reject(Action action){try{action();}catch(InvalidDataException){passed++;return;}throw new Exception("Malformed snapshot accepted");}
void U32(byte[] b,int p,uint v)=>BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(p,4),v);
void Ptr(byte[] b,int p,ulong v)=>BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(p,8),v);
var tcp4=new byte[28];U32(tcp4,0,1);U32(tcp4,4,5);tcp4[8]=192;tcp4[9]=168;tcp4[10]=1;tcp4[11]=7;
tcp4[12]=0x12;tcp4[13]=0x34;tcp4[16]=1;tcp4[17]=2;tcp4[18]=3;tcp4[19]=4;tcp4[20]=1;tcp4[21]=0xbb;U32(tcp4,24,913);
var row=NetworkContentSnapshot.DecodeTcp(tcp4,2).Single();Check(row.LocalAddress=="192.168.1.7" && row.LocalPort==4660 && row.RemoteAddress=="1.2.3.4" && row.RemotePort==443 && row.Pid==913);
U32(tcp4,4,2);row=NetworkContentSnapshot.DecodeTcp(tcp4,2).Single();Check(row.RemoteAddress is null && row.RemotePort is null);
Reject(()=>NetworkContentSnapshot.DecodeTcp(tcp4[..^1],2));Reject(()=>NetworkContentSnapshot.DecodeTcp(new byte[5],2));
U32(tcp4,0,uint.MaxValue);Reject(()=>NetworkContentSnapshot.DecodeTcp(tcp4,2));Reject(()=>NetworkContentSnapshot.DecodeTcp(new byte[4],10));
var tcp6=new byte[60];U32(tcp6,0,1);tcp6[4]=0xfe;tcp6[5]=0x80;tcp6[19]=1;tcp6[23]=7;tcp6[24]=0x1f;tcp6[25]=0x90;
tcp6[43]=2;tcp6[47]=8;tcp6[48]=0;tcp6[49]=80;U32(tcp6,52,5);U32(tcp6,56,17);
row=NetworkContentSnapshot.DecodeTcp(tcp6,23).Single();Check(row.LocalAddress=="fe80::1" && row.LocalScopeId==7 && row.LocalPort==8080 && row.RemoteAddress=="::2" && row.RemoteScopeId==8 && row.RemotePort==80 && row.Pid==17);
U32(tcp6,52,99);Reject(()=>NetworkContentSnapshot.DecodeTcp(tcp6,23));
const ulong origin=0x100000000;var adapters=new byte[512];U32(adapters,0,448);U32(adapters,4,12);Ptr(adapters,16,origin+448);adapters[448]=(byte)'a';
U32(adapters,88,6);for(int i=0;i<6;i++)adapters[80+i]=(byte)(i+1);U32(adapters,100,71);U32(adapters,104,1);
var adapter=NetworkContentSnapshot.DecodeAdapters(adapters,origin,8).Single();Check(adapter.Name=="a" && adapter.Mac=="010203040506" && adapter.IfIndex==12 && adapter.Type==71);
Ptr(adapters,8,origin);Reject(()=>NetworkContentSnapshot.DecodeAdapters(adapters,origin,8));Ptr(adapters,8,0);
Ptr(adapters,16,origin-1);Reject(()=>NetworkContentSnapshot.DecodeAdapters(adapters,origin,8));Ptr(adapters,16,origin+512);Reject(()=>NetworkContentSnapshot.DecodeAdapters(adapters,origin,8));
Ptr(adapters,16,origin+448);U32(adapters,88,9);Reject(()=>NetworkContentSnapshot.DecodeAdapters(adapters,origin,8));U32(adapters,88,6);
Reject(()=>NetworkContentSnapshot.DecodeAdapters(adapters,origin,4));Reject(()=>NetworkContentSnapshot.DecodeAdapters(adapters,ulong.MaxValue,8));
var addresses=new byte[768];adapters.CopyTo(addresses,0);Ptr(addresses,24,origin+512);U32(addresses,512,64);Ptr(addresses,528,origin+640);U32(addresses,536,16);addresses[568]=24;addresses[640]=2;addresses[644]=10;addresses[647]=8;
adapter=NetworkContentSnapshot.DecodeAdapters(addresses,origin,8).Single();Check(adapter.Unicast.Single().Value=="10.0.0.8" && adapter.Unicast[0].PrefixLength==24);
Ptr(addresses,520,origin+512);Reject(()=>NetworkContentSnapshot.DecodeAdapters(addresses,origin,8));Ptr(addresses,520,0);
addresses[568]=33;Reject(()=>NetworkContentSnapshot.DecodeAdapters(addresses,origin,8));addresses[568]=24;
Ptr(addresses,528,origin+760);Reject(()=>NetworkContentSnapshot.DecodeAdapters(addresses,origin,8));
Ptr(addresses,528,origin+640);Ptr(addresses,48,origin+512);Ptr(addresses,208,origin+512);
adapter=NetworkContentSnapshot.DecodeAdapters(addresses,origin,8).Single();Check(adapter.Dns.Single().Value=="10.0.0.8" && adapter.Gateways.Single().Value=="10.0.0.8");
Ptr(addresses,72,origin+704);var text=System.Text.Encoding.Unicode.GetBytes("网络");text.CopyTo(addresses,704);
Check(NetworkContentSnapshot.DecodeAdapters(addresses,origin,8).Single().FriendlyName=="网络");
Ptr(addresses,72,origin+766);addresses[766]=65;addresses[767]=66;Reject(()=>NetworkContentSnapshot.DecodeAdapters(addresses,origin,8));
Console.WriteLine(JsonSerializer.Serialize(new {Scope="BOUNDED_DECODER_FIXTURES_ONLY",Passed=passed,NativeCalls=false,PrivacyQualified=false}));return 0;
