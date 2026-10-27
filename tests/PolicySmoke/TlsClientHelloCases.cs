using System.Text;
using ClaudeCodeProtection.Security;

internal static class TlsClientHelloCases
{
    private const string Host="www.microsoft.com";
    private static byte[] U16(int value)=>new[]{(byte)(value>>8),(byte)value};
    private static byte[] Join(params byte[][] parts)=>parts.SelectMany(p=>p).ToArray();
    private static byte[] Extension(int type,byte[] data)=>Join(U16(type),U16(data.Length),data);
    private static byte[] Sni(string host)
    {var name=Encoding.UTF8.GetBytes(host);var entry=Join(new byte[]{0},U16(name.Length),name);return Extension(0,Join(U16(entry.Length),entry));}
    private static byte[] Alpn(params string[] protocols)
    {
        var list=protocols.SelectMany(p=>Join(new[]{(byte)p.Length},Encoding.ASCII.GetBytes(p))).ToArray();
        return Extension(16,Join(U16(list.Length),list));
    }
    private static byte[] Hello(params byte[][] extensions)
    {
        var extra=Join(extensions);
        var body=Join(new byte[]{3,3},new byte[32],new byte[]{0,0,2,0x13,1,1,0},U16(extra.Length),extra);
        return Join(new[]{(byte)1,(byte)(body.Length>>16),(byte)(body.Length>>8),(byte)body.Length},body);
    }
    private static byte[] Record(byte[] bytes)=>Join(new byte[]{22,3,1},U16(bytes.Length),bytes);
    private static void Check(bool condition,string message)
    {if(!condition)throw new InvalidOperationException("TlsClientHello: "+message);}
    private static void Refuse(byte[] bytes)
    {
        try{ProxyDestinationPolicy.ValidateTlsClientHello(Host,bytes);}
        catch(InvalidDataException){return;}
        throw new InvalidOperationException("TlsClientHello: unsafe handshake accepted");
    }
    private static async Task RefuseWire(byte[] wire)
    {
        using var input=new SessionTunnelCases.Endpoint(wire,true){MaximumRead=1};
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(2));
        try{using var view=await SessionTunnel.RequireTlsClientHelloAsync(input,Host,()=>{},deadline.Token);}
        catch(IOException){return;}
        throw new InvalidOperationException("TlsClientHello: unsafe record accepted");
    }
    internal static async Task RunAsync()
    {
        var hello=Hello(Sni(Host),Alpn("h2","http/1.1"),Extension(43,new byte[]{2,3,4}),Extension(0x0a0a,Array.Empty<byte>()));
        ProxyDestinationPolicy.ValidateTlsClientHello(Host,hello);
        ProxyDestinationPolicy.ValidateTlsClientHello(Host,Hello(Sni(Host.ToUpperInvariant())));
        foreach(var name in new[]{"localhost","router.local","127.0.0.1","api.anthropic.com",Host+".",Host+"\0.other",Host+"é"})Refuse(Hello(Sni(name)));
        foreach(var extensions in new[]{Array.Empty<byte[]>(),new[]{Alpn("h2")},new[]{Sni(Host),Sni(Host)},
            new[]{Sni(Host),Alpn("h2"),Alpn("http/1.1")},new[]{Sni(Host),Alpn()},new[]{Sni(Host),Alpn("h3")},
            new[]{Sni(Host),Alpn("h2","h2")}})Refuse(Hello(extensions));
        foreach(var hidden in new[]{65037,64768,65486})Refuse(Hello(Sni(Host),Extension(hidden,new byte[]{0})));
        Refuse(hello[..^1]);Refuse(Join(hello,new byte[]{0}));
        foreach(var change in new[]{(0,(byte)2),(1,(byte)1),(4,(byte)2),(38,(byte)33),(40,(byte)3),(43,(byte)0),(44,(byte)1)})
        {var invalid=(byte[])hello.Clone();invalid[change.Item1]=change.Item2;Refuse(invalid);}
        // Reassemble record and stream fragmentation, then use the ACTUAL
        // duplex copier: the replay must preserve/charge every original byte.
        foreach(var fragmented in new[]{false,true})
        {
            var records=fragmented?Join(Record(hello[..2]),Record(hello[2..17]),Record(hello[17..])):Record(hello);
            var wire=Join(records,new byte[]{23,3,3,0,1,42});
            using var input=new SessionTunnelCases.Endpoint(wire,true){MaximumRead=1};
            using var output=new SessionTunnelCases.Endpoint(Array.Empty<byte>(),true);
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(2));
            using var view=await SessionTunnel.RequireTlsClientHelloAsync(input,Host,()=>{},deadline.Token);long charged=0;
            await SessionTunnel.CopyAsync(view,output,input.FinishSending,output.FinishSending,n=>charged+=n,65536,()=>{},deadline.Token);
            Check(output.Written.SequenceEqual(wire) && charged==wire.Length,"prefix/tail replay changed or omitted bytes from accounting");
        }
        await RefuseWire(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n\r\n"));
        await RefuseWire(Join(new byte[]{23,3,3},U16(hello.Length),hello));
        await RefuseWire(Record(hello)[..^1]);await RefuseWire(Record(Join(hello,new byte[]{1,0,0,0})));
        await RefuseWire(Join(new byte[]{22,3,1,0x40,1},new byte[16385]));
        await RefuseWire(Enumerable.Range(0,8).SelectMany(i=>Record(hello[i..(i+1)])).ToArray());
        // Permission disappears while the record is being read; no validated
        // replay view can escape with the old permission.
        using(var input=new SessionTunnelCases.Endpoint(Record(hello),false))
        using(var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(2)))
        {
            var live=true;
            void Authorized(){if(!live)throw new InvalidOperationException("owned revoked permission");}
            var pending=SessionTunnel.RequireTlsClientHelloAsync(input,Host,Authorized,deadline.Token);
            live=false;input.OpenRead();
            try{using var view=await pending;throw new InvalidDataException("Revoked handshake returned a replay view");}
            catch(InvalidOperationException){}
            Check(input.ActiveReads==0,"revoked handshake reader not drained");
        }
    }
}
