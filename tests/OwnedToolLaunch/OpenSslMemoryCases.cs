using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;

internal static class OpenSslMemoryCases
{
    // This is just an in-memory SNI. The trust root is generated for this
    // test and is never installed or used to contact that host.
    private const string Host="www.microsoft.com";
    private const string CryptoHash="CA9E9C0400B0DA1A242670262CC45CF71389E8CA08519281C68E7BB960FEAC16";
    private const string SslHash="3A5DAF9BB851619EECFF5E492906E66279882934F32C603415B181C7A55CED2E";
    private const BindingFlags Instance=BindingFlags.Instance|BindingFlags.NonPublic;

    internal static async Task Run(Assembly library)
    {
        var type=library.GetType("ProtectionLifecycle.OpenSslMemoryConnection",true)!;
        var fixturePeer=type.GetMethod("CreateOfflineFixturePeer",BindingFlags.Static|BindingFlags.NonPublic)!;
        var gatewayParser=library.GetType("ClaudeCodeProtection.Security.SessionTunnel",true)!
            .GetMethod("RequireTlsClientHelloAsync",BindingFlags.Static|BindingFlags.NonPublic)!;
        var dir=Path.Combine(AppContext.BaseDirectory,"native");
        using var crypto=new OrdinaryModule(dir,"libcrypto-3-x64.dll",7986688,CryptoHash);
        using var ssl=new OrdinaryModule(dir,"libssl-3-x64.dll",1581568,SslHash);
        using var caKey=RSA.Create(2048);
        using var ca=CreateCa(caKey,"CN=Fixed local TLS test root");
        using var wrongCaKey=RSA.Create(2048);
        using var wrongCa=CreateCa(wrongCaKey,"CN=Independent local TLS test root");
        using var key=RSA.Create(2048);
        var request=new CertificateRequest("CN=deliberate-mismatch.invalid",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        var san=new SubjectAlternativeNameBuilder();
        san.AddDnsName(Host);request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature,true));
        var now=DateTimeOffset.UtcNow;
        using var issued=request.Create(ca,now.AddMinutes(-5),now.AddHours(1),RandomNumberGenerator.GetBytes(16));
        var serverKey=key.ExportPkcs8PrivateKey();
        try
        {
            await Exchange(Host,ca.RawData,null);
            await Exchange("deliberate-mismatch.invalid",ca.RawData,62); // CN must not substitute for SAN.
            await Exchange(Host,wrongCa.RawData,20);
            await CheckEarlyEof(ca.RawData);
        }
        finally{CryptographicOperations.ZeroMemory(serverKey);}
        Console.WriteLine("PASS ordinary exact OpenSSL Windows modules: real TLS through production gateway ClientHello replay, encrypted request/reply, wrong trust anchor and SAN rejected, early EOF fails closed. Memory only.");

        IDisposable CreateClient(Stream wire,string host,byte[] anchor)
            =>(IDisposable)Activator.CreateInstance(type,Instance,null,[ssl.Handle,crypto.Handle,wire,host,anchor],null)!;
        Task Invoke(IDisposable actor,string name,params object[] args)=>(Task)type.GetMethod(name,Instance)!.Invoke(actor,args)!;

        async Task Exchange(string host,byte[] anchor,int? expectedVerificationError)
        {
            var outgoing=Channel.CreateUnbounded<byte[]>();var incoming=Channel.CreateUnbounded<byte[]>();
            using var clientWire=new MemoryWire(incoming.Reader,outgoing.Writer);
            using var serverWire=new MemoryWire(outgoing.Reader,incoming.Writer);
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(8));
            using var client=CreateClient(clientWire,host,anchor);
            var server=Serve();
            try
            {
                await Invoke(client,"AuthenticateAsync",timeout.Token);
                if(expectedVerificationError is not null)throw new InvalidDataException("Bad TLS identity was accepted");
                await Invoke(client,"WriteAsync",new byte[]{19,43,71},timeout.Token);
                var response=new byte[3];
                int read=await (Task<int>)Invoke(client,"ReadAsync",response,timeout.Token);
                if(read!=3 || !response.AsSpan().SequenceEqual(new byte[]{89,53,11}))
                    throw new InvalidDataException("Encrypted application reply differs");
                await server;
            }
            catch(IOException error) when(expectedVerificationError is not null && error.GetType().FullName=="ProtectionLifecycle.OpenSslFailure")
            {
                timeout.Cancel();
                try{await server;}catch(Exception e)when(e is OperationCanceledException or IOException){}
                if((int?)error.GetType().GetProperty("NativeError",Instance)!.GetValue(error)!=1 ||
                    (int?)error.GetType().GetProperty("VerificationError",Instance)!.GetValue(error)!=expectedVerificationError)
                    throw new InvalidDataException("TLS rejection did not identify the expected certificate error",error);
            }
            catch
            {
                timeout.Cancel();
                if(server.IsFaulted)await server;
                throw;
            }
            async Task Serve()
            {
                try
                {
                    var parsed=expectedVerificationError is null?
                        await (Task<Stream>)gatewayParser.Invoke(null,[serverWire,Host,(Action)(()=>{}),timeout.Token])!:null;
                    using var replay=parsed;
                    using var peer=(IDisposable)fixturePeer.Invoke(null,[ssl.Handle,crypto.Handle,replay??serverWire,issued.RawData,serverKey])!;
                    await Invoke(peer,"AuthenticateAsync",timeout.Token);
                    var request=new byte[3];
                    var count=await (Task<int>)Invoke(peer,"ReadAsync",request,timeout.Token);
                    if(count!=3 || !request.AsSpan().SequenceEqual(new byte[]{19,43,71}))
                        throw new InvalidDataException("Encrypted application request differs");
                    await Invoke(peer,"WriteAsync",new byte[]{89,53,11},timeout.Token);
                }
                catch(Exception failure){serverWire.Complete(failure);throw;}
            }
        }

        async Task CheckEarlyEof(byte[] anchor)
        {
            var outgoing=Channel.CreateUnbounded<byte[]>();var incoming=Channel.CreateUnbounded<byte[]>();
            incoming.Writer.Complete();
            using var wire=new MemoryWire(incoming.Reader,outgoing.Writer);
            using var client=CreateClient(wire,Host,anchor);
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try
            {
                await Invoke(client,"AuthenticateAsync",timeout.Token);
                throw new InvalidDataException("Truncated TLS stream authenticated");
            }
            catch(EndOfStreamException){}
            try
            {
                await Invoke(client,"WriteAsync",new byte[]{19,43,71},timeout.Token);
            }
            catch(InvalidOperationException){return;}
            throw new InvalidDataException("Application data was accepted after failed authentication");
        }
    }

    private static X509Certificate2 CreateCa(RSA key,string subject)
    {
        var request=new CertificateRequest(subject,key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign,true));
        var now=DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddHours(-1),now.AddHours(2));
    }
    private sealed class MemoryWire(ChannelReader<byte[]> reader,ChannelWriter<byte[]> writer) : Stream
    {
        private ReadOnlyMemory<byte> pending;
        public override bool CanRead=>true;
        public override bool CanSeek=>false;
        public override bool CanWrite=>true;
        public override long Length=>throw new NotSupportedException();
        public override long Position {get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
        public override void Flush(){}
        public override long Seek(long offset,SeekOrigin origin)=>throw new NotSupportedException();
        public override void SetLength(long value)=>throw new NotSupportedException();
        public override int Read(byte[] b,int o,int n)=>throw new NotSupportedException();
        public override void Write(byte[] b,int o,int n)=>throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(Memory<byte> data,CancellationToken cancel=default)
        {
            if(pending.IsEmpty)
            {
                if(!await reader.WaitToReadAsync(cancel))return 0;
                pending=await reader.ReadAsync(cancel);
            }
            var count=Math.Min(data.Length,pending.Length);
            pending[..count].CopyTo(data);pending=pending[count..];
            return count;
        }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> data,CancellationToken cancel=default)
            =>writer.WriteAsync(data.ToArray(),cancel);
        internal void Complete(Exception failure)=>writer.TryComplete(failure);
    }

    private sealed class OrdinaryModule : IDisposable
    {
        private readonly FileStream file;
        internal IntPtr Handle {get;}
        internal OrdinaryModule(string dir,string leaf,long length,string hash)
        {
            var path=Path.Combine(dir,leaf);
            if(GetModuleHandle(leaf)!=IntPtr.Zero)throw new InvalidDataException("Unexpected already loaded fixture module");
            file=File.Open(path,FileMode.Open,FileAccess.Read,FileShare.Read);
            try
            {
                if(file.Length!=length || Convert.ToHexString(SHA256.HashData(file))!=hash)
                    throw new InvalidDataException("Ordinary test module digest differs");
                Handle=LoadLibrary(path,IntPtr.Zero,0x900); // exact DLL load directory and System32
                if(Handle==IntPtr.Zero)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
            catch{file.Dispose();throw;}
        }
        public void Dispose(){NativeLibrary.Free(Handle);file.Dispose();}
    }
    [DllImport("kernel32.dll",EntryPoint="LoadLibraryExW",SetLastError=true,CharSet=CharSet.Unicode)]
    private static extern IntPtr LoadLibrary(string path,IntPtr reserved,uint flags);
    [DllImport("kernel32.dll",EntryPoint="GetModuleHandleW",CharSet=CharSet.Unicode)]
    private static extern IntPtr GetModuleHandle(string name);
}
