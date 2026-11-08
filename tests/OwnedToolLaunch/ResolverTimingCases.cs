using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Channels;

internal static class ResolverTimingCases
{
    private const BindingFlags Instance=BindingFlags.Instance|BindingFlags.NonPublic|BindingFlags.Public;

    internal static async Task Run(Assembly library)
    {
        using var request=new HttpRequestMessage(HttpMethod.Get,"https://resolver.invalid/dns-query?name=www.microsoft.com&type=A")
        {
            Version=HttpVersion.Version11,VersionPolicy=HttpVersionPolicy.RequestVersionExact
        };
        using var unrelated=new HttpRequestMessage(HttpMethod.Get,request.RequestUri);
        var timingType=library.GetType("ProtectionLifecycle.ResolverRequestTiming",true)!;
        object Bind(HttpRequestMessage message)=>Activator.CreateInstance(timingType,Instance,null,[message],null)!;
        var timing=Bind(request);
        var property=timingType.GetProperty("StartedAt",Instance)!;
        var method=timingType.GetMethod("OnAuthenticatedStream",Instance)!;
        var filter=method.CreateDelegate<Func<SocketsHttpPlaintextStreamFilterContext,CancellationToken,ValueTask<Stream>>>(timing);
        var wrong=method.CreateDelegate<Func<SocketsHttpPlaintextStreamFilterContext,CancellationToken,ValueTask<Stream>>>(Bind(unrelated));
        long StartedAt()=>(long)property.GetValue(timing)!;
        try{_=StartedAt();throw new InvalidOperationException("Missing resolver start accepted");}
        catch(TargetInvocationException error)when(error.InnerException is InvalidDataException){}

        var witness=library.GetType("ProtectionLifecycle.OpenSslOfflineWitness",true)!;
        var wireType=witness.GetNestedType("MemoryWire",BindingFlags.NonPublic)!;
        var toServer=Channel.CreateUnbounded<byte[]>();var toClient=Channel.CreateUnbounded<byte[]>();
        Stream Wire(ChannelReader<byte[]> from,ChannelWriter<byte[]> to)
            =>(Stream)Activator.CreateInstance(wireType,Instance,null,[from,to],null)!;
        using var clientWire=Wire(toClient.Reader,toServer.Writer);
        using var serverWire=Wire(toServer.Reader,toClient.Writer);
        using var key=RSA.Create(2048);
        var certificateRequest=new CertificateRequest("CN=resolver.invalid",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        var names=new SubjectAlternativeNameBuilder();names.AddDnsName("resolver.invalid");
        certificateRequest.CertificateExtensions.Add(names.Build());
        using var generated=certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1),DateTimeOffset.UtcNow.AddHours(1));
        // Windows Schannel requires a key associated with an OS key container.
        // Use the disposable user-key import, without persisting it or adding
        // the synthetic certificate to a trust store.
        var pfx=generated.Export(X509ContentType.Pfx);
        using var certificate=Import(pfx);
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var peer=new SslStream(serverWire,leaveInnerStreamOpen:true);
        var certificateObserved=0L;
        var tunnelStarts=0;
        using var handler=new SocketsHttpHandler
        {
            UseProxy=false,
            ConnectCallback=(_,_)=>Interlocked.Increment(ref tunnelStarts)==1?
                ValueTask.FromResult(clientWire):throw new InvalidOperationException("Fixture opened multiple connections"),
            SslOptions=new()
            {
                CertificateChainPolicy=new X509ChainPolicy{DisableCertificateDownloads=true,RevocationMode=X509RevocationMode.NoCheck},
                RemoteCertificateValidationCallback=(_,actual,_,errors)=>
                {
                    if(actual is null || (errors&~SslPolicyErrors.RemoteCertificateChainErrors)!=0 ||
                        !actual.GetRawCertData().AsSpan().SequenceEqual(certificate.RawData))return false;
                    Volatile.Write(ref certificateObserved,Stopwatch.GetTimestamp());
                    return true;
                }
            },
            PlaintextStreamFilter=(context,token)=>
            {
                Deny(()=>wrong(context,token));
                var result=filter(context,token);
                Deny(()=>filter(context,token));
                return result;
            }
        };
        using var http=new HttpClient(handler);
        var server=Serve();
        try
        {
            using var response=await http.SendAsync(request,deadline.Token);
            var seen=await server;
            if(response.StatusCode!=HttpStatusCode.OK || response.Headers.Age!=TimeSpan.FromSeconds(1) || tunnelStarts!=1 ||
                Volatile.Read(ref certificateObserved)<=0 || StartedAt()<certificateObserved || StartedAt()>seen)
                throw new InvalidDataException("Resolver start did not follow TLS and precede the DNS request");
            Console.WriteLine("PASS actual HttpClient TLS over in-memory streams: resolver start follows certificate validation, precedes DNS request and rejects duplicate or unrelated binding. No sockets or external requests.");
        }
        finally
        {
            deadline.Cancel();
            try{await server;}
            catch(OperationCanceledException)when(deadline.IsCancellationRequested){}
        }

        async Task<long> Serve()
        {
            await peer.AuthenticateAsServerAsync(new SslServerAuthenticationOptions{ServerCertificate=certificate},deadline.Token);
            var bytes=new byte[2048];
            var count=await peer.ReadAsync(bytes,deadline.Token);
            var received=Stopwatch.GetTimestamp();
            if(!Encoding.ASCII.GetString(bytes,0,count).StartsWith("GET /dns-query?name=www.microsoft.com&type=A HTTP/1.1\r\n",StringComparison.Ordinal))
                throw new InvalidDataException("Fixture DNS request differs");
            await peer.WriteAsync("HTTP/1.1 200 OK\r\nAge: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray(),deadline.Token);
            return received;
        }

        static void Deny(Func<ValueTask<Stream>> callback)
        {
            try{_=callback();throw new InvalidOperationException("Invalid resolver timing callback accepted");}
            catch(InvalidDataException){}
        }

        static X509Certificate2 Import(byte[] pfx)
        {
            try{return new X509Certificate2(pfx,(string?)null,X509KeyStorageFlags.UserKeySet);}
            finally{CryptographicOperations.ZeroMemory(pfx);}
        }
    }
}
