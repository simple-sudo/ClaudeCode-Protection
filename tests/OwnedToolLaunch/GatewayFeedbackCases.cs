using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

internal static class GatewayFeedbackCases
{
    internal static void Run(Assembly library)
    {
        var type=library.GetType("ProtectionLifecycle.GatewayChildReport",true)!;var count=0;
        var id=new string('a',32);var pid=(uint)Environment.ProcessId;
        object? Call(string method,params object?[] values)
        {
            try{return type.GetMethod(method,BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,values);}
            catch(TargetInvocationException ex)when(ex.InnerException is not null){ExceptionDispatchInfo.Capture(ex.InnerException).Throw();throw;}
        }
        void Check(bool good){if(!good)throw new InvalidOperationException("Gateway feedback fixture mismatch");count++;}
        string Result(string phase,int code,int? status=null,Exception? error=null)
        {var value=Call("Result",id,phase,code,status,error)!;return JsonSerializer.Serialize(value,value.GetType());}
        void Accept(string raw,uint code){Check(Call("Parse",raw,id,pid,code) is not null);}
        void Refuse(string raw,uint code=42)
        {
            var refused=false;try{Call("Parse",raw,id,pid,code);}catch(Exception ex)when(ex is InvalidDataException or JsonException){refused=true;}Check(refused);
        }
        var good=Result("COMPLETE",42,204);Accept(good,42);
        Accept(Result("IDENTITY",125),125);Accept(Result("HTTPS",126,407),126);
        var error=Result("HTTPS",125,error:new HttpRequestException("fixture-secret-url-and-token",new SocketException(10013)));
        Accept(error,125);Check(!error.Contains("fixture-secret",StringComparison.Ordinal) && !error.Contains("Message",StringComparison.Ordinal) && !error.Contains("Stack",StringComparison.Ordinal));
        var node=JsonNode.Parse(error)!;Check(node["Errors"]!.AsArray().Count==2 && node["Errors"]![1]!["Kind"]!.GetValue<string>()=="SOCKET" && node["Errors"]![1]!["Code"]!.GetValue<int>()==10013);
        Exception nested=new InvalidOperationException("private-fixture");for(var i=0;i<8;i++)nested=new InvalidOperationException("private-fixture",nested);
        var bounded=Result("HTTPS",125,error:nested);Check(JsonNode.Parse(bounded)!["Errors"]!.AsArray().Count==4 && !bounded.Contains("private-fixture",StringComparison.Ordinal));Accept(bounded,125);
        string Mutate(Action<JsonObject> edit){var n=JsonNode.Parse(good)!.AsObject();edit(n);return n.ToJsonString();}
        foreach(var raw in new[]{"", "{",good+good,good.Replace("\"SchemaVersion\":1","\"SchemaVersion\":1,\"SchemaVersion\":1"),
            Mutate(n=>n["Extra"]="private-path"),Mutate(n=>n.Remove("Phase")),Mutate(n=>n["SessionId"]=new string('b',32)),
            Mutate(n=>n["Pid"]=Environment.ProcessId+1),Mutate(n=>n["SchemaVersion"]=2),Mutate(n=>n["Phase"]="OPEN_HOST_PATH"),
            Mutate(n=>n["HttpStatus"]=403),Mutate(n=>n["HttpStatus"]=null),Mutate(n=>n["Errors"]=null),
            Mutate(n=>n["Errors"]=new JsonArray(new JsonObject{["Kind"]="private-type",["Code"]=5})),new string('x',4097)})Refuse(raw);
        Refuse(good,125);Refuse(Result("COMPLETE",125),125);Refuse(Result("HTTPS",126,200),126);
        var noErrors=JsonNode.Parse(error)!;noErrors["Errors"]=new JsonArray();Refuse(noErrors.ToJsonString(),125);
        var many=JsonNode.Parse(error)!;many["Errors"]=new JsonArray(Enumerable.Range(0,5).Select(_=>(JsonNode)new JsonObject{["Kind"]="HTTP",["Code"]=1}).ToArray());Refuse(many.ToJsonString(),125);
        string Read(byte[] data)
        {
            using var stream=new MemoryStream(data);using var reader=new StreamReader(stream,new UTF8Encoding(false,true));
            return ((Task<string>)Call("ReadBounded",reader)!).GetAwaiter().GetResult();
        }
        Check(Read(Encoding.UTF8.GetBytes(good+"\r\n"))==good+"\r\n");
        Check(Read(Encoding.UTF8.GetBytes(good.PadRight(4096)))==good.PadRight(4096));Accept(good.PadRight(4096),42);
        var oversized=false;try{Read(Encoding.UTF8.GetBytes(new string('x',4097)));}catch(InvalidDataException){oversized=true;}Check(oversized);
        var invalidUtf8=false;try{Read(new byte[]{255});}catch(DecoderFallbackException){invalidUtf8=true;}Check(invalidUtf8);
        foreach(var phase in new[]{"TIMEZONE_DEFINITION","TIMEZONE_PUBLIC_CACHE","TIMEZONE_LOCAL_BINDING","HTTPS_SETTINGS","HTTPS_TLS_POLICY","HTTPS_CLIENT","HTTPS_SEND","HTTPS_SOCKET_INITIALIZATION","HTTPS_SOCKET_CREATE","HTTPS_CONNECT","HTTPS_CONNECT_WRITE","HTTPS_CONNECT_REPLY"})Accept(Result(phase,125,error:new System.Security.SecurityException("private-fixture")),125);
        foreach(var phase in new[]{"HTTPS_TLS_HANDSHAKE","HTTPS_HTTP_EXCHANGE"})
        {
            var failure=Result(phase,125,error:new System.Security.Authentication.AuthenticationException("private-fixture"));
            Accept(failure,125);
            Refuse(failure,42);
            Refuse(Result(phase,125,200,new System.Security.Authentication.AuthenticationException()),125);
        }
        var runtime=typeof(System.Net.Security.SslStream).Assembly;
        var sspi=runtime.GetType("System.Net.SSPIWrapper",true)!;
        var pal=runtime.GetType("System.Net.Security.SslStreamPal",true)!;
        const BindingFlags staticMethods=BindingFlags.Static|BindingFlags.NonPublic|BindingFlags.Public;
        Check(Call("SchannelFrame",sspi.GetMethod("EnumerateSecurityPackages",staticMethods),true) is "TLS_SCHANNEL_ENUMERATE");
        Check(Call("SchannelFrame",sspi.GetMethod("GetVerifyPackageInfo",staticMethods),false) is "TLS_SCHANNEL_PACKAGE_MISSING");
        Check(Call("SchannelFrame",pal.GetMethod("AcquireCredentialsHandleSchCredentials",staticMethods),true) is "TLS_SCHANNEL_ACQUIRE");
        Check(Call("SchannelFrame",pal.GetMethod("AcquireCredentialsHandleSchannelCred",staticMethods),true) is "TLS_SCHANNEL_ACQUIRE");
        Check(Call("SchannelFrame",pal.GetMethod("VerifyPackageInfo",staticMethods),true) is null);
        Check(Call("SchannelFrame",pal.GetMethod("InitializeSecurityContext",staticMethods),true) is null);
        Check(Call("SchannelFrame",type.GetMethod("Result",staticMethods),true) is null);
        Check(Call("SchannelFrame",null,true) is null);
        const int packageStatus=unchecked((int)0x80090305);
        var ambiguous=Result("HTTPS_TLS_HANDSHAKE",125,error:new System.ComponentModel.Win32Exception(packageStatus,"private-fixture"));
        Accept(ambiguous,125);
        Check(JsonNode.Parse(ambiguous)!["Errors"]![0]!["Kind"]!.GetValue<string>()=="NATIVE");
        Check(!ambiguous.Contains("private-fixture",StringComparison.Ordinal));
        foreach(var kind in new[]{"TLS_SCHANNEL_ENUMERATE","TLS_SCHANNEL_PACKAGE_MISSING","TLS_SCHANNEL_ACQUIRE"})
        {
            var categorized=JsonNode.Parse(ambiguous)!;
            categorized["Errors"]![0]!["Kind"]=kind;
            Accept(categorized.ToJsonString(),125);
            categorized["Phase"]="HTTPS_HTTP_EXCHANGE";Refuse(categorized.ToJsonString(),125);
            categorized["Phase"]="HTTPS_TLS_HANDSHAKE";categorized["Errors"]![0]!["Code"]=0;Refuse(categorized.ToJsonString(),125);
        }
        var startupCode=Result("HTTPS_SOCKET_CREATE",125,error:new SocketException(10107));
        Accept(startupCode,125);
        Check(JsonNode.Parse(startupCode)!["Errors"]![0]!["Kind"]!.GetValue<string>()=="SOCKET"); // Code alone is not startup evidence.
        // Real pinned-runtime metadata, no invocation or Winsock startup. The
        // exception and the actual Winsock implementation live in different DLLs.
        var winsock=typeof(Socket).Assembly.GetType("Interop+Winsock",true)!;
        var runtimeMethods=winsock.GetMethods(BindingFlags.NonPublic|BindingFlags.Public|BindingFlags.Static);
        Check(typeof(SocketException).Assembly!=winsock.Assembly);
        Check(Call("SocketStartupFrame",runtimeMethods.Single(m=>m.Name=="EnsureInitialized")) is true);
        Check(Call("SocketStartupFrame",runtimeMethods.Single(m=>m.Name.StartsWith("<EnsureInitialized>g__Initialize|",StringComparison.Ordinal))) is true);
        Check(Call("SocketStartupFrame",typeof(SocketException).GetConstructors().First()) is false);
        Check(Call("SocketStartupFrame",new object?[]{null}) is false);
        var startupFrame=JsonNode.Parse(startupCode)!;startupFrame["Errors"]![0]!["Kind"]="SOCKET_STARTUP";
        Accept(startupFrame.ToJsonString(),125);
        startupFrame["Errors"]![0]!["Kind"]="SOCKET_STARTUP_PRIVATE_PATH";Refuse(startupFrame.ToJsonString(),125);
        startupFrame=JsonNode.Parse(startupCode)!;startupFrame["Phase"]="HTTPS_SOCKET_CREATE_PRIVATE_PATH";Refuse(startupFrame.ToJsonString(),125);
        var nativeFailureType=library.GetType("ProtectionLifecycle.SessionProxy+FixedSocketCreationException",true)!;
        Exception Captured(int status)=>(Exception)Activator.CreateInstance(nativeFailureType,BindingFlags.Instance|BindingFlags.NonPublic,null,new object[]{10022,status},null)!;
        foreach(var status in new[]{0,unchecked((int)0xc000000d),unchecked((int)0xc0000022)})
        {
            var captured=Result("HTTPS_SOCKET_CREATE",125,error:new HttpRequestException("private-fixture",Captured(status)));
            Accept(captured,125);var pair=JsonNode.Parse(captured)!;
            Check(pair["Errors"]!.AsArray().Count==3 && pair["Errors"]![1]!["Kind"]!.GetValue<string>()=="SOCKET_CREATE" &&
                pair["Errors"]![1]!["Code"]!.GetValue<int>()==10022 && pair["Errors"]![2]!["Kind"]!.GetValue<string>()=="SOCKET_NT_CONTEXT" &&
                pair["Errors"]![2]!["Code"]!.GetValue<int>()==status && !captured.Contains("private-fixture",StringComparison.Ordinal));
            pair["Phase"]="HTTPS_CONNECT";Refuse(pair.ToJsonString(),125);
            pair=JsonNode.Parse(captured)!;pair["Errors"]!.AsArray().RemoveAt(2);Refuse(pair.ToJsonString(),125);
            pair=JsonNode.Parse(captured)!;pair["Errors"]!.AsArray().RemoveAt(1);Refuse(pair.ToJsonString(),125);
            pair=JsonNode.Parse(captured)!;pair["Errors"]![1]!["Code"]=0;Refuse(pair.ToJsonString(),125);
        }
        var deepCaptured=Result("HTTPS_SOCKET_CREATE",125,error:new HttpRequestException("private-fixture",
            new InvalidOperationException("private-fixture",new InvalidOperationException("private-fixture",Captured(0)))));
        Accept(deepCaptured,125);Check(JsonNode.Parse(deepCaptured)!["Errors"]![3]!["Kind"]!.GetValue<string>()=="SOCKET");
        var registry=Result("HTTPS_SETTINGS",125,error:new TypeInitializationException("Microsoft.Win32.Registry",new System.Security.SecurityException("private-fixture")));
        Accept(registry,125);Check(JsonNode.Parse(registry)!["Errors"]![0]!["Kind"]!.GetValue<string>()=="REGISTRY_INITIALIZATION" && !registry.Contains("Microsoft.Win32",StringComparison.Ordinal));
        var unknown=Result("HTTPS_SETTINGS",125,error:new TypeInitializationException("private-type-token",new System.Security.SecurityException("private-fixture")));
        Check(!unknown.Contains("private-type-token",StringComparison.Ordinal) && JsonNode.Parse(unknown)!["Errors"]![0]!["Kind"]!.GetValue<string>()=="INITIALIZATION");
        var namedSecurity=Result("HTTPS_TLS_POLICY",125,error:new System.Security.SecurityException("System.TimeZoneInfo Internal.Win32.RegistryKey PRIVATE_PATH"));
        Accept(namedSecurity,125);
        Check(JsonNode.Parse(namedSecurity)!["Errors"]![0]!["Kind"]!.GetValue<string>()=="SECURITY" &&
            !namedSecurity.Contains("PRIVATE_PATH",StringComparison.Ordinal));
        foreach(var kind in new[]{"TIMEZONE_REGISTRY","REGISTRY_ACCESS","TZ_CATALOG_SEARCH","TZ_CATALOG_ENUMERATION",
            "TZ_DEFINITION","TZ_DYNAMIC_RULES","TZ_ENUMERATED_DEFINITION","TZ_UTC_DEFINITION"})
        {
            var categorized=JsonNode.Parse(namedSecurity)!;categorized["Errors"]![0]!["Kind"]=kind;
            Accept(categorized.ToJsonString(),125);
            categorized["Errors"]![0]!["Kind"]=kind+"_PRIVATE_PATH";Refuse(categorized.ToJsonString(),125);
        }
        var proxy=library.GetType("ProtectionLifecycle.SessionProxy",true)!;
        object? ProxyCall(string method,params object?[] values)
        {
            try{return proxy.GetMethod(method,BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,values);}
            catch(TargetInvocationException ex)when(ex.InnerException is not null){ExceptionDispatchInfo.Capture(ex.InnerException).Throw();throw;}
        }
        var secret=new string('B',64);var header=(byte[])ProxyCall("FixedClientConnectHeader",id,secret)!;var headerText=Encoding.ASCII.GetString(header);
        Check(headerText=="CONNECT www.microsoft.com:443 HTTP/1.1\r\nHost: www.microsoft.com:443\r\nProxy-Authorization: Basic "+Convert.ToBase64String(Encoding.ASCII.GetBytes(id+":"+secret))+"\r\n\r\n");
        foreach(var pair in new[]{("bad",secret),(id,"bad"),(id,"B\r\nInjected: x"),(new string('a',33),secret)})
        {var refused=false;try{ProxyCall("FixedClientConnectHeader",pair.Item1,pair.Item2);}catch(InvalidDataException){refused=true;}Check(refused);}
        ProxyCall("RequireFixedClientConnectReply","HTTP/1.1 200 Connection Established\r\n\r\n");Check(true);
        foreach(var reply in new[]{"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n","HTTP/1.1 2000 Connection Established\r\n\r\n","HTTP/1.0 200 Connection Established\r\n\r\n","HTTP/1.1 200 Connection Established\r\nExtra: data\r\n\r\n"})
        {var refused=false;try{ProxyCall("RequireFixedClientConnectReply",reply);}catch(InvalidDataException){refused=true;}Check(refused);}
        var tunnel=library.GetType("ProtectionLifecycle.UpstreamTunnelAttempt",true)!;
        var parseStatus=tunnel.GetMethod("ParseConnectStatus",BindingFlags.NonPublic|BindingFlags.Static)!;
        foreach(var (reply,expected) in new (string,int?)[]{
            ("HTTP/1.1 200 Connection Established\r\n\r\n",200),("HTTP/1.0 200\r\n\r\n",200),
            ("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",407),("HTTP/1.1 502 refusal\r\n\r\n",502),
            ("HTTP/1.1 2000 Connection Established\r\n\r\n",null),("HTTP/1.1 20A\r\n\r\n",null),
            ("HTTP/2 200\r\n\r\n",null),("HTTP/1.1  200\r\n\r\n",null),("HTTP/1.1 200",null)})
            Check((int?)parseStatus.Invoke(null,[reply])==expected);
        const BindingFlags tunnelInstance=BindingFlags.Instance|BindingFlags.NonPublic|BindingFlags.Public;
        var attempt=Activator.CreateInstance(tunnel,tunnelInstance,null,[60,3,System.Diagnostics.Stopwatch.GetTimestamp()],null)!;
        var step=tunnel.GetProperty("Step",tunnelInstance)!;
        var capture=tunnel.GetMethod("Capture",tunnelInstance)!;
        var recordStatus=tunnel.GetMethod("RecordStatus",tunnelInstance)!;
        JsonElement Snapshot()=>JsonSerializer.SerializeToElement(capture.Invoke(attempt,null));
        var initial=Snapshot();
        Check(initial.GetProperty("Step").GetString()=="AdmissionBeforeTunnel" && initial.GetProperty("ConnectStatus").ValueKind==JsonValueKind.Null);
        step.SetValue(attempt,Enum.Parse(step.PropertyType,"FreshnessAfterReply"));
        recordStatus.Invoke(attempt,[200]);
        var refusedAfterReply=Snapshot();
        Check(refusedAfterReply.GetProperty("Step").GetString()=="FreshnessAfterReply" &&
            refusedAfterReply.GetProperty("ConnectStatus").GetInt32()==200 && !refusedAfterReply.GetProperty("TunnelReady").GetBoolean());
        step.SetValue(attempt,Enum.Parse(step.PropertyType,"TunnelReady"));
        var ready=Snapshot();
        Check(ready.GetProperty("TunnelReady").GetBoolean() && ready.GetProperty("MinimumTtlSeconds").GetInt32()==60 &&
            ready.GetProperty("ResponseAgeSeconds").GetInt32()==3 && ready.GetProperty("ElapsedMs").GetInt64()>=0 &&
            ready.EnumerateObject().Count()==6);
        var culture=System.Globalization.CultureInfo.CurrentCulture;var ui=System.Globalization.CultureInfo.CurrentUICulture;
        var defaultCulture=System.Globalization.CultureInfo.DefaultThreadCurrentCulture;var defaultUi=System.Globalization.CultureInfo.DefaultThreadCurrentUICulture;
        try
        {
            library.GetType("ProtectionLifecycle.AtomicChild",true)!.GetMethod("ConfigureFixedChildCulture",BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,null);
            Check(System.Globalization.CultureInfo.CurrentCulture.Name=="" && System.Globalization.CultureInfo.CurrentUICulture.Name=="" && System.Globalization.CultureInfo.DefaultThreadCurrentCulture?.Name=="" && System.Globalization.CultureInfo.DefaultThreadCurrentUICulture?.Name=="");
            var tls=(System.Net.Security.SslClientAuthenticationOptions)ProxyCall("OfflineTls")!;
            Check(tls.CertificateRevocationCheckMode==System.Security.Cryptography.X509Certificates.X509RevocationMode.Offline && tls.CertificateChainPolicy is {DisableCertificateDownloads:true,RevocationMode:System.Security.Cryptography.X509Certificates.X509RevocationMode.Offline,VerificationFlags:System.Security.Cryptography.X509Certificates.X509VerificationFlags.NoFlag});
        }
        finally{System.Globalization.CultureInfo.DefaultThreadCurrentCulture=defaultCulture;System.Globalization.CultureInfo.DefaultThreadCurrentUICulture=defaultUi;System.Globalization.CultureInfo.CurrentCulture=culture;System.Globalization.CultureInfo.CurrentUICulture=ui;}
        var initialized=winsock.GetField("s_initialized",BindingFlags.NonPublic|BindingFlags.Static)!;
        ProxyCall("InitializeFixedClientSockets");Check(initialized.GetValue(null) is 1);
        ProxyCall("InitializeFixedClientSockets");Check(initialized.GetValue(null) is 1);
        var resolver=library.GetType("ProtectionLifecycle.ResolverTlsEvidence",true)!;
        var observe=resolver.GetMethod("Observe",BindingFlags.NonPublic|BindingFlags.Static)!;
        using(var key=RSA.Create(2048))
        {
            var request=new CertificateRequest("CN=Ordinary resolver policy fixture",key,
                HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));
            using var root=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1),DateTimeOffset.UtcNow.AddHours(1));
            using var chain=new X509Chain();
            chain.ChainPolicy.TrustMode=X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(root);
            chain.ChainPolicy.DisableCertificateDownloads=true;
            chain.ChainPolicy.RevocationMode=X509RevocationMode.NoCheck; // fixture only
            Check(chain.Build(root));
            object Observe(string host,X509Certificate2? cert,
                X509Chain? actualChain,SslPolicyErrors errors)
                =>observe.Invoke(null,[host,cert,actualChain,errors])!;
            bool Accepted(object value)=>(bool)resolver.GetProperty("Accepted")!.GetValue(value)!;
            var none=SslPolicyErrors.None;
            var clean=Observe("cloudflare-dns.com",root,chain,none);
            Check(Accepted(clean) && ((string[])resolver.GetProperty("ChainCertificateSHA256")!.GetValue(clean)!).Single()==
                Convert.ToHexString(SHA256.HashData(root.RawData)));
            Check(!Accepted(Observe("www.microsoft.com",root,chain,none)));
            Check(!Accepted(Observe("cloudflare-dns.com",root,chain,SslPolicyErrors.RemoteCertificateChainErrors)));
            Check(!Accepted(Observe("cloudflare-dns.com",root,chain,SslPolicyErrors.RemoteCertificateNameMismatch)));
            Check(!Accepted(Observe("cloudflare-dns.com",null,chain,none)));
            Check(!Accepted(Observe("cloudflare-dns.com",root,null,none)));
        }
        Console.WriteLine($"PASS {count} fixed gateway feedback checks and actual pinned-runtime process-local Winsock initialization/reuse; no exception messages, paths, tokens or raw output; diagnostic only. No socket creation/connections, UAC, child process, protected state, Job or WFP operation.");
    }

    // Real Schannel client initialization with an in-memory transport that
    // returns EOF. The ordinary comparison can reach ClientHello without
    // making a connection or requiring any server certificate.
    internal static void VerifyOrdinaryClientHello(Assembly library)
    {
        var proxy=library.GetType("ProtectionLifecycle.SessionProxy",true)!;
        var tls=(System.Net.Security.SslClientAuthenticationOptions)proxy
            .GetMethod("OfflineTls",BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,null)!;
        tls.TargetHost="www.microsoft.com";
        tls.ApplicationProtocols=[System.Net.Security.SslApplicationProtocol.Http11];
        using var wire=new ClientHelloCapture();
        using var ssl=new System.Net.Security.SslStream(wire,leaveInnerStreamOpen:true);
        try
        {
            ssl.AuthenticateAsClient(tls);
            throw new InvalidOperationException("TLS authenticated without a server");
        }
        catch(IOException) when(wire.CapturedBytes>0) { }

        var original=wire.ToArray();
        using var input=new MemoryStream(original,writable:false);
        var parse=library.GetType("ClaudeCodeProtection.Security.SessionTunnel",true)!
            .GetMethod("RequireTlsClientHelloAsync",BindingFlags.Static|BindingFlags.NonPublic)!;
        var task=(Task<Stream>)parse.Invoke(null,[input,tls.TargetHost,(Action)(()=>{}),CancellationToken.None])!;
        using var replay=task.GetAwaiter().GetResult();
        var received=new byte[wire.CapturedBytes];
        replay.ReadExactly(received);
        if(!received.AsSpan().SequenceEqual(original) || input.Position!=input.Length || replay.ReadByte()!=-1)
            throw new InvalidOperationException("Ordinary ClientHello replay differs");
        Console.WriteLine("PASS ordinary Schannel emitted ClientHello accepted by the production gateway parser over memory; deliberate EOF, no socket or server handshake.");
    }

    private sealed class ClientHelloCapture : Stream
    {
        private readonly MemoryStream captured=new();
        internal int CapturedBytes=>checked((int)captured.Length);
        internal byte[] ToArray()=>captured.ToArray();
        public override bool CanRead=>true;
        public override bool CanWrite=>true;
        public override bool CanSeek=>false;
        public override long Length=>throw new NotSupportedException();
        public override long Position { get=>throw new NotSupportedException();set=>throw new NotSupportedException(); }
        public override int Read(byte[] buffer,int offset,int count)=>0;
        public override void Write(byte[] buffer,int offset,int count)
        {
            if(count>32768-captured.Length)throw new InvalidDataException("Ordinary ClientHello exceeds gateway bound");
            captured.Write(buffer,offset,count);
        }
        public override void Flush() { }
        public override long Seek(long offset,SeekOrigin origin)=>throw new NotSupportedException();
        public override void SetLength(long value)=>throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if(disposing)captured.Dispose();
            base.Dispose(disposing);
        }
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll",SetLastError=true,ExactSpelling=true)]
    [System.Runtime.InteropServices.DefaultDllImportSearchPaths(System.Runtime.InteropServices.DllImportSearchPath.System32)]
    [return:System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool GetHandleInformation(SafeSocketHandle handle,out uint flags);
    internal static void RunSocketCreate(Assembly library)
    {
        var proxy=library.GetType("ProtectionLifecycle.SessionProxy",true)!;
        proxy.GetMethod("InitializeFixedClientSockets",BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,null);
        var socket=(Socket)proxy.GetMethod("CreateFixedClientSocket",BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,null)!;
        var handle=socket.SafeHandle;
        try
        {
            if(socket.AddressFamily!=AddressFamily.InterNetwork || socket.SocketType!=SocketType.Stream || socket.ProtocolType!=ProtocolType.Tcp ||
                socket.IsBound || socket.Connected || !socket.Blocking || handle.IsInvalid || handle.IsClosed ||
                !GetHandleInformation(handle,out var flags) || (flags&1)!=0)throw new InvalidOperationException("Fixed socket native adoption differs");
        }
        finally{socket.Dispose();}
        if(!handle.IsClosed)throw new InvalidOperationException("Fixed socket ownership did not close");
        Console.WriteLine("PASS ordinary fixed IPv4/TCP WSASocketW(2,1,6,NULL,0,0x81), public Socket adoption, noninheritance, unbound/disconnected state and owned handle closure. One socket, no bind/connect/listen/send, no LPAC/WFP/system permission changes; not protected-network qualification.");
    }
}
