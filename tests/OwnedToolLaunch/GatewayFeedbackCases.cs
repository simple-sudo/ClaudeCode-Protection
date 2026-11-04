using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Net.Sockets;

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
        Console.WriteLine($"PASS {count} fixed gateway feedback checks and actual pinned-runtime process-local Winsock initialization/reuse; no exception messages, paths, tokens or raw output; diagnostic only. No socket creation/connections, UAC, child process, protected state, Job or WFP operation.");
    }
}
