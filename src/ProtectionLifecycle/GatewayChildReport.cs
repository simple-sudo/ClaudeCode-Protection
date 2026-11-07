using System.ComponentModel;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text.Json;

namespace ProtectionLifecycle;

// Diagnostic data from the single inherited write handle. Never an admission,
// environment PASS, authority to retry, or input to a privileged path operation.
internal sealed record GatewayChildError(string Kind,int Code);
internal sealed record GatewayFailureFeedback(string Phase,GatewayChildError[] Errors);
internal sealed record GatewayChildReport(int SchemaVersion,string SessionId,int Pid,string Phase,int ExitCode,int? HttpStatus,GatewayChildError[] Errors)
{
    internal const int MaxCharacters=4096;
    internal static GatewayChildReport Result(string sessionId,string phase,int exitCode,int? status=null,Exception? failure=null)
    {
        var errors=DescribeCore(failure,phase=="HTTPS_TLS_HANDSHAKE").ToList();
        if(exitCode==125 && errors.Count==0)errors.Add(new("REFUSED",125));
        // Invalid environment text is never echoed, including on input refusal.
        var id=sessionId.Length==32 && sessionId.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f')?sessionId:"";
        return new(1,id,Environment.ProcessId,phase,exitCode,status,errors.ToArray());
    }
    internal static GatewayChildError[] Describe(Exception? failure)=>DescribeCore(failure,false);
    private static GatewayChildError[] DescribeCore(Exception? failure,bool classifySchannel)
    {
        var errors=new List<GatewayChildError>();
        for(var ex=failure;ex is not null && errors.Count<4;ex=ex.InnerException)
        {
            var captured=ex as SessionProxy.FixedSocketCreationException;
            var includeContext=captured is not null && errors.Count<3;
            var code=ex is Win32Exception native?native.NativeErrorCode:ex.HResult;
            var schannel=classifySchannel && code<0?SchannelFailureKind(ex):null;
            errors.Add(new(includeContext?"SOCKET_CREATE":schannel??Kind(ex),code));
            if(includeContext)errors.Add(new("SOCKET_NT_CONTEXT",captured!.LastNtStatus));
        }
        return errors.ToArray();
    }
    private static string Kind(Exception ex)=>ex switch {
        TypeInitializationException init when init.TypeName is "Microsoft.Win32.Registry" or "Internal.Win32.Registry"=>"REGISTRY_INITIALIZATION",
        TypeInitializationException=>"INITIALIZATION",System.Security.SecurityException security=>SecurityKind(security),
        SocketException socket=>SocketKind(socket),Win32Exception=>"NATIVE",AuthenticationException=>"TLS",
        HttpRequestException=>"HTTP",OperationCanceledException=>"TIMEOUT",UnauthorizedAccessException=>"ACCESS",
        InvalidDataException=>"CONTRACT",_=>"OTHER"};
    private static string SocketKind(SocketException error)
    {
        // A fixed runtime startup frame can identify a failed WSAStartup path.
        // The numeric code and message alone cannot. Never export raw frames.
        try
        {
            var trace=new System.Diagnostics.StackTrace(error,false);
            if(trace.FrameCount is <1 or >64)return "SOCKET";
            for(var i=0;i<trace.FrameCount;i++)
            {
                if(SocketStartupFrame(trace.GetFrame(i)?.GetMethod()))return "SOCKET_STARTUP";
            }
        }
        catch{ /* A restricted stack inspection must not hide the failure. */ }
        return "SOCKET";
    }
    private static bool SocketStartupFrame(System.Reflection.MethodBase? method)=>
        method?.DeclaringType is Type type && type.Assembly==typeof(Socket).Assembly && type.FullName=="Interop+Winsock" &&
        (method.Name=="EnsureInitialized" || method.Name.StartsWith("<EnsureInitialized>g__Initialize|",StringComparison.Ordinal));
    private static string? SchannelFailureKind(Exception error)
    {
        if(error is not (Win32Exception or NotSupportedException))return null;
        try
        {
            var trace=new System.Diagnostics.StackTrace(error,false);
            if(trace.FrameCount is <1 or >64)return null;
            for(var i=0;i<trace.FrameCount;i++)
            {
                var kind=SchannelFrame(trace.GetFrame(i)?.GetMethod(),error is Win32Exception);
                if(kind is not null)return kind;
            }
        }
        catch{ /* Retain the original failure when the stack is unavailable. */ }
        return null;
    }
    private static string? SchannelFrame(System.Reflection.MethodBase? method,bool native)
    {
        // Exact .NET Windows runtime call sites. Codes and messages alone
        // cannot identify the failing step.
        if(method?.DeclaringType is not Type type || type.Assembly!=typeof(System.Net.Security.SslStream).Assembly)return null;
        return (type.FullName,method.Name,native) switch {
            ("System.Net.SSPIWrapper","EnumerateSecurityPackages",true)=>"TLS_SCHANNEL_ENUMERATE",
            ("System.Net.SSPIWrapper","GetVerifyPackageInfo",false)=>"TLS_SCHANNEL_PACKAGE_MISSING",
            ("System.Net.Security.SslStreamPal","VerifyPackageInfo",false)=>"TLS_SCHANNEL_PACKAGE_MISSING",
            ("System.Net.SSPIWrapper","AcquireCredentialsHandle",true)=>"TLS_SCHANNEL_ACQUIRE",
            ("System.Net.Security.SslStreamPal","AcquireCredentialsHandleSchCredentials",true)=>"TLS_SCHANNEL_ACQUIRE",
            ("System.Net.Security.SslStreamPal","AcquireCredentialsHandleSchannelCred",true)=>"TLS_SCHANNEL_ACQUIRE",
            _=>null
        };
    }
    private static bool SchannelKind(string? kind)=>kind is "TLS_SCHANNEL_ENUMERATE" or "TLS_SCHANNEL_PACKAGE_MISSING" or "TLS_SCHANNEL_ACQUIRE";
    private static string SecurityKind(System.Security.SecurityException error)
    {
        // Only report fixed runtime call-site categories. Never export frame
        // names, file names, exception messages, registry paths or raw stacks.
        // Failure to inspect a restricted runtime must not replace the original
        // failure or prevent its bounded report from reaching the original owner.
        try
        {
            var trace=new System.Diagnostics.StackTrace(error,false);
            if(trace.FrameCount is <1 or >64)return "SECURITY";
            var localTime=false;var registry=false;string? operation=null;
            for(var i=0;i<trace.FrameCount;i++)
            {
                var method=trace.GetFrame(i)?.GetMethod();var type=method?.DeclaringType;
                if(type is null || type.Assembly!=typeof(DateTime).Assembly)continue;
                if(type.FullName=="System.TimeZoneInfo" || type.DeclaringType?.FullName=="System.TimeZoneInfo")localTime=true;
                if(type.FullName is "Internal.Win32.RegistryKey" or "Microsoft.Win32.RegistryKey")registry=true;
                // The nearest known runtime operation wins, so a dynamic-rule
                // failure is not mislabeled by its outer definition lookup.
                if(operation is null && type.FullName=="System.TimeZoneInfo")operation=method!.Name switch {
                    "FindIdFromTimeZoneInformation"=>"TZ_CATALOG_SEARCH",
                    "PopulateAllSystemTimeZones"=>"TZ_CATALOG_ENUMERATION",
                    "TryGetTimeZoneFromLocalMachine"=>"TZ_DEFINITION",
                    "TryCreateAdjustmentRules"=>"TZ_DYNAMIC_RULES",
                    "TryCompareTimeZoneInformationToRegistry"=>"TZ_ENUMERATED_DEFINITION",
                    "GetUtcStandardDisplayName"=>"TZ_UTC_DEFINITION",_=>null};
            }
            return localTime && registry?operation??"TIMEZONE_REGISTRY":registry?"REGISTRY_ACCESS":"SECURITY";
        }
        catch{return "SECURITY";}
    }
    internal static bool KnownErrorKind(string? kind)=>kind is "REFUSED" or "SOCKET" or "SOCKET_STARTUP" or "SOCKET_CREATE" or "SOCKET_NT_CONTEXT" or "NATIVE" or "TLS" or "HTTP" or "TIMEOUT" or "ACCESS" or "CONTRACT" or "OTHER" or "INITIALIZATION" or "REGISTRY_INITIALIZATION" or "SECURITY" or "TIMEZONE_REGISTRY" or "REGISTRY_ACCESS" or "TZ_CATALOG_SEARCH" or "TZ_CATALOG_ENUMERATION" or "TZ_DEFINITION" or "TZ_DYNAMIC_RULES" or "TZ_ENUMERATED_DEFINITION" or "TZ_UTC_DEFINITION";
    internal static GatewayChildReport Parse(string raw,string expectedSessionId,uint expectedPid,uint actualExitCode)
    {
        if(raw.Length is <2 or >MaxCharacters)throw new InvalidDataException("GatewayFeedbackBounds");
        using var doc=JsonDocument.Parse(raw,new JsonDocumentOptions{MaxDepth=5});
        StrictJson.Fields(doc.RootElement,"SchemaVersion","SessionId","Pid","Phase","ExitCode","HttpStatus","Errors");
        var errors=doc.RootElement.GetProperty("Errors");
        if(errors.ValueKind!=JsonValueKind.Array || errors.GetArrayLength()>4)throw new InvalidDataException("GatewayFeedbackErrorsShape");
        foreach(var e in errors.EnumerateArray())StrictJson.Fields(e,"Kind","Code");
        var r=JsonSerializer.Deserialize<GatewayChildReport>(raw)??throw new InvalidDataException("GatewayFeedbackMissing");
        if(r.SchemaVersion!=1 || r.SessionId!=Identifiers.Hex32(expectedSessionId) || expectedPid==0 || r.Pid<=0 || (uint)r.Pid!=expectedPid ||
            (uint)r.ExitCode!=actualExitCode || r.Errors is null || r.Errors.Any(e=>e is null || !(KnownErrorKind(e.Kind) || SchannelKind(e.Kind))))
            throw new InvalidDataException("GatewayFeedbackOwnerOrErrorBinding");
        for(var i=0;i<r.Errors.Length;i++)
        {
            var kind=r.Errors[i].Kind;
            if(SchannelKind(kind) && (r.Phase!="HTTPS_TLS_HANDSHAKE" || r.ExitCode!=125 || r.Errors[i].Code>=0))
                throw new InvalidDataException("GatewayFeedbackSchannelPhaseBinding");
            if(kind is not ("SOCKET_CREATE" or "SOCKET_NT_CONTEXT"))continue;
            if(r.ExitCode!=125 || r.Phase!="HTTPS_SOCKET_CREATE" ||
                (kind=="SOCKET_CREATE" && (r.Errors[i].Code<=0 || i+1>=r.Errors.Length || r.Errors[i+1].Kind!="SOCKET_NT_CONTEXT")) ||
                (kind=="SOCKET_NT_CONTEXT" && (i==0 || r.Errors[i-1].Kind!="SOCKET_CREATE")))
                throw new InvalidDataException("GatewayFeedbackSocketContextBinding");
        }
        var success=r.ExitCode==42 && r.Phase=="COMPLETE" && r.HttpStatus is >=200 and <400 && r.Errors.Length==0;
        var rejectedStatus=r.ExitCode==126 && r.Phase=="HTTPS" && r.HttpStatus is >=100 and <=599 && !(r.HttpStatus is >=200 and <400) && r.Errors.Length==0;
        var failed=r.ExitCode==125 && (r.Phase is "ENVIRONMENT" or "IDENTITY" or "NETWORK_CONTENT_READS" or "NETWORK_CONTENT_REQUIRES_ANALYSIS" or
            "TIMEZONE_DEFINITION" or "TIMEZONE_PUBLIC_CACHE" or "TIMEZONE_LOCAL_BINDING" or "HTTPS" or "HTTPS_SETTINGS" or
            "HTTPS_TLS_POLICY" or "HTTPS_CLIENT" or "HTTPS_SEND" or "HTTPS_SOCKET_INITIALIZATION" or "HTTPS_SOCKET_CREATE" or
            "HTTPS_CONNECT" or "HTTPS_CONNECT_WRITE" or "HTTPS_CONNECT_REPLY" or "HTTPS_TLS_HANDSHAKE" or "HTTPS_HTTP_EXCHANGE") &&
            r.HttpStatus is null && r.Errors.Length is >0 and <=4;
        if(!success && !rejectedStatus && !failed)throw new InvalidDataException("GatewayFeedbackOutcomeShape");
        return r;
    }
    internal static async Task<string> ReadBounded(StreamReader reader)
    {
        // Drain concurrently with the fixed child. A second JSON record, raw
        // console error or invalid UTF-8 is rejected instead of being exported.
        var buffer=new char[MaxCharacters+1];var used=0;
        while(used<buffer.Length)
        {
            var count=await reader.ReadAsync(buffer.AsMemory(used,buffer.Length-used));
            if(count==0)return new string(buffer,0,used);used+=count;
        }
        throw new InvalidDataException("GatewayFeedbackBounds");
    }
}
