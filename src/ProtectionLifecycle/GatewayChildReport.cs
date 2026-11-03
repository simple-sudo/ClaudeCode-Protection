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
        var errors=Describe(failure).ToList();
        if(exitCode==125 && errors.Count==0)errors.Add(new("REFUSED",125));
        // Invalid environment text is never echoed, including on input refusal.
        var id=sessionId.Length==32 && sessionId.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f')?sessionId:"";
        return new(1,id,Environment.ProcessId,phase,exitCode,status,errors.ToArray());
    }
    internal static GatewayChildError[] Describe(Exception? failure)
    {
        var errors=new List<GatewayChildError>();
        for(var ex=failure;ex is not null && errors.Count<4;ex=ex.InnerException)
            errors.Add(new(Kind(ex),ex is Win32Exception native?native.NativeErrorCode:ex.HResult));
        return errors.ToArray();
    }
    private static string Kind(Exception ex)=>ex switch {
        TypeInitializationException init when init.TypeName is "Microsoft.Win32.Registry" or "Internal.Win32.Registry"=>"REGISTRY_INITIALIZATION",
        TypeInitializationException=>"INITIALIZATION",System.Security.SecurityException=>"SECURITY",
        SocketException=>"SOCKET",Win32Exception=>"NATIVE",AuthenticationException=>"TLS",
        HttpRequestException=>"HTTP",OperationCanceledException=>"TIMEOUT",UnauthorizedAccessException=>"ACCESS",
        InvalidDataException=>"CONTRACT",_=>"OTHER"};
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
            (uint)r.ExitCode!=actualExitCode || r.Errors is null || r.Errors.Any(e=>e is null || e.Kind is not ("REFUSED" or "SOCKET" or "NATIVE" or "TLS" or "HTTP" or "TIMEOUT" or "ACCESS" or "CONTRACT" or "OTHER" or "INITIALIZATION" or "REGISTRY_INITIALIZATION" or "SECURITY")))
            throw new InvalidDataException("GatewayFeedbackOwnerOrErrorBinding");
        var success=r.ExitCode==42 && r.Phase=="COMPLETE" && r.HttpStatus is >=200 and <400 && r.Errors.Length==0;
        var rejectedStatus=r.ExitCode==126 && r.Phase=="HTTPS" && r.HttpStatus is >=100 and <=599 && !(r.HttpStatus is >=200 and <400) && r.Errors.Length==0;
        var failed=r.ExitCode==125 && (r.Phase is "ENVIRONMENT" or "IDENTITY" or "HTTPS" or "HTTPS_SETTINGS" or "HTTPS_TLS_POLICY" or "HTTPS_CLIENT" or "HTTPS_SEND" or "HTTPS_CONNECT" or "HTTPS_CONNECT_REPLY") && r.HttpStatus is null && r.Errors.Length is >0 and <=4;
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
