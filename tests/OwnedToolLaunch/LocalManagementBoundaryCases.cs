using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using System.Text.Json.Nodes;

internal static class LocalManagementBoundaryCases
{
    private delegate bool TrustedResponse(ReadOnlySpan<byte> bytes);
    private const BindingFlags Static=BindingFlags.Static|BindingFlags.NonPublic;
    private const BindingFlags Instance=BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic;
    internal static void Run(Assembly library)
    {
        var report=library.GetType("ProtectionLifecycle.LocalManagementBoundaryReport",true)!;
        var attempt=library.GetType("ProtectionLifecycle.LocalManagementAttempt",true)!;
        var boundary=library.GetType("ProtectionLifecycle.LocalManagementBoundary",true)!;
        var parse=report.GetMethod("Parse",Static)!;
        var session=new string('a',32);
        const uint pid=1234;
        var checks=0;
        void Check(bool condition){if(!condition)throw new InvalidDataException("Local management boundary fixture refused");checks++;}
        object Attempt(string role,string phase,int? code=null,byte[]? bytes=null)
            =>Activator.CreateInstance(attempt,Instance,null,[role,phase,code,bytes??[]],null)!;
        string Body(uint exit,params object[] attempts)
        {
            var typed=Array.CreateInstance(attempt,attempts.Length);
            for(int i=0;i<attempts.Length;i++)typed.SetValue(attempts[i],i);
            var value=Activator.CreateInstance(report,Instance,null,[1,session,(int)pid,"LOCAL_BOUNDARY",(int)exit,null,typed],null)!;
            return JsonSerializer.Serialize(value,report);
        }
        object Parse(string body,uint exit)
        {
            try{return parse.Invoke(null,[body,session,pid,exit])!;}
            catch(TargetInvocationException error)when(error.InnerException is not null)
            {ExceptionDispatchInfo.Capture(error.InnerException).Throw();throw;}
        }
        void Reject(string raw,uint exit)
        {
            try{_=Parse(raw,exit);}
            catch(InvalidDataException){checks++;return;}
            throw new InvalidDataException("Unsafe management observation accepted");
        }
        var ack=Attempt("OWNED_GATEWAY","ACKNOWLEDGED");
        var rawDenied=Attempt("RAW_PROXY","CONNECT",10013);
        var controllerDenied=Attempt("CONTROLLER","CONNECT",10013);
        var good=Body(42,ack,rawDenied,controllerDenied);
        var observed=report.GetProperty("BoundaryObserved",Instance)!;
        Check((bool)observed.GetValue(Parse(good,42))!);
        Reject(good,125);
        Reject(good.Replace(session,new string('b',32),StringComparison.Ordinal),42);
        Reject(good.Replace("\"Pid\":1234","\"Pid\":1235",StringComparison.Ordinal),42);
        Reject(good.Replace("\"Attempts\":","\"BoundaryObserved\":true,\"Attempts\":",StringComparison.Ordinal),42);
        Reject(Body(42,ack,controllerDenied,rawDenied),42);
        foreach(var notDenial in new[]{Attempt("CONTROLLER","CONNECT",10061),Attempt("CONTROLLER","CONNECT",10060),
            Attempt("CONTROLLER","SOCKET",10013),Attempt("CONTROLLER","READ_FAILURE",10013),
            Attempt("CONTROLLER","READ_COMPLETE",bytes:"HTTP/1.1 200 OK\r\n\r\n{}"u8.ToArray())})
        {
            Reject(Body(42,ack,rawDenied,notDenial),42);
            Check(!(bool)observed.GetValue(Parse(Body(125,ack,rawDenied,notDenial),125))!);
        }
        Reject(Body(125,ack,Attempt("RAW_PROXY","CONNECTED",bytes:[1]),controllerDenied),125);
        Reject(Body(125,ack,rawDenied,Attempt("CONTROLLER","READ_COMPLETE",bytes:new byte[8192])),125);
        Reject(Body(125,ack,rawDenied,Attempt("CONTROLLER","READ_LIMIT",bytes:new byte[8191])),125);
        Check(!(bool)observed.GetValue(Parse(Body(125,ack,rawDenied,Attempt("CONTROLLER","READ_LIMIT",bytes:new byte[8192])),125))!);
        Reject(good.Replace("\"Code\":10013","\"Code\":null",StringComparison.Ordinal),42);

        var summary=attempt.GetMethod("Summary",Instance)!;
        var captured=Attempt("CONTROLLER","READ_COMPLETE",bytes:"sensitive fixture"u8.ToArray());
        var safe=JsonSerializer.SerializeToElement(summary.Invoke(captured,null));
        Check(safe.GetProperty("ReceivedBytes").GetInt32()==17 && safe.GetProperty("SHA256").GetString()!.Length==64 &&
            safe.EnumerateObject().Count()==5 && !safe.GetRawText().Contains("sensitive fixture",StringComparison.Ordinal));
        var trusted=boundary.GetMethod("TrustedResponseObserved",Static)!.CreateDelegate<TrustedResponse>();
        Check(trusted("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"u8));
        Check(!trusted("HTTP/1.1 401 Unauthorized\r\n\r\n{}"u8));
        Check(!trusted("HTTP/1.1 200 OK\r\n\r\n"u8));
        Console.WriteLine($"PASS {checks} fixed local management feedback and trusted reference checks. Fixture only, no connections, installed state, or WFP operation.");
    }
}
