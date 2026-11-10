using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
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
        CheckRoutes(library,Check);
        Console.WriteLine($"PASS {checks} fixed local management feedback and trusted reference checks. Fixture only, no connections, installed state, or WFP operation.");
    }

    private static void CheckRoutes(Assembly library,Action<bool> check)
    {
        var routeType=library.GetType("ProtectionLifecycle.ProxyRouteObservation",true)!;
        var evaluate=routeType.GetMethod("Evaluate",Static)!;
        var withReadback=routeType.GetMethod("EvaluateWithConfigReadback",Static)!;
        var require=routeType.GetMethod("RequireAllowed",Instance)!;
        JsonElement Route(string proxies,string config="{\"mode\":\"global\"}")=>JsonSerializer.SerializeToElement(
            evaluate.Invoke(null,[Encoding.UTF8.GetBytes(config),Encoding.UTF8.GetBytes(proxies)]));
        const string snapshot="""
            {"proxies":{
              "GLOBAL":{"name":"GLOBAL","type":"Selector","now":"chain","all":["chain","DIRECT"],"emptyFallback":"REJECT","dialer-proxy":""},
              "chain":{"name":"chain","type":"Fallback","now":"private node","all":["private node","backup"],"emptyFallback":"REJECT","dialer-proxy":""},
              "private node":{"name":"private node","type":"Vless","dialer-proxy":""},
              "backup":{"name":"backup","type":"Vless","dialer-proxy":""},
              "REJECT":{"name":"REJECT","type":"Reject","dialer-proxy":""}
            }}
            """;
        bool Flag(JsonElement route,string name)=>route.GetProperty(name).GetBoolean();
        string? Status(JsonElement route)=>route.GetProperty("Status").GetString();
        var current=Route(snapshot);
        check(Status(current)=="NO_DIRECT_ROUTE_IN_SNAPSHOT" && Flag(current,"Complete") && !Flag(current,"ReachableDirect") &&
            Flag(current,"ManualDirectChoice") && Flag(current,"SelectableDirectRoute") && !Flag(current,"AllowsRoutePrecheck") &&
            !current.GetRawText().Contains("private node",StringComparison.Ordinal));
        var nestedAlternative=snapshot.Replace("\"chain\",\"DIRECT\"","\"chain\",\"alternate\"",StringComparison.Ordinal)
            .Replace("\"REJECT\":{","\"alternate\":{\"name\":\"alternate\",\"type\":\"Selector\",\"now\":\"backup\",\"all\":[\"backup\",\"DIRECT\"],\"emptyFallback\":\"REJECT\",\"dialer-proxy\":\"\"},\"REJECT\":{",StringComparison.Ordinal);
        var nested=Route(nestedAlternative);
        check(!Flag(nested,"ReachableDirect") && !Flag(nested,"ManualDirectChoice") && Flag(nested,"SelectableDirectRoute") && !Flag(nested,"AllowsRoutePrecheck"));
        var unknownChoice=Route(snapshot.Replace("\"chain\",\"DIRECT\"","\"chain\",\"missing\"",StringComparison.Ordinal));
        check(Flag(unknownChoice,"Complete") && !Flag(unknownChoice,"SelectionGraphComplete") && !Flag(unknownChoice,"AllowsRoutePrecheck"));
        var allSafe=Route(nestedAlternative.Replace("\"backup\",\"DIRECT\"","\"backup\",\"private node\"",StringComparison.Ordinal));
        check(Flag(allSafe,"Complete") && Flag(allSafe,"SelectionGraphComplete") && Flag(allSafe,"AllowsRoutePrecheck"));
        var safeInventory=Encoding.UTF8.GetBytes(nestedAlternative.Replace("\"backup\",\"DIRECT\"","\"backup\",\"private node\"",StringComparison.Ordinal));
        var global="{\"mode\":\"global\"}"u8.ToArray();
        JsonElement WithReadback(byte[] after)=>JsonSerializer.SerializeToElement(withReadback.Invoke(null,[global,safeInventory,after]));
        check(Flag(WithReadback(global.ToArray()),"AllowsRoutePrecheck"));
        var changed=WithReadback("{\"mode\":\"direct\"}"u8.ToArray());
        check(Status(changed)=="CONTROLLER_CONFIG_CHANGED_DURING_SNAPSHOT" && !Flag(changed,"AllowsRoutePrecheck"));
        check(Status(WithReadback(new byte[16385]))=="CONTROLLER_EVIDENCE_UNAVAILABLE");
        const string connectStage="UpstreamRouteBeforeConnectRefused";
        var safeRoute=withReadback.Invoke(null,[global,safeInventory,global.ToArray()]);
        _=require.Invoke(safeRoute,[connectStage]);check(true);
        foreach(var unsafeRoute in new[]{
            withReadback.Invoke(null,[global,safeInventory,"{\"mode\":\"direct\"}"u8.ToArray()]),
            evaluate.Invoke(null,[global,Encoding.UTF8.GetBytes(snapshot)]),
            evaluate.Invoke(null,[global,new byte[0]])})
        {
            var refused=false;
            try{_=require.Invoke(unsafeRoute,[connectStage]);}
            catch(TargetInvocationException error)when(error.InnerException is InvalidDataException refusal &&
                refusal.Data["Stage"] is string actual && actual==connectStage){refused=true;}
            check(refused);
        }
        var badRoute=evaluate.Invoke(null,[global,Encoding.UTF8.GetBytes(snapshot)]);
        var monitor=typeof(LocalManagementBoundaryCases).GetMethod(nameof(CheckRouteMonitor),Static)!.MakeGenericMethod(routeType);
        ((Task)monitor.Invoke(null,[routeType.GetMethod("Supervise",Static),safeRoute,badRoute,check])!).GetAwaiter().GetResult();
        var emptyFallback=Route(snapshot.Replace("\"emptyFallback\":\"REJECT\"","\"emptyFallback\":\"COMPATIBLE\"",StringComparison.Ordinal));
        check(Flag(emptyFallback,"DirectEmptyFallback") && Flag(emptyFallback,"ReachableDirect"));
        var automatic=Route(snapshot.Replace("\"backup\":{\"name\":\"backup\",\"type\":\"Vless\"",
            "\"backup\":{\"name\":\"backup\",\"type\":\"Direct\"",StringComparison.Ordinal));
        check(Flag(automatic,"ReachableDirect") && !Flag(automatic,"DirectEmptyFallback"));
        var selected=Route(snapshot.Replace("\"now\":\"chain\"","\"now\":\"DIRECT\"",StringComparison.Ordinal));
        check(Flag(selected,"ReachableDirect") && Status(selected)=="DIRECT_ROUTE_REACHABLE");
        check(Status(Route(snapshot,"{\"mode\":\"direct\"}"))=="DIRECT_MODE");
        check(Status(Route(snapshot,"{\"mode\":\"rule\"}"))=="GLOBAL_MODE_NOT_OBSERVED");
        foreach(var incomplete in new[]{
            snapshot.Replace("\"private node\",\"backup\"","\"private node\",\"GLOBAL\"",StringComparison.Ordinal),
            snapshot.Replace("\"private node\",\"backup\"","\"private node\",\"missing\"",StringComparison.Ordinal),
            snapshot.Replace("\"private node\",\"backup\"","\"private node\",\"private node\"",StringComparison.Ordinal),
            snapshot.Replace("\"emptyFallback\":\"REJECT\",","",StringComparison.Ordinal),
            snapshot.Replace("\"now\":\"chain\"","\"now\":\"unlisted\"",StringComparison.Ordinal),
            snapshot.Replace("\"dialer-proxy\":\"\"","\"dialer-proxy\":\"chain\"",StringComparison.Ordinal),
            snapshot.Replace("\"type\":\"Vless\"","\"type\":\"Unknown\"",StringComparison.Ordinal)})
            check(Status(Route(incomplete))=="ROUTE_EVIDENCE_INCOMPLETE");
        check(Status(Route(snapshot,"{\"mode\":\"direct\",\"mode\":\"global\"}"))=="CONTROLLER_EVIDENCE_UNAVAILABLE");
        check(Status(Route(snapshot.Replace("\"name\":\"GLOBAL\"","\"name\":\"GLOBAL\",\"name\":\"GLOBAL\"",StringComparison.Ordinal)))==
            "CONTROLLER_EVIDENCE_UNAVAILABLE");
        check(Status(Route(new string(' ',524289)))=="CONTROLLER_EVIDENCE_UNAVAILABLE");
    }

    private static async Task CheckRouteMonitor<T>(MethodInfo monitor,T allowed,T denied,Action<bool> check)
    {
        var captures=0;
        var verified=0;
        Func<CancellationToken,Task<T>> read=_=>Task.FromResult(++captures==1?allowed:denied);
        var refused=false;
        try
        {
            await ((Task)monitor.Invoke(null,[read,(Action)(()=>verified++),TimeSpan.Zero,CancellationToken.None])!)
                .WaitAsync(TimeSpan.FromSeconds(2));
        }
        catch(InvalidDataException error)when(error.Data["Stage"] as string=="UpstreamActiveRouteRefused"){refused=true;}
        check(refused && captures==2 && verified==1);

        using var stop=new CancellationTokenSource();
        read=_=>{stop.Cancel();return Task.FromResult(denied);};
        var canceled=false;
        try
        {
            await ((Task)monitor.Invoke(null,[read,(Action)(()=>verified++),TimeSpan.Zero,stop.Token])!)
                .WaitAsync(TimeSpan.FromSeconds(2));
        }
        catch(OperationCanceledException)when(stop.IsCancellationRequested){canceled=true;}
        check(canceled && verified==1);
    }
}
