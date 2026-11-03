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
        Console.WriteLine($"PASS {count} fixed gateway feedback contract and bounded-memory reader checks; no exception messages, paths, tokens or raw output; diagnostic only. No UAC, network, child process, protected state, Job or WFP operation.");
    }
}
