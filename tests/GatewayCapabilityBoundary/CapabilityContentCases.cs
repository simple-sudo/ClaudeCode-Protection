using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text.Json.Nodes;

internal static class CapabilityContentCases
{
    internal static int Run(Assembly library)
    {
        var method=library.GetType("ProtectionLifecycle.GatewayCapabilityChildReport",true)!.GetMethod("Parse",BindingFlags.NonPublic|BindingFlags.Static)!;
        int count=0;
        object Parse(JsonObject value,uint exit)
        {try{return method.Invoke(null,new object[]{value.ToJsonString(),new string('a',32),111u,exit,1000L})!;}catch(TargetInvocationException e)when(e.InnerException is not null){ExceptionDispatchInfo.Capture(e.InnerException).Throw();throw;}}
        JsonObject Denied()=>JsonNode.Parse("""
        {"SchemaVersion":1,"Gateway":{"SchemaVersion":1,"SessionId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","Pid":111,"Phase":"COMPLETE","ExitCode":42,"HttpStatus":200,"Errors":[]},
        "Endpoint":{"Pid":111,"Phase":"SOCKET_CLOSED","Created":true,"OwnedHandleClosed":true,"Errors":[]},
        "Network":{"Pid":111,"StartedFileTime":2000,"FinishedFileTime":3000,"Reads":[
        {"Role":"adapters-all-families","SizeStatus":5,"RequestedBytes":0,"ReadStatus":null,"ReturnedBytes":0,"NativeBase":0,"Content":"","ErrorKind":null,"ErrorCode":null},
        {"Role":"tcp-owner-pid-v4","SizeStatus":5,"RequestedBytes":0,"ReadStatus":null,"ReturnedBytes":0,"NativeBase":0,"Content":"","ErrorKind":null,"ErrorCode":null},
        {"Role":"tcp-owner-pid-v6","SizeStatus":5,"RequestedBytes":0,"ReadStatus":null,"ReturnedBytes":0,"NativeBase":0,"Content":"","ErrorKind":null,"ErrorCode":null}]}}
        """)!.AsObject();
        void Accept(JsonObject value,uint exit){_=Parse(value,exit);count++;}
        void Reject(Action<JsonObject> mutate)
        {var value=Denied();mutate(value);bool rejected=false;try{_=Parse(value,42);}catch(Exception e)when(e is InvalidDataException or System.Text.Json.JsonException or FormatException){rejected=true;}if(!rejected)throw new InvalidDataException("CapabilityContentFixtureAcceptedInvalid");count++;}
        JsonObject Row(JsonObject value,int index=0)=>value["Network"]!["Reads"]![index]!.AsObject();
        Accept(Denied(),42);
        Reject(v=>v["Extra"]=true);Reject(v=>v["SchemaVersion"]=2);Reject(v=>v["Network"]!["Pid"]=112);
        Reject(v=>v["Network"]!["StartedFileTime"]=999);Reject(v=>v["Network"]!["FinishedFileTime"]=1999);
        Reject(v=>v["Network"]!["FinishedFileTime"]=2000+TimeSpan.TicksPerSecond*16);
        Reject(v=>v["Network"]!["Reads"]!.AsArray().RemoveAt(0));Reject(v=>Row(v)["Role"]="untrusted");
        Reject(v=>Row(v,1)["Role"]="adapters-all-families");Reject(v=>Row(v)["Content"]=Convert.ToBase64String(new byte[65537]));
        Reject(v=>Row(v)["RequestedBytes"]=65537);Reject(v=>Row(v)["NativeBase"]=1234);Reject(v=>Row(v)["ErrorCode"]=5);
        Reject(v=>Row(v)["ErrorKind"]="arbitrary text");Reject(v=>Row(v)["ReadStatus"]=0);Reject(v=>v["Network"]=null);
        Reject(v=>v["Endpoint"]=null);Reject(v=>v["Endpoint"]!["Pid"]=112);Reject(v=>v["Endpoint"]!["OwnedHandleClosed"]=false);
        Reject(v=>v["Endpoint"]!["Created"]=false);Reject(v=>v["Endpoint"]!["Phase"]="UNVERIFIED");
        var exposure=Denied();exposure["Gateway"]!["Phase"]="NETWORK_CONTENT_REQUIRES_ANALYSIS";exposure["Gateway"]!["ExitCode"]=125;
        exposure["Gateway"]!["HttpStatus"]=null;exposure["Gateway"]!["Errors"]=JsonNode.Parse("[{\"Kind\":\"CONTRACT\",\"Code\":-1}]");
        var r=Row(exposure);r["SizeStatus"]=111;r["RequestedBytes"]=4;r["ReadStatus"]=0;r["ReturnedBytes"]=4;r["Content"]="AAAAAA==";r["NativeBase"]=4096;
        Accept(exposure,125);
        var premature=exposure.DeepClone().AsObject();premature["Gateway"]=Denied()["Gateway"]!.DeepClone();
        bool denied=false;try{Parse(premature,42);}catch(InvalidDataException){denied=true;}if(!denied)throw new InvalidDataException("ExposedContentForwardingAccepted");count++;
        var contradiction=Denied();contradiction["Gateway"]=exposure["Gateway"]!.DeepClone();
        denied=false;try{Parse(contradiction,125);}catch(InvalidDataException){denied=true;}if(!denied)throw new InvalidDataException("FalseExposureOutcomeAccepted");count++;
        var early=Denied();early["Gateway"]=exposure["Gateway"]!.DeepClone();early["Gateway"]!["Phase"]="IDENTITY";early["Network"]=null;early["Endpoint"]=null;Accept(early,125);
        var socketFailure=Denied();socketFailure["Gateway"]=exposure["Gateway"]!.DeepClone();socketFailure["Gateway"]!["Phase"]="HTTPS_SOCKET_CREATE";
        socketFailure["Endpoint"]=JsonNode.Parse("{\"Pid\":111,\"Phase\":\"SOCKET_CREATE\",\"Created\":false,\"OwnedHandleClosed\":null,\"Errors\":[{\"Kind\":\"SOCKET_CREATE\",\"Code\":10013},{\"Kind\":\"SOCKET_NT_CONTEXT\",\"Code\":-1073741790}]}");
        Accept(socketFailure,125);
        return count;
    }
}
