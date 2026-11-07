using System.Collections;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

internal static class OpenSslMemoryCases
{
    private const BindingFlags Static=BindingFlags.Static|BindingFlags.NonPublic;
    private const BindingFlags Instance=BindingFlags.Instance|BindingFlags.NonPublic|BindingFlags.Public;
    internal static Task Run(Assembly library)
    {
        var type=library.GetType("ProtectionLifecycle.OpenSslOfflineWitness",true)!;
        var installed=library.GetType("ProtectionLifecycle.InstalledBroker",true)!;
        var id=new string('a',32);var before=DateTime.UtcNow.ToFileTimeUtc();
        int checks=0;
        void Check(bool value){if(!value)throw new InvalidDataException("Offline OpenSSL check failed");checks++;}
        void Reject<T>(Action action) where T:Exception
        {
            try{action();}
            catch(T){checks++;return;}
            throw new InvalidDataException("Invalid offline TLS input accepted");
        }
        var observed=Call(type.GetMethod("Observe",Static)!,id,true)!;
        var raw=JsonSerializer.Serialize(observed,type);
        Console.WriteLine(raw);
        var parse=type.GetMethod("Parse",Static)!;
        object Read(string data,uint exit)=>Call(parse,data,id,(uint)Environment.ProcessId,before,exit)!;
        bool Complete(object result)=>(bool)type.GetProperty("Complete",Instance)!.GetValue(result)!;
        Check(Complete(Read(raw,0)));
        Reject<InvalidDataException>(()=>Read(raw,3));
        Reject<InvalidDataException>(()=>Read(raw.Insert(1,"\"SchemaVersion\":1,"),0));
        var valid=JsonNode.Parse(raw)!.AsObject();
        foreach(var (field,value) in new (string,JsonNode?)[]{
            ("Pid",Environment.ProcessId+1),("SchemaVersion",2),("SessionId",new string('b',32)),("StartedFileTime",before-1),
            ("WrongNameError",0),("UnknownRootError",null),("EofDenied",false),("FailureStage","WRONG_NAME"),("Unreviewed",true)})
        {
            var invalid=valid.DeepClone().AsObject();invalid[field]=value;
            Reject<InvalidDataException>(()=>Read(invalid.ToJsonString(),0));
        }
        var failure=valid.DeepClone().AsObject();
        failure["FailureStage"]="UNKNOWN_ROOT";failure["ErrorCode"]=31;failure["UnknownRootError"]=null;failure["EofDenied"]=false;
        Check(!Complete(Read(failure.ToJsonString(),3)));
        Reject<InvalidDataException>(()=>Read(failure.ToJsonString(),0));
        Reject<UnauthorizedAccessException>(()=>Call(installed.GetMethod("QualifyOpenSslOffline")!));
        var env="CPC_OPENSSL_OFFLINE_SESSION";var old=Environment.GetEnvironmentVariable(env);
        try
        {
            Environment.SetEnvironmentVariable(env,id);
            Reject<InvalidDataException>(()=>Call(installed.GetMethod("RunOpenSslOfflineChild")!));
        }
        finally{Environment.SetEnvironmentVariable(env,old);}

        var policy=library.GetType("ProtectionLifecycle.PackagePolicy",true)!;
        var catalog=library.GetType("ProtectionLifecycle.PackageAssetCatalog",true)!;
        var versions=catalog.GetMethod("ForSchema",Static)!;
        var assetIds=new HashSet<string>(StringComparer.Ordinal);
        JsonArray Assets(int schema,string label)
        {
            var result=new JsonArray();
            foreach(var asset in (IEnumerable)Call(versions,schema)!)
            {
                object? Field(string name)=>asset!.GetType().GetProperty(name,Instance)!.GetValue(asset);
                result.Add(new JsonObject {[label]=(string)Field("Id")!,["Length"]=(long?)Field("FixedLength")??1L,
                    ["SHA256"]=(string?)Field("FixedSHA256")??new string('A',64)});
            }
            return result;
        }
        var pinned=policy.GetMethod("ParsePinned",Static)!;
        object ParseManifest(int schema,JsonArray assets)
        {
            var bytes=JsonSerializer.SerializeToUtf8Bytes(new JsonObject {
                ["SchemaVersion"]=schema,["Scope"]="UNACTIVATED_PRODUCT",["Release"]=id,["Files"]=assets.DeepClone()
            });
            return Call(pinned,new ReadOnlyMemory<byte>(bytes),Convert.ToHexString(SHA256.HashData(bytes)))!;
        }
        var v1=Assets(1,"Asset");var v2=Assets(2,"Asset");
        Check(v1.Count==14 && v2.Count==16 && v1.All(a=>assetIds.Add(a!["Asset"]!.GetValue<string>())) &&
            v2.Take(v1.Count).All(a=>assetIds.Contains(a!["Asset"]!.GetValue<string>())));
        _=ParseManifest(1,v1);_=ParseManifest(2,v2);checks+=2;
        Reject<InvalidDataException>(()=>ParseManifest(1,v2));
        Reject<InvalidDataException>(()=>ParseManifest(2,v1));
        Reject<InvalidDataException>(()=>ParseManifest(3,v2));
        var changed=v2.DeepClone().AsArray();changed[15]!["SHA256"]=new string('B',64);
        Reject<InvalidDataException>(()=>ParseManifest(2,changed));
        changed=v2.DeepClone().AsArray();changed[15]!["Length"]=10;
        Reject<InvalidDataException>(()=>ParseManifest(2,changed));
        changed=v2.DeepClone().AsArray();changed[15]=changed[14]!.DeepClone();
        Reject<InvalidDataException>(()=>ParseManifest(2,changed));
        var stage=policy.GetMethod("ParseInventory",Static)!;
        void ReadStage(JsonArray files,int schema)
        {
            using var document=JsonDocument.Parse(files.ToJsonString());
            _=Call(stage,document.RootElement,schema,"Id");
        }
        ReadStage(Assets(1,"Id"),1);ReadStage(Assets(2,"Id"),2);checks+=2;
        Reject<InvalidDataException>(()=>ReadStage(Assets(2,"Id"),1));
        Reject<InvalidDataException>(()=>ReadStage(v2,2));
        Console.WriteLine($"PASS {checks} fixed OpenSSL and package compatibility checks. Real TLS and gateway replay in ordinary memory only.");
        return Task.CompletedTask;
    }

    private static object? Call(MethodInfo method,params object[] args)
    {
        try{return method.Invoke(null,args);}
        catch(TargetInvocationException error)when(error.InnerException is not null)
        {ExceptionDispatchInfo.Capture(error.InnerException).Throw();throw;}
    }
}