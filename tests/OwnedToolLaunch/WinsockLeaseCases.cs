using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.AccessControl;
using System.Text.Json;
using System.Text.Json.Nodes;

internal static class WinsockLeaseCases
{
    internal static void Run(Assembly library,bool metadata)
    {
        var lease=library.GetType("ProtectionLifecycle.SessionWinsockReadAccess",true)!;
        var intentType=library.GetType("ProtectionLifecycle.WinsockReadIntent",true)!;
        var scope=library.GetType("ProtectionLifecycle.WinsockRegistryScope",true)!;
        const BindingFlags flags=BindingFlags.Static|BindingFlags.NonPublic;
        object? Call(Type type,string method,params object?[] values)
        {
            try{return type.GetMethod(method,flags)!.Invoke(null,values);}
            catch(TargetInvocationException ex)when(ex.InnerException is not null)
            {ExceptionDispatchInfo.Capture(ex.InnerException).Throw();throw;}
        }
        if(metadata){Console.WriteLine(Call(lease,"InspectCurrentMetadata"));return;}
        var count=0;void Check(bool ok){if(!ok)throw new InvalidOperationException("Winsock lease contract differs");count++;}
        const string package="S-1-15-2-1-2-3-4-5-6-7";
        var installation=new string('d',32);
        var original=new RawSecurityDescriptor("O:SYD:P(A;;KA;;;SY)(A;;KR;;;BU)").GetSddlForm(AccessControlSections.Owner|AccessControlSections.Access);
        var targets=(Array)Call(scope,"Targets",1)!;
        var rows=targets.Cast<object>().Select(target=>
        {
            var path=(string)target.GetType().GetProperty("Path")!.GetValue(target)!;
            var access=(int)target.GetType().GetProperty("Access")!.GetValue(target)!;
            return new{Path=path,Access=access,ContentSHA256=path.Length==0?null:new string('A',64),OriginalSecurity=original,
                GrantedSecurity=(string)Call(scope,"AddReadAce",original,package,access)!};
        }).ToArray();
        var valid=JsonSerializer.Serialize(new{SchemaVersion=1,InstallationId=installation,SessionId=new string('a',32),JobId=new string('b',32),
            Release=new string('c',32),ManifestSHA256=new string('A',64),PackageSid=package,ControlSet=1,Targets=rows});
        void Validate(string json,string? owner=null,string? sid=null)=>Call(lease,"Validate",JsonSerializer.Deserialize(json,intentType)!,owner??installation,sid??package);
        Validate(valid);Check(true);
        void Refuse(Action action)
        {
            var refused=false;try{action();}catch(Exception ex)when(ex is InvalidDataException or ArgumentException){refused=true;}Check(refused);
        }
        Refuse(()=>Validate(valid,owner:new string('e',32)));Refuse(()=>Validate(valid,sid:"S-1-15-2-9-8-7-6-5-4-3"));
        var legacy=original.Replace("D:P","D:",StringComparison.Ordinal);
        Call(scope,"RequireSupportedRootSecurity",legacy);Check(true);
        Call(scope,"RequireSupportedRootSecurity",original);Check(true);
        Call(scope,"RequireSupportedRootSecurity",original.Replace("D:P","D:AI",StringComparison.Ordinal));Check(true);
        var legacyIntent=JsonNode.Parse(valid)!.AsObject();
        legacyIntent["Targets"]![0]!["OriginalSecurity"]=legacy;
        legacyIntent["Targets"]![0]!["GrantedSecurity"]=(string)Call(scope,"AddReadAce",legacy,package,0x20000)!;
        Validate(legacyIntent.ToJsonString());Check(true);
        Refuse(()=>Call(scope,"RequireSupportedRootSecurity","O:SYD:AR(A;;KA;;;SY)"));
        Refuse(()=>Call(scope,"RequireSupportedRootSecurity","O:SYD:(A;ID;KA;;;SY)"));
        foreach(var mutate in new Action<JsonObject>[] {
            j=>j["SchemaVersion"]=2,j=>j["ControlSet"]=0,j=>j["ControlSet"]=2,j=>j["SessionId"]="bad",
            j=>j["JobId"]="bad",j=>j["Release"]="bad",j=>j["ManifestSHA256"]="bad",j=>j["Targets"]=null,
            j=>j["Targets"]![0]=null,j=>j["Targets"]![0]!["Path"]=@"SOFTWARE\Microsoft\Cryptography",
            j=>j["Targets"]![0]!["Access"]=1,j=>j["Targets"]![0]!["ContentSHA256"]=new string('A',64),
            j=>j["Targets"]![1]!["ContentSHA256"]=null,j=>j["Targets"]![1]!["ContentSHA256"]="bad",
            j=>j["Targets"]![1]!["GrantedSecurity"]=original,j=>j["Targets"]!.AsArray().RemoveAt(24),
            j=>j["Targets"]![0]!["GrantedSecurity"]="O:SYD:P(A;;KA;;;SY)(A;;KR;;;BU)(A;CI;RC;;;"+package+")"})
        {
            var changed=JsonNode.Parse(valid)!.AsObject();mutate(changed);Refuse(()=>Validate(changed.ToJsonString()));
        }
        var state=library.GetType("ProtectionLifecycle.ProtectedState",true)!;
        var prefix=(string)lease.GetField("IntentPrefix",flags)!.GetRawConstantValue()!;
        Call(state,"RequireFixedInventoryPrefix",prefix);Check(prefix=="winsock-access-intent-");
        var broker=library.GetType("ProtectionLifecycle.InstalledBroker",true)!;
        foreach(var method in new[]{"QualifyWinsockSessionGateway","InspectWinsockReadAccess","RecoverWinsockReadAccess"})
        {
            var entry=broker.GetMethod(method)!;Check(entry.GetParameters().Length==0);
            var refused=false;
            try{entry.Invoke(null,null);}catch(TargetInvocationException ex)when(ex.InnerException is UnauthorizedAccessException){refused=true;}
            Check(refused);
        }
        Console.WriteLine($"PASS {count} Winsock intent ownership, exact target/hash/ACL binding, malformed-record rejection, state prefix and ordinary-maintenance refusal checks. Memory records and own caller identity only; no registry/state mutation or protected launch.");
    }
}
