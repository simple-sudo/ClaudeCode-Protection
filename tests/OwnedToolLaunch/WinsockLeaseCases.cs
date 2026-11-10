using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.AccessControl;
using System.Text.Json;
using System.Text.Json.Nodes;

internal static class WinsockLeaseCases
{
    internal static void RunGraphicsDrivers(Assembly library)
    {
        var lease=library.GetType("ProtectionLifecycle.SessionWinsockReadAccess",true)!;
        var intent=library.GetType("ProtectionLifecycle.WinsockReadIntent",true)!;
        const BindingFlags hidden=BindingFlags.Static|BindingFlags.NonPublic;
        const string package="S-1-15-2-1-2-3-4-5-6-7",original="O:SYD:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;BU)";
        object? Call(string method,params object?[] args)
        {
            try{return lease.GetMethod(method,hidden)!.Invoke(null,args);}
            catch(TargetInvocationException e)when(e.InnerException is not null){ExceptionDispatchInfo.Capture(e.InnerException).Throw();throw;}
        }
        var granted=(string)Call("GraphicsDriversGrant",original,package)!;
        var acl=new RawSecurityDescriptor(granted).DiscretionaryAcl!;
        if(acl.Count!=3 || acl[0] is not CommonAce read || read.SecurityIdentifier.Value!=package ||
            read.AceFlags!=AceFlags.None || read.AccessMask!=0x20019 || read.AceQualifier!=AceQualifier.AccessAllowed)
            throw new InvalidDataException("GraphicsDrivers test ACE differs");
        var id=new string('a',32);
        var row=JsonSerializer.SerializeToNode(new{SchemaVersion=4,InstallationId=id,SessionId=id,JobId=id,Release=id,
            ManifestSHA256=new string('A',64),PackageSid=package,ControlSet=1,Targets=new[]{new{
                Path=@"SYSTEM\ControlSet001\Control\GraphicsDrivers",Access=0x20019,ContentSHA256=new string('B',64),
                OriginalSecurity=original,GrantedSecurity=granted}}})!;
        void Validate(JsonNode value)=>Call("Validate",JsonSerializer.Deserialize(value.ToJsonString(),intent)!,id,package);
        Validate(row);
        foreach(var change in new Action<JsonNode>[] {
            j=>j["ControlSet"]=2,j=>j["JobId"]=new string('b',32),j=>j["Targets"]![0]!["Access"]=0xf003f,
            j=>j["Targets"]![0]!["Path"]=@"SYSTEM\ControlSet001\Control\GraphicsDrivers\Configuration",
            j=>j["Targets"]![0]!["ContentSHA256"]=null,j=>j["Targets"]![0]!["GrantedSecurity"]=original})
        {
            var changed=row.DeepClone();change(changed);
            try{Validate(changed);}
            catch(InvalidDataException){continue;}
            throw new InvalidDataException("GraphicsDrivers malformed intent accepted");
        }
        var scope=library.GetType("ProtectionLifecycle.WinsockRegistryScope",true)!;
        var rootGranted=(string)scope.GetMethod("AddReadAce",hidden)!.Invoke(null,[original,package,0x20000])!;
        var rootCase=row.DeepClone();rootCase["SchemaVersion"]=5;
        rootCase["Targets"]!.AsArray().Insert(0,JsonSerializer.SerializeToNode(new{Path="",Access=0x20000,
            ContentSHA256=(string?)null,OriginalSecurity=original,GrantedSecurity=rootGranted}));
        Validate(rootCase);
        foreach(var access in new[]{0x20019,0xf003f})
        {
            var broadened=rootCase.DeepClone();broadened["Targets"]![0]!["Access"]=access;
            try{Validate(broadened);}
            catch(InvalidDataException){continue;}
            throw new InvalidDataException("GraphicsDrivers root content access accepted");
        }
        Console.WriteLine(Call("InspectGraphicsDriversMetadata"));
        Console.WriteLine("PASS exact package read, root READ_CONTROL, eight invalid intents and ordinary read-only native registry inventory");
    }

    internal static void RunProviders(Assembly library,bool metadata)
    {
        var lease=library.GetType("ProtectionLifecycle.SessionWinsockReadAccess",true)!;
        var scope=library.GetType("ProtectionLifecycle.WinsockRegistryScope",true)!;
        object? Call(Type type,string method,params object?[] arguments)
        {
            try{return type.GetMethod(method,BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,arguments);}
            catch(TargetInvocationException ex)when(ex.InnerException is not null){ExceptionDispatchInfo.Capture(ex.InnerException).Throw();throw;}
        }
        if(metadata){Console.WriteLine(Call(lease,"InspectProviderMetadata"));return;}
        var count=0;
        void Check(bool ok){if(!ok)throw new InvalidOperationException("Winsock provider contract differs");count++;}
        void Refuse(Action action){var no=false;try{action();}catch(Exception ex)when(ex is InvalidDataException or ArgumentException){no=true;}Check(no);}
        var targets=(Array)Call(scope,"ProviderTargets",1)!;
        var transport=(Array)Call(scope,"TransportTargets",1)!;
        var legacy=(Array)Call(scope,"Targets",1)!;
        string PathOf(object item)=>(string)item.GetType().GetProperty("Path")!.GetValue(item)!;
        int AccessOf(object item)=>(int)item.GetType().GetProperty("Access")!.GetValue(item)!;
        var prefix=@"SYSTEM\ControlSet001\Services\Winsock\Setup Migration\Providers";
        Check(targets.Length==31 && targets.Cast<object>().Take(28).SequenceEqual(transport.Cast<object>()));
        Check(targets.Cast<object>().Skip(28).Select(PathOf).SequenceEqual(new[]{prefix,prefix+@"\Tcpip6",prefix+@"\Tcpip"}));
        Check(targets.Cast<object>().Skip(28).All(t=>AccessOf(t)==0x20019));
        Call(scope,"RequireExactProviderTargets",1,targets);Check(true);
        Refuse(()=>Call(scope,"RequireExactProviderTargets",1,transport));Refuse(()=>Call(scope,"RequireExactProviderTargets",1,legacy));
        Refuse(()=>Call(scope,"RequireExactTransportTargets",1,targets));Refuse(()=>Call(scope,"ProviderTargets",0));
        var names=new[]{"afunix","Psched","RFCOMM","Tcpip","Tcpip6","vmbus"};
        Call(scope,"RequireProviderSelection",new object?[]{names});Check(true);
        Call(scope,"RequireProviderSelection",new object?[]{names.Reverse().ToArray()});Check(true);
        Refuse(()=>Call(scope,"RequireProviderSelection",new object?[]{names.Skip(1).ToArray()}));
        Refuse(()=>Call(scope,"RequireProviderSelection",new object?[]{names.Append("UnknownProvider").ToArray()}));
        Refuse(()=>Call(scope,"RequireProviderSelection",new object?[]{names.Append("Tcpip").ToArray()}));
        foreach(var family in new[]{2,23})
        {
            var id=Guid.Parse(family==23?"f9eab0c0-26d4-11d0-bbbf-00aa006c34e4":"e70f1aa0-ab8b-11cf-8ca3-00805f48a192").ToByteArray();
            Call(scope,"RequireProviderId",id,family);Check(true);
            Refuse(()=>Call(scope,"RequireProviderId",id,family==2?23:2));
            Refuse(()=>Call(scope,"RequireProviderId",id[..^1],family));
            var changed=(byte[])id.Clone();changed[0]^=1;Refuse(()=>Call(scope,"RequireProviderId",changed,family));
            Refuse(()=>Call(scope,"RequireProviderId",id,0));
        }
        const string package="S-1-15-2-1-2-3-4-5-6-7",original="O:SYD:P(A;;KA;;;SY)(A;;KR;;;BU)";
        var intent=library.GetType("ProtectionLifecycle.WinsockReadIntent",true)!;
        void Validate(string text)=>Call(lease,"Validate",JsonSerializer.Deserialize(text,intent)!,new string('d',32),package);
        string Make(int schema,Array list)=>JsonSerializer.Serialize(new{SchemaVersion=schema,InstallationId=new string('d',32),SessionId=new string('a',32),JobId=new string('b',32),Release=new string('c',32),ManifestSHA256=new string('A',64),PackageSid=package,ControlSet=1,
            Targets=list.Cast<object>().Select(t=>new{Path=PathOf(t),Access=AccessOf(t),ContentSHA256=PathOf(t).Length==0?null:new string('A',64),OriginalSecurity=original,GrantedSecurity=(string)Call(scope,"AddReadAce",original,package,AccessOf(t))!}).ToArray()});
        var json=Make(3,targets);Validate(json);Check(true);Validate(Make(2,transport));Check(true);Validate(Make(1,legacy));Check(true);
        Refuse(()=>Validate(Make(3,transport)));Refuse(()=>Validate(Make(2,targets)));Refuse(()=>Validate(Make(1,targets)));
        foreach(var mutation in new Action<JsonObject>[] {
            j=>j["SchemaVersion"]=4,j=>j["ControlSet"]=2,j=>j["Targets"]!.AsArray().RemoveAt(30),
            j=>j["Targets"]![28]!["Path"]=@"SYSTEM\ControlSet001\Services\Winsock\Setup Migration",
            j=>j["Targets"]![29]!["Path"]=prefix+@"\afunix",j=>j["Targets"]![30]!["Access"]=0xf003f,
            j=>j["Targets"]![29]!["ContentSHA256"]=null,
            j=>j["Targets"]![29]!["OriginalSecurity"]="O:SYD:P(A;;KA;;;SY)",
            j=>j["Targets"]!.AsArray().Add(j["Targets"]![30]!.DeepClone())})
        {var changed=JsonNode.Parse(json)!.AsObject();mutation(changed);Refuse(()=>Validate(changed.ToJsonString()));}
        var entry=library.GetType("ProtectionLifecycle.InstalledBroker",true)!.GetMethod("QualifyWinsockProviderSessionGateway")!;
        Check(entry.GetParameters().Length==0);
        var rejected=false;try{entry.Invoke(null,null);}catch(TargetInvocationException ex)when(ex.InnerException is UnauthorizedAccessException){rejected=true;}Check(rejected);
        Console.WriteLine($"PASS {count} provider-map scope, generic GUID, selection drift, v1/v2/v3 recovery separation and ordinary-entry refusal checks. No registry/state write, protected process or network operation.");
    }
    internal static void RunTransport(Assembly library,bool metadata)
    {
        var lease=library.GetType("ProtectionLifecycle.SessionWinsockReadAccess",true)!;
        var scope=library.GetType("ProtectionLifecycle.WinsockRegistryScope",true)!;
        const BindingFlags flags=BindingFlags.Static|BindingFlags.NonPublic;
        object? Call(Type type,string method,params object?[] arguments)
        {
            try{return type.GetMethod(method,flags)!.Invoke(null,arguments);}
            catch(TargetInvocationException ex)when(ex.InnerException is not null){ExceptionDispatchInfo.Capture(ex.InnerException).Throw();throw;}
        }
        if(metadata){Console.WriteLine(Call(lease,"InspectTransportMetadata"));return;}
        var count=0;
        void Check(bool ok){if(!ok)throw new InvalidOperationException("Winsock transport contract differs");count++;}
        void Refuse(Action action){var no=false;try{action();}catch(Exception ex)when(ex is InvalidDataException or ArgumentException){no=true;}Check(no);}
        var targets=(Array)Call(scope,"TransportTargets",1)!;
        var old=(Array)Call(scope,"Targets",1)!;
        string PathOf(object item)=>(string)item.GetType().GetProperty("Path")!.GetValue(item)!;
        int AccessOf(object item)=>(int)item.GetType().GetProperty("Access")!.GetValue(item)!;
        Check(targets.Length==28 && targets.Cast<object>().Take(25).SequenceEqual(old.Cast<object>()));
        Check(targets.Cast<object>().Skip(25).Select(PathOf).SequenceEqual(new[]{@"SYSTEM\ControlSet001\Services\Winsock\Parameters",@"SYSTEM\ControlSet001\Services\Tcpip6\Parameters\Winsock",@"SYSTEM\ControlSet001\Services\Tcpip\Parameters\Winsock"}));
        Check(targets.Cast<object>().Skip(25).All(t=>AccessOf(t)==0x20019));
        Call(scope,"RequireExactTransportTargets",1,targets);Check(true);
        Refuse(()=>Call(scope,"RequireExactTargets",1,targets));Refuse(()=>Call(scope,"RequireExactTransportTargets",1,old));
        var transportNames=new[]{"Tcpip6","Tcpip","vmbus","Psched","afunix","RFCOMM"};
        Call(scope,"RequireTransportSelection",new object?[]{transportNames});Check(true);
        Refuse(()=>Call(scope,"RequireTransportSelection",new object?[]{transportNames.Reverse().ToArray()}));
        Refuse(()=>Call(scope,"RequireTransportSelection",new object?[]{transportNames.Append("ExternalProvider").ToArray()}));
        var pairs=new[]{(1,6),(1,0),(0,6),(2,17),(2,0),(0,17),(3,255),(3,0)};
        foreach(var family in new[]{2,23})
        {
            var bytes=new byte[104];BitConverter.GetBytes(8).CopyTo(bytes,0);BitConverter.GetBytes(3).CopyTo(bytes,4);
            for(var i=0;i<8;i++){BitConverter.GetBytes(family).CopyTo(bytes,8+i*12);BitConverter.GetBytes(pairs[i].Item1).CopyTo(bytes,12+i*12);BitConverter.GetBytes(pairs[i].Item2).CopyTo(bytes,16+i*12);}
            Call(scope,"RequireTransportMapping",bytes,family);Check(true);
            var corrupt=(byte[])bytes.Clone();corrupt[20]^=1;Refuse(()=>Call(scope,"RequireTransportMapping",corrupt,family));
            Refuse(()=>Call(scope,"RequireTransportMapping",bytes[..^1],family));Refuse(()=>Call(scope,"RequireTransportMapping",bytes,0));
        }
        const string package="S-1-15-2-1-2-3-4-5-6-7",original="O:SYD:P(A;;KA;;;SY)(A;;KR;;;BU)";
        var rows=targets.Cast<object>().Select(t=>new{Path=PathOf(t),Access=AccessOf(t),ContentSHA256=PathOf(t).Length==0?null:new string('A',64),OriginalSecurity=original,GrantedSecurity=(string)Call(scope,"AddReadAce",original,package,AccessOf(t))!}).ToArray();
        var json=JsonSerializer.Serialize(new{SchemaVersion=2,InstallationId=new string('d',32),SessionId=new string('a',32),JobId=new string('b',32),Release=new string('c',32),ManifestSHA256=new string('A',64),PackageSid=package,ControlSet=1,Targets=rows});
        var intent=library.GetType("ProtectionLifecycle.WinsockReadIntent",true)!;
        void Validate(string text)=>Call(lease,"Validate",JsonSerializer.Deserialize(text,intent)!,new string('d',32),package);
        Validate(json);Check(true);
        foreach(var mutation in new Action<JsonObject>[] {
            j=>j["SchemaVersion"]=1,j=>j["SchemaVersion"]=3,j=>j["Targets"]!.AsArray().RemoveAt(27),
            j=>j["Targets"]![25]!["Path"]=@"SYSTEM\ControlSet001\Services\Tcpip\Parameters",
            j=>j["Targets"]![26]!["Path"]=@"SYSTEM\ControlSet001\Services\Tcpip6\Parameters\Winsock\0",
            j=>j["Targets"]![27]!["Access"]=0xf003f,j=>j["Targets"]![25]!["ContentSHA256"]=null})
        {var changed=JsonNode.Parse(json)!.AsObject();mutation(changed);Refuse(()=>Validate(changed.ToJsonString()));}
        var entry=library.GetType("ProtectionLifecycle.InstalledBroker",true)!.GetMethod("QualifyWinsockTransportSessionGateway")!;
        Check(entry.GetParameters().Length==0);
        var rejected=false;try{entry.Invoke(null,null);}catch(TargetInvocationException ex)when(ex.InnerException is UnauthorizedAccessException){rejected=true;}
        Check(rejected);
        Console.WriteLine($"PASS {count} fixed transport targets, selection/mapping, v1/v2 separation and ordinary caller refusal checks. Memory and own identity only; no registry writes or protected session.");
    }
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
