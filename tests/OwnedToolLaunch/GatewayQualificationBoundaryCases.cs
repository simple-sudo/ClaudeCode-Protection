using System.Reflection;
using System.Runtime.ExceptionServices;

internal static class GatewayQualificationBoundaryCases
{
    internal static void Run(Assembly library)
    {
        var broker=library.GetType("ProtectionLifecycle.InstalledBroker",true)!;
        var session=library.GetType("ProtectionLifecycle.ProtectedSession",true)!;
        var count=0;
        void Check(bool value){if(!value)throw new InvalidOperationException("Gateway qualification boundary refused");count++;}
        object? Call(string method)
        {
            var output=Console.Out;var culture=System.Globalization.CultureInfo.CurrentCulture;var ui=System.Globalization.CultureInfo.CurrentUICulture;
            var defaultCulture=System.Globalization.CultureInfo.DefaultThreadCurrentCulture;var defaultUi=System.Globalization.CultureInfo.DefaultThreadCurrentUICulture;
            try
            {
                if(method=="RunGatewayQualificationCanary")Console.SetOut(new StringWriter());
                return broker.GetMethod(method,BindingFlags.Public|BindingFlags.Static)!.Invoke(null,null);
            }
            catch(TargetInvocationException ex)when(ex.InnerException is not null){ExceptionDispatchInfo.Capture(ex.InnerException).Throw();throw;}
            finally{Console.SetOut(output);System.Globalization.CultureInfo.DefaultThreadCurrentCulture=defaultCulture;System.Globalization.CultureInfo.DefaultThreadCurrentUICulture=defaultUi;System.Globalization.CultureInfo.CurrentCulture=culture;System.Globalization.CultureInfo.CurrentUICulture=ui;}
        }
        Check((bool)session.GetProperty("SystemTestingBlocked",BindingFlags.Static|BindingFlags.NonPublic)!.GetValue(null)!);
        Check(broker.GetMethod("QualifySessionGateway")!.GetParameters().Length==0);
        Check(broker.GetMethod("RunGatewayQualificationCanary")!.GetParameters().Length==0);
        var matchRoot=session.GetNestedType("Admission",BindingFlags.NonPublic)!
            .GetMethod("MatchesFixedGatewayRoot",BindingFlags.NonPublic|BindingFlags.Static)!;
        bool Matches((uint,long) peer,uint pid,long time)=>(bool)matchRoot.Invoke(null,new object[]{peer,pid,time})!;
        Check(Matches((111,200),111,200));
        Check(!Matches((222,200),111,200));
        Check(!Matches((111,201),111,200));
        Check(!Matches((0,200),0,200));
        Check(!Matches((111,0),111,0));
        // Ordinary callers must be rejected by the common administrator gate,
        // before opening protected state or creating native runtime objects.
        var denied=false;try{Call("QualifySessionGateway");}catch(UnauthorizedAccessException){denied=true;}Check(denied);
        var names=new[]{"CPC_SESSION_ID","CPC_SESSION_SECRET","CPC_RESOURCE_PLAN","CPC_NETWORK_PLAN","CPC_GPU_PLAN"};
        var saved=names.Select(Environment.GetEnvironmentVariable).ToArray();
        try
        {
            foreach(var name in names)Environment.SetEnvironmentVariable(name,null);
            Check((int)Call("RunGatewayQualificationCanary")! ==125);
            Environment.SetEnvironmentVariable(names[0],new string('a',32));
            Check((int)Call("RunGatewayQualificationCanary")! ==125);
            Environment.SetEnvironmentVariable(names[1],new string('B',64));
            // Well-shaped environment strings cannot manufacture a real LPAC.
            Check((int)Call("RunGatewayQualificationCanary")! ==125);
            foreach(var name in names.Skip(2))
            {
                Environment.SetEnvironmentVariable(name,"{}");
                Check((int)Call("RunGatewayQualificationCanary")! ==125);
                Environment.SetEnvironmentVariable(name,null);
            }
            var blocked=false;try{Call("RunAdmissionCanary");}catch(InvalidOperationException ex)when(ex.Message.StartsWith("SYSTEM_ARTIFACT_NOT_QUALIFIED:",StringComparison.Ordinal)){blocked=true;}Check(blocked);
            blocked=false;try{Call("RunSyntheticSession");}catch(InvalidOperationException ex)when(ex.Message.StartsWith("SYSTEM_ARTIFACT_NOT_QUALIFIED:",StringComparison.Ordinal)){blocked=true;}Check(blocked);
        }
        finally{for(var i=0;i<names.Length;i++)Environment.SetEnvironmentVariable(names[i],saved[i]);}
        var atomic=library.GetType("ProtectionLifecycle.AtomicChild",true)!;
        var map=atomic.GetMethod("SetPrivateRuntimeDirectories",BindingFlags.Static|BindingFlags.NonPublic)!;
        var env=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase){["PATH"]="fixed-system-path",["HTTP_PROXY"]="fixed-session-endpoint",["LOCALAPPDATA"]="host-value-must-be-replaced"};
        const string owned=@"C:\fixed-nonexistent-container-fixture";
        map.Invoke(null,new object[]{env,owned});
        foreach(var name in new[]{"TEMP","TMP","LOCALAPPDATA","USERPROFILE"})Check(env[name]==owned);
        Check(env["PATH"]=="fixed-system-path");Check(env["HTTP_PROXY"]=="fixed-session-endpoint");Check(env.Count==6);
        foreach(var invalid in new[]{"", "bad\0value"})
        {
            var before=string.Join(";",env.Select(x=>x.Key+"="+x.Value));var refused=false;
            try{map.Invoke(null,new object[]{env,invalid});}catch(TargetInvocationException ex)when(ex.InnerException is InvalidDataException){refused=true;}
            Check(refused && before==string.Join(";",env.Select(x=>x.Key+"="+x.Value)));
        }
        Console.WriteLine($"PASS {count} ordinary gateway qualification boundary checks; common maintenance gate, actual ordinary self token, conflicting plans, unchanged formal holds and pure private-directory mapping. No UAC, protected-state access, gateway, network, Job or WFP operation.");
    }
}
