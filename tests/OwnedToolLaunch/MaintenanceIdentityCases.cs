using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

internal static class MaintenanceIdentityCases
{
    internal static void Run(Assembly library)
    {
        const BindingFlags flags=BindingFlags.Static|BindingFlags.NonPublic;
        var type=library.GetType("ProtectionLifecycle.MaintenanceIdentity",true)!;
        var factsType=type.GetNestedType("TokenFacts",BindingFlags.NonPublic)!;
        object Facts(int kind=1,int app=0,int elevated=1,int restricted=0)=>Activator.CreateInstance(factsType,kind,app,elevated,restricted)!;
        object? Call(string name,params object?[] args)
        {try{return type.GetMethod(name,flags)!.Invoke(null,args);}catch(TargetInvocationException e)when(e.InnerException is not null){ExceptionDispatchInfo.Capture(e.InnerException).Throw();throw;}}
        var checks=0;
        void Require(bool condition,string reason){if(!condition)throw new InvalidDataException(reason);checks++;}
        void Refuse(Action action)
        {try{action();}catch(UnauthorizedAccessException){checks++;return;}throw new InvalidDataException("Maintenance authority was accepted");}
        Call("RequireEvidence",Facts(),true);checks++;
        foreach(var facts in new[]{Facts(kind:2),Facts(kind:0),Facts(kind:3),Facts(app:1),Facts(app:-1),Facts(elevated:0),Facts(elevated:2),Facts(restricted:1),Facts(restricted:-1)})
            Refuse(()=>Call("RequireEvidence",facts,true));
        Refuse(()=>Call("RequireEvidence",Facts(),false));
        using var identity=WindowsIdentity.GetCurrent(TokenAccessLevels.Query|TokenAccessLevels.Duplicate);
        var ownFacts=Call("ReadFacts",identity.AccessToken)!;
        int Value(string name)=>(int)factsType.GetProperty(name)!.GetValue(ownFacts)!;
        Require(Value("Type")==1 && Value("AppContainer")==0 && Value("Elevated")==0 && Value("RestrictedSidCount")==0,"ordinary own token facts");
        Refuse(()=>Call("RequireCurrentAdministrator"));
        var state=library.GetType("ProtectionLifecycle.ProtectedState",true)!;
        try{state.GetMethod("RequireAdministrator",flags)!.Invoke(null,null);throw new InvalidDataException("state accepted ordinary maintenance");}
        catch(TargetInvocationException e)when(e.InnerException is UnauthorizedAccessException){checks++;}
        // Same-user ordinary thread impersonation only: no foreign identity,
        // privilege, token adjustment, state access, process creation or UAC.
        WindowsIdentity.RunImpersonated(identity.AccessToken,()=>
        {
            using var effective=WindowsIdentity.GetCurrent(TokenAccessLevels.Query|TokenAccessLevels.Duplicate);
            var threaded=Call("ReadFacts",effective.AccessToken)!;
            Require((int)factsType.GetProperty("Type")!.GetValue(threaded)! ==2,"actual thread impersonation observed");
            // Even an artificial administrator membership result must not
            // turn an actual impersonation token into maintenance authority.
            Refuse(()=>Call("RequireEvidence",threaded,true));
            Refuse(()=>Call("RequireCurrentAdministrator"));
        });
        using var restored=WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        var after=Call("ReadFacts",restored.AccessToken)!;
        Require((int)factsType.GetProperty("Type")!.GetValue(after)! ==1,"thread primary identity restored");
        using var invalid=new SafeAccessTokenHandle(IntPtr.Zero);
        try{Call("ReadFacts",invalid);throw new InvalidDataException("invalid token accepted");}
        catch(System.ComponentModel.Win32Exception){checks++;}
        Console.WriteLine($"PASS maintenance identity: {checks} checks; unrestricted primary admin policy control, impersonation/AppContainer/restriction/elevation/membership refusals, actual ordinary token/shared gate refusal, same-user thread impersonation/restoration, invalid query refusal. No elevation/install/Broker/state/LPAC/Job/network; no elevated or restricted-token runtime claim.");
    }
}
