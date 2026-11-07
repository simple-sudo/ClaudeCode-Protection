using System.ComponentModel;
using System.Reflection;
using System.Runtime.ExceptionServices;

internal static class ResetSettingsFileCases
{
    internal static void Run(Assembly library)
    {
        const BindingFlags flags=BindingFlags.NonPublic|BindingFlags.Static;
        var type=library.GetType("ProtectionLifecycle.HostPrivacyProbe",true)!;
        var targetType=type.GetNestedType("Target",BindingFlags.NonPublic)!;
        var checks=0;
        object? Call(string name,params object?[] args)
        {try{return type.GetMethod(name,flags)!.Invoke(null,args);}catch(TargetInvocationException e)when(e.InnerException is not null){ExceptionDispatchInfo.Capture(e.InnerException).Throw();throw;}}
        void Require(bool value,string reason){if(!value)throw new InvalidDataException(reason);checks++;}
        void Refuse(Action action)
        {try{action();}catch(Exception e)when(e is IOException or Win32Exception or InvalidDataException){checks++;return;}throw new InvalidDataException("Reset target conflict accepted");}
        int Depth(object state)=>(int)state.GetType().GetProperty("MissingParentDepth")!.GetValue(state)!;
        string Id(object state)=>(string)state.GetType().GetProperty("Identity")!.GetValue(state)!;
        var catalogue=library.GetType("ClaudeCodeProtection.Workspaces.HostPrivacyContract",true)!;
        var inventory=((System.Collections.IEnumerable)catalogue.GetProperty("Checks",flags)!.GetValue(null)!).Cast<object>().ToArray();
        object Target(string path,object state,int index=7)=>Activator.CreateInstance(targetType,inventory[index],path,0,Id(state),Depth(state))!;
        var root=Path.Combine(Path.GetTempPath(),"cpc-reset-file-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        var folder=Path.Combine(root,".claude");var path=Path.Combine(folder,"settings.json");
        var missingFolder=Call("ObserveFileState",path,true)!;
        Require(Depth(missingFolder)==2 && Id(missingFolder).Length==24,"absent parent anchored to exact ordinary fixture root");
        Call("AssertFileStateCurrent",Target(path,missingFolder));checks++;
        Refuse(()=>Call("ObserveFileState",path,false));
        Directory.CreateDirectory(folder);
        Refuse(()=>Call("AssertFileStateCurrent",Target(path,missingFolder)));
        var missingFile=Call("ObserveFileState",path,true)!;
        Require(Depth(missingFile)==1 && Id(missingFile).Length==24,"absent file anchored to existing parent");
        Call("AssertFileStateCurrent",Target(path,missingFile));checks++;
        File.WriteAllText(path,"OWN_NONSECRET_RESET_FILE");
        Refuse(()=>Call("AssertFileStateCurrent",Target(path,missingFile)));
        var present=Call("ObserveFileState",path,true)!;
        Require(Depth(present)==0,"present file retains exact original file identity mode");
        Call("AssertFileStateCurrent",Target(path,present));checks++;
        Call("AssertFileStateCurrent",Target(path,present,0));checks++;
        var retained=Path.Combine(folder,"retained-nonsecret-settings.json");File.Move(path,retained);
        Refuse(()=>Call("AssertFileStateCurrent",Target(path,present)));
        var plain=Path.Combine(root,"plain.txt");File.WriteAllText(plain,"OWN_NONSECRET_REGULAR_FILE");
        Refuse(()=>Call("ObserveFileState",Path.Combine(plain,"settings.json"),true));
        foreach(var depth in new[]{1,2})Refuse(()=>Call("RequireMissingTarget",false,depth));
        foreach(var depth in new[]{0,1,2}){Call("RequireMissingTarget",true,depth);checks++;}
        foreach(var depth in new[]{-1,3})Refuse(()=>Call("RequireMissingTarget",true,depth));
        Require((bool)Call("IsMissing",new Win32Exception(2))! && (bool)Call("IsMissing",new Win32Exception(3))! &&
            !(bool)Call("IsMissing",new Win32Exception(5))! && !(bool)Call("IsMissing",new Win32Exception(32))!,"only exact file/path absence is classified missing");
        Console.WriteLine($"PASS reset-settings file state: {checks} checks; actual ordinary own missing-parent/missing-file/present transitions, anchor identity and creation/disappearance conflicts, regular-file parent refusal, only slot7/depth1-2 permitted. No real user config/content/ACL/host target/Broker/LPAC/Job/UAC/network; own nonsecret file retained at {retained}");
    }
}
