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
        object Target(string path,object state)=>Activator.CreateInstance(targetType,"private-claude-settings","file-read-data-open",path,0,Id(state),Depth(state))!;
        var root=Path.Combine(Path.GetTempPath(),"cpc-reset-file-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        var folder=Path.Combine(root,".claude");var path=Path.Combine(folder,"settings.json");
        var missingFolder=Call("ObserveFileState",path,true)!;
        Require(Depth(missingFolder)==2 && Id(missingFolder).Length==24,"absent parent anchored to exact ordinary fixture root");
        Call("AssertFileStateCurrent",Target(path,missingFolder),7);checks++;
        Refuse(()=>Call("ObserveFileState",path,false));
        Directory.CreateDirectory(folder);
        Refuse(()=>Call("AssertFileStateCurrent",Target(path,missingFolder),7));
        var missingFile=Call("ObserveFileState",path,true)!;
        Require(Depth(missingFile)==1 && Id(missingFile).Length==24,"absent file anchored to existing parent");
        Call("AssertFileStateCurrent",Target(path,missingFile),7);checks++;
        File.WriteAllText(path,"OWN_NONSECRET_RESET_FILE");
        Refuse(()=>Call("AssertFileStateCurrent",Target(path,missingFile),7));
        var present=Call("ObserveFileState",path,true)!;
        Require(Depth(present)==0,"present file retains exact original file identity mode");
        Call("AssertFileStateCurrent",Target(path,present),7);checks++;
        Call("AssertFileStateCurrent",Target(path,present),0);checks++;
        var retained=Path.Combine(folder,"retained-nonsecret-settings.json");File.Move(path,retained);
        Refuse(()=>Call("AssertFileStateCurrent",Target(path,present),7));
        var plain=Path.Combine(root,"plain.txt");File.WriteAllText(plain,"OWN_NONSECRET_REGULAR_FILE");
        Refuse(()=>Call("ObserveFileState",Path.Combine(plain,"settings.json"),true));
        foreach(var index in Enumerable.Range(0,33).Where(i=>i!=7))
            foreach(var depth in new[]{1,2})Refuse(()=>Call("RequireMissingTarget",index,depth));
        foreach(var depth in new[]{0,1,2}){Call("RequireMissingTarget",7,depth);checks++;}
        foreach(var depth in new[]{-1,3})Refuse(()=>Call("RequireMissingTarget",7,depth));
        Require((bool)Call("IsMissing",new Win32Exception(2))! && (bool)Call("IsMissing",new Win32Exception(3))! &&
            !(bool)Call("IsMissing",new Win32Exception(5))! && !(bool)Call("IsMissing",new Win32Exception(32))!,"only exact file/path absence is classified missing");
        Console.WriteLine($"PASS reset-settings file state: {checks} checks; actual ordinary own missing-parent/missing-file/present transitions, anchor identity and creation/disappearance conflicts, regular-file parent refusal, only slot7/depth1-2 permitted. No real user config/content/ACL/host target/Broker/LPAC/Job/UAC/network; own nonsecret file retained at {retained}");
    }
}
