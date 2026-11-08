using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Win32.SafeHandles;

internal static class OfflineConsoleNativeCases
{
    private const BindingFlags Instance=BindingFlags.Instance|BindingFlags.NonPublic|BindingFlags.Public;
    private const BindingFlags Static=BindingFlags.Static|BindingFlags.NonPublic;
    private const uint Success=0,StillRunning=258;

    internal static void Run(Assembly library)
    {
        var broker=library.GetType("ProtectionLifecycle.InstalledBroker",true)!;
        Refuse<UnauthorizedAccessException>(()=>Call(broker.GetMethod("QualifyOfflineConsole")!,null));
        var atomic=library.GetType("ProtectionLifecycle.AtomicChild",true)!;
        Refuse<InvalidDataException>(()=>Call(atomic.GetMethod("AssertOfflineConsoleWorkerIdentity",Static)!,null));
        VerifyFailureMetadata(library);
        VerifyWorkspaceEnvironment(library);
        VerifyProjectionEvidence(library);
        VerifyHostIdentityEvidence(library);
        var type=library.GetType("ProtectionLifecycle.OfflineConsoleStreams",true)!;
        var read=type.GetMethod("ReadBounded",Static)!;
        foreach(var length in new[]{0,4096})
        {
            using var bytes=new MemoryStream(new byte[length]);
            var result=Result((Task)Call(read,null,bytes)!);
            Require(result.Bytes.Length==length && !result.Overflow);
        }
        RunChild(library,type,false);
        RunChild(library,type,true);
        Console.WriteLine("PASS native ordinary three-handle inheritance, stdin EOF, distinct output, overflow, excluded handle and child-creation refusal. LPAC and WFP not executed.");
    }

    private static void VerifyFailureMetadata(Assembly library)
    {
        var owner=library.GetType("ProtectionLifecycle.OfflineConsoleQualification",true)!;
        var output=library.GetType("ProtectionLifecycle.OfflineConsoleOutput",true)!;
        var parse=owner.GetMethod("ParseChildFailure",Static)!;
        const string known="CPC_OFFLINE_CONSOLE_FAILURE|Workspace|ACCESS|-2147024891\n";
        object? Parse(string message,uint exit=125,bool overflow=false)=>
            Call(parse,null,exit,Activator.CreateInstance(output,Encoding.ASCII.GetBytes(message),overflow));
        var result=Parse(known)!;
        Require(result.GetType().GetProperty("Stage")!.GetValue(result) as string=="Workspace");
        Require((int)result.GetType().GetProperty("Code")!.GetValue(result)! == -2147024891);
        Require(Parse(known,0) is null && Parse(known,overflow:true) is null);
        Require(Parse(known.Replace("Workspace","4",StringComparison.Ordinal)) is null);
        Require(Parse(known.Replace("ACCESS","unreviewed",StringComparison.Ordinal)) is null);
        Require(Parse(known.Replace("-2147024891","+12",StringComparison.Ordinal)) is null);
        Require(Parse(known+"private extra") is null);
    }

    private static void VerifyWorkspaceEnvironment(Assembly library)
    {
        var owner=library.GetType("ProtectionLifecycle.OfflineConsoleQualification",true)!;
        var bind=owner.GetMethod("BindEnvironment",Static)!;
        var verify=owner.GetMethod("FindEnvironmentMismatch",Static)!;
        var session=new string('a',32);
        var parent=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var workspace=Path.Combine(parent,"ClaudeCodeProtection-Task-"+session);
        var package="ClaudeCodeProtection."+new string('b',32);
        var nativeBase=Path.Combine(workspace,"local");
        var localData=Path.Combine(nativeBase,"Packages",package,"AC");
        var temp=Path.Combine(localData,"Temp");
        var env=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        _=Call(bind,null,env,workspace,package,session);
        Require(env.Count==11 && env["ProgramFiles"]==parent && env["CPC_OFFLINE_CONSOLE_SESSION"]==session &&
            env["TEMP"]==temp && env["TMP"]==temp && env["LOCALAPPDATA"]==nativeBase && env["CPC_OFFLINE_CONSOLE_PACKAGE"]==package);
        string? Diagnose(string cwd)=>Call(verify,null,workspace,localData,temp,cwd,(Func<string,string?>)(name=>env.GetValueOrDefault(name)))?.ToString();
        Require(Diagnose(workspace)=="LocalAppData");
        env["LOCALAPPDATA"]=localData;
        Require(Diagnose(workspace.ToUpperInvariant()) is null);
        Require(Diagnose(parent)=="CurrentDirectory");
        foreach(var (name,expected) in new[]{("TEMP","Temp"),("TMP","Tmp"),("LOCALAPPDATA","LocalAppData"),("USERPROFILE","UserProfile"),
            ("HOME","Home"),("XDG_CONFIG_HOME","XdgConfigHome"),("CLAUDE_CONFIG_DIR","ClaudeConfigDir"),("APPDATA","AppData")})
        {
            var original=env[name];
            Require(env.Remove(name) && Diagnose(workspace)==expected);
            env.Add(name,original);
        }
        env["TEMP"]=Path.Combine(parent,"HostTemp");
        Require(Diagnose(workspace)=="Temp");
        env["TEMP"]=Path.Combine(localData,"Packages",package,"AC","Temp");
        Require(Diagnose(workspace)=="Temp");
        env["TEMP"]=temp;
        env["HTTP_PROXY"]="unused";
        Require(Diagnose(workspace)=="UnexpectedAuthority");
        Refuse<InvalidDataException>(()=>Call(bind,null,env,workspace,package,session));
        Refuse<InvalidDataException>(()=>Call(bind,null,new Dictionary<string,string>(),parent,package,session));
        Refuse<InvalidDataException>(()=>Call(bind,null,new Dictionary<string,string>(),workspace,"..\\"+package,session));
        Refuse<InvalidDataException>(()=>Call(bind,null,new Dictionary<string,string>(),workspace,package+"\\..",session));
    }

    private static void VerifyProjectionEvidence(Assembly library)
    {
        var projection=library.GetType("ProtectionLifecycle.OfflineConsoleProjection",true)!;
        var parse=projection.GetMethod("Parse",Static)!;
        var classify=projection.GetMethod("Classify",Static)!;
        var session=new string('b',32);
        byte[] Frame(string? temp)=>System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,SessionId=session,Pid=42,Temp=temp,Tmp=(string?)null,LocalAppData=""
        });
        var data=Frame(@"C:\Private\Path");
        _=Call(parse,null,data,session,42u);
        Refuse<InvalidDataException>(()=>Call(parse,null,data,session,43u));
        Refuse<InvalidDataException>(()=>Call(parse,null,data,new string('c',32),42u));
        Refuse<InvalidDataException>(()=>Call(parse,null,Frame(new string('x',241)),session,42u));
        Refuse<InvalidDataException>(()=>Call(parse,null,Frame("a\0b"),session,42u));
        var duplicate=Encoding.UTF8.GetBytes("{\"Temp\":null,"+Encoding.UTF8.GetString(data)[1..]);
        Refuse<InvalidDataException>(()=>Call(parse,null,duplicate,session,42u));
        foreach(var (actual,expected) in new (string?,string)[] {
            (null,"ABSENT"),("","EMPTY"),(@"C:\Profile\AC\Temp","OWNED_EXACT"),(@"C:\Profile\AC\Temp\","OWNED_TRAILING_SEPARATOR"),
            (@"C:\Task","TASK_WORKSPACE"),(@"C:\Host\Temp\","HOST_DEFAULT"),(@"C:\Unknown","OTHER")
        })
            Require((string?)Call(classify,null,actual,@"C:\Profile\AC\Temp",@"C:\Task",@"C:\Host\Temp")==expected);
    }

    private static void VerifyHostIdentityEvidence(Assembly library)
    {
        var type=library.GetType("ProtectionLifecycle.OfflineConsoleHostIdentity",true)!;
        var reading=library.GetType("ProtectionLifecycle.OfflineConsoleIdentityRead",true)!;
        var parse=type.GetMethod("Parse",Static)!;
        var compare=type.GetMethod("Compare",Static)!;
        var session=new string('c',32);
        var reference=Call(type.GetMethod("Capture",Static)!,null,session)!;
        var captured=JsonSerializer.SerializeToUtf8Bytes(reference,type);
        _=Call(parse,null,captured,session,(uint)Environment.ProcessId);
        using(var document=JsonDocument.Parse(captured))
        {
            var root=document.RootElement;
            foreach(var field in new[]{"TokenUser","LogonName","ProfileDirectory","ComputerName","MachineGuid"})
                Require(root.GetProperty(field).GetProperty("Error").GetInt32()==0 &&
                    root.GetProperty(field).GetProperty("Value").GetString() is {Length:>0});
            using var identity=System.Security.Principal.WindowsIdentity.GetCurrent();
            Require(root.GetProperty("TokenUser").GetProperty("Value").GetString()==identity.User?.Value);
        }
        Refuse<InvalidDataException>(()=>Call(parse,null,captured,session,0u));
        Refuse<InvalidDataException>(()=>Call(parse,null,captured,new string('d',32),(uint)Environment.ProcessId));
        Refuse<InvalidDataException>(()=>Call(parse,null,new byte[32769],session,(uint)Environment.ProcessId));
        void Deny(Action<JsonObject> change)
        {
            var sample=JsonNode.Parse(captured)!.AsObject();
            change(sample);
            Refuse<InvalidDataException>(()=>Call(parse,null,JsonSerializer.SerializeToUtf8Bytes(sample),session,(uint)Environment.ProcessId));
        }
        Deny(sample=>sample["MachineGuid"]!["Error"]=5);
        Deny(sample=>sample["ProfileDirectory"]!["Value"]=new string('x',1024));
        Deny(sample=>sample["ComputerName"]!["Value"]="a\0b");
        Deny(sample=>sample["LogonName"]!["Extra"]=true);
        Deny(sample=>sample.Remove("TokenUser"));
        object Reading(int error,string? value)=>Activator.CreateInstance(reading,error,value)!;
        var host=Reading(0,"Owner");
        foreach(var (actor,expected) in new[]{
            (Reading(0,"owner"),"MATCHES_HOST"),(Reading(0,"other"),"DIFFERS_FROM_HOST"),
            (Reading(5,null),"DENIED"),(Reading(2,null),"UNAVAILABLE")})
            Require((string?)Call(compare,null,actor,host)==expected);
        Require((string?)Call(compare,null,host,Reading(5,null))=="REFERENCE_UNAVAILABLE");
        Console.WriteLine("PASS five actual ordinary identity reads and bounded identity evidence controls. Restricted identity not executed.");
    }

    private static void RunChild(Assembly library,Type type,bool flood)
    {
        using var transport=(IDisposable)Activator.CreateInstance(type,nonPublic:true)!;
        using var binding=(IDisposable)Call(type.GetMethod("PrepareCreationAttributes",Instance)!,transport)!;
        var (input,output,error)=((IntPtr,IntPtr,IntPtr))binding.GetType().GetProperty("Channels",Instance)!.GetValue(binding)!;
        using var excluded=new EventWaitHandle(false,EventResetMode.ManualReset);
        if(!SetHandleInformation(excluded.SafeWaitHandle,1,1))throw Error("MakeFixtureEventInheritable");
        var image=Environment.ProcessPath!;
        var mode=flood?"flood":"normal";
        var value=excluded.SafeWaitHandle.DangerousGetHandle().ToInt64().ToString(CultureInfo.InvariantCulture);
        var command=new StringBuilder($"\"{image}\" offline-console-streams-worker {mode} {value}");
        nuint size=0;
        _=InitializeProcThreadAttributeList(IntPtr.Zero,2,0,ref size);
        if(size is 0 or >65536)throw Error("SizeFixtureAttributeList");
        var attributes=Marshal.AllocHGlobal(checked((int)size));
        ProcessInfo native;
        bool initialized=false;
        try
        {
            if(!InitializeProcThreadAttributeList(attributes,2,0,ref size))throw Error("CreateFixtureAttributeList");
            initialized=true;
            _=Call(binding.GetType().GetMethod("Bind",Instance)!,binding,attributes);
            var startup=new StartupEx{Basic=new(){Size=Marshal.SizeOf<StartupEx>(),Flags=0x100,Input=input,Output=output,Error=error},
                Attributes=attributes};
            var detached=(uint)type.GetField("DetachedCreationFlag",Static)!.GetRawConstantValue()!;
            if(!CreateProcess(image,command,IntPtr.Zero,IntPtr.Zero,true,0x00080004u|detached,IntPtr.Zero,null,ref startup,out native))
                throw Error("CreateSuspendedConsoleFixture");
        }
        finally
        {
            if(initialized)DeleteProcThreadAttributeList(attributes);
            Marshal.FreeHGlobal(attributes);
        }
        using var process=new SafeProcessHandle(native.Process,true);
        using var thread=new SafeWaitHandle(native.Thread,true);
        try
        {
            var atomic=library.GetType("ProtectionLifecycle.AtomicChild",true)!;
            _=Call(atomic.GetMethod("AssertNoChildCreation",Static)!,null,process);
            var captures=(ITuple)Call(type.GetMethod("ReadAfterCreate",Instance)!,transport)!;
            Refuse<InvalidDataException>(()=>Call(type.GetMethod("ReadAfterCreate",Instance)!,transport));
            Require(ResumeThread(thread)==1);
            var wait=WaitForSingleObject(process,6000);
            if(wait!=Success || !GetExitCodeProcess(process,out var exit))
                throw new InvalidDataException("Ordinary console fixture exit unavailable: "+wait);
            var stdout=Result((Task)captures[0]!);
            var stderr=Result((Task)captures[1]!);
            if(exit!=0)throw new InvalidDataException($"Ordinary console fixture exit {exit}, stderr bytes {stderr.Bytes.Length}");
            Require(!stderr.Overflow && stderr.Bytes.AsSpan().SequenceEqual("fixture-stderr\n"u8));
            Require(flood?stdout.Overflow && stdout.Bytes.Length==4096 && stdout.Bytes.All(value=>value==65):
                !stdout.Overflow && stdout.Bytes.AsSpan().SequenceEqual("fixture-stdout\n"u8));
            Require(!excluded.WaitOne(0));
        }
        finally
        {
            if(WaitForSingleObject(process,0)==StillRunning)
            {
                if(!TerminateProcess(process,125) || WaitForSingleObject(process,3000)!=Success)
                    throw Error("StopExactOrdinaryFixture");
            }
        }
    }

    internal static int Worker(string mode,string eventValue)
    {
        if(mode is not ("normal" or "flood") || !long.TryParse(eventValue,NumberStyles.None,CultureInfo.InvariantCulture,out var raw) ||
            raw<=0 || !Console.IsInputRedirected || !Console.IsOutputRedirected || !Console.IsErrorRedirected)return 120;
        using(var input=Console.OpenStandardInput())
            if(input.ReadByte()!=-1)return 121;
        if(SetEvent((IntPtr)raw) || Marshal.GetLastWin32Error()!=6)return 122;
        var child=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true};
        child.ArgumentList.Add("ordinary-console-fixture-inert");
        try{using var unexpected=Process.Start(child);return 123;}
        catch(Win32Exception error)when(error.NativeErrorCode==367){}
        using(var stdout=Console.OpenStandardOutput())
        {
            if(mode=="normal")stdout.Write("fixture-stdout\n"u8);
            else stdout.Write(Enumerable.Repeat((byte)65,4097).ToArray());
        }
        using(var stderr=Console.OpenStandardError())stderr.Write("fixture-stderr\n"u8);
        return 0;
    }

    private static (byte[] Bytes,bool Overflow) Result(Task task)
    {
        task.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
        var value=task.GetType().GetProperty("Result")!.GetValue(task)!;
        return ((byte[])value.GetType().GetProperty("Bytes")!.GetValue(value)!,
            (bool)value.GetType().GetProperty("Overflow")!.GetValue(value)!);
    }
    private static void Require(bool value){if(!value)throw new InvalidDataException("Offline console native fixture differs");}
    private static void Refuse<T>(Action action) where T:Exception
    {try{action();}catch(T){return;}throw new InvalidDataException("Offline console refusal missing");}
    private static object? Call(MethodInfo method,object? target,params object?[] args)
    {
        try{return method.Invoke(target,args);}
        catch(TargetInvocationException ex)when(ex.InnerException is not null){ExceptionDispatchInfo.Capture(ex.InnerException).Throw();throw;}
    }
    private static Win32Exception Error(string stage)=>new(Marshal.GetLastWin32Error(),stage);

    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
    private struct Startup
    {
        internal int Size;
        internal string? Reserved,Desktop,Title;
        internal int X,Y,XSize,YSize,XCount,YCount,Fill;
        internal uint Flags;
        internal ushort Show,ReservedBytes;
        internal IntPtr ReservedPointer,Input,Output,Error;
    }
    [StructLayout(LayoutKind.Sequential)] private struct StartupEx {internal Startup Basic;internal IntPtr Attributes;}
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInfo {internal IntPtr Process,Thread;internal uint Pid,Tid;}
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref nuint size);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll",EntryPoint="CreateProcessW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern bool CreateProcess(string image,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,
        uint flags,IntPtr environment,string? cwd,ref StartupEx startup,out ProcessInfo info);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool SetHandleInformation(SafeWaitHandle handle,uint mask,uint flags);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool SetEvent(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint ResumeThread(SafeWaitHandle thread);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetExitCodeProcess(SafeProcessHandle process,out uint code);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool TerminateProcess(SafeProcessHandle process,uint code);
}
