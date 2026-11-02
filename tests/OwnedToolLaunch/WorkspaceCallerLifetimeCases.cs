using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.ExceptionServices;
using Microsoft.Win32.SafeHandles;

internal static class WorkspaceCallerLifetimeCases
{
    internal static void Run(Assembly library,Func<uint,uint,SafeProcessHandle> openProcess)
    {
        var type=library.GetType("ProtectionLifecycle.WorkspaceCallerLifetime",true)!;
        const BindingFlags instance=BindingFlags.NonPublic|BindingFlags.Instance;
        const BindingFlags statics=BindingFlags.NonPublic|BindingFlags.Static;
        var checks=0;
        void Require(bool condition,string reason){if(!condition)throw new InvalidDataException(reason);checks++;}
        object? Invoke(object? target,string name,params object?[] args)
        {
            try{return type.GetMethod(name,target is null?statics:instance)!.Invoke(target,args);}
            catch(TargetInvocationException error)when(error.InnerException is not null){ExceptionDispatchInfo.Capture(error.InnerException).Throw();throw;}
        }
        void Refuse(Action action,string reason)
        {try{action();}catch(InvalidDataException error)when(error.Message==reason){checks++;return;}throw new InvalidDataException("Expected "+reason);}
        object New()=>Activator.CreateInstance(type,true)!;
        var access=(uint)type.GetField("CallerProcessAccess",statics)!.GetRawConstantValue()!;
        Require(access==0x101000,"caller handle requests query and synchronize only");
        Invoke(null,"RequireAliveObservation",258u,0);checks++;
        Refuse(()=>Invoke(null,"RequireAliveObservation",0u,0),"WorkspaceCallerExited");
        Refuse(()=>Invoke(null,"RequireAliveObservation",1u,0),"WorkspaceCallerWaitUnconfirmed");
        Refuse(()=>Invoke(null,"RequireAliveObservation",uint.MaxValue,0),"WorkspaceCallerWaitUnconfirmed");
        Refuse(()=>Invoke(null,"RequireAliveObservation",258u,5),"WorkspaceCallerWaitUnconfirmed");
        using(var empty=(IDisposable)New())Refuse(()=>Invoke(empty,"AssertAlive"),"WorkspaceCallerUnavailable");
        var session=library.GetType("ProtectionLifecycle.ProtectedSession",true)!;
        foreach(var name in new[]{"DevelopBundledProjectForCaller","BuildCallerProject","ProcessWorkspaceDataForCaller"})
        {
            var method=session.GetMethod(name,statics)!;var args=new object?[method.GetParameters().Length];
            try{method.Invoke(null,args);}catch(TargetInvocationException e)when(e.InnerException is ArgumentNullException argument && argument.ParamName=="assertCaller"){checks++;continue;}
            throw new InvalidDataException("Workspace pipe path permitted a null caller guard");
        }
        var host=Environment.ProcessPath??throw new InvalidDataException("Test host missing");
        if(!string.Equals(host,@"C:\Program Files\dotnet\dotnet.exe",StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Fixed original test host required");
        var start=new ProcessStartInfo(host){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=AppContext.BaseDirectory};
        start.Environment.Clear();foreach(var name in new[]{"SystemRoot","windir","SystemDrive","TEMP","TMP"})if(Environment.GetEnvironmentVariable(name) is string value)start.Environment[name]=value;
        foreach(var arg in new[]{"exec","--fx-version","8.0.28",Assembly.GetExecutingAssembly().Location,"workspace-caller-lifetime-child"})start.ArgumentList.Add(arg);
        using var child=Process.Start(start)??throw new IOException("Own ordinary fixture not created");
        try
        {
            Require(child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult()=="READY","own child ready on fixed pipe");
            using(var noSync=(IDisposable)New())
            using(var query=openProcess(0x1000,(uint)child.Id))
            {
                var refused=false;try{Invoke(noSync,"Bind",query);}catch(Win32Exception error)when(error.NativeErrorCode==5){refused=true;}
                Require(refused,"query-only handle cannot be silently treated as a live wait object");
            }
            using var lifetime=(IDisposable)New();using var held=openProcess(access,(uint)child.Id);
            Invoke(lifetime,"Bind",held);Invoke(lifetime,"AssertAlive");checks++;
            Refuse(()=>Invoke(lifetime,"Bind",held),"WorkspaceCallerCannotRebind");
            child.StandardInput.WriteLine("finish");child.StandardInput.Close();
            Require(child.WaitForExit(5000) && child.ExitCode==259,"own child exits with the numeric STILL_ACTIVE value");
            Refuse(()=>Invoke(lifetime,"AssertAlive"),"WorkspaceCallerExited");
            lifetime.Dispose();Refuse(()=>Invoke(lifetime,"AssertAlive"),"WorkspaceCallerUnavailable");
            Require(child.StandardError.ReadToEnd().Length==0,"ordinary child emitted no errors");
        }
        finally
        {
            if(!child.HasExited){child.StandardInput.Close();if(!child.WaitForExit(5000))throw new IOException("Own ordinary child not terminal; retain exact process for observation");}
        }
        Console.WriteLine($"PASS workspace caller lifetime: {checks} checks; query+synchronize live object, query-only denial, actual own child exit259, unknown waits/null guards/rebind/dispose refused. No Broker/LPAC/Job/UAC/host target/control handle/network; only this own child asked to exit via stdin.");
    }
}
