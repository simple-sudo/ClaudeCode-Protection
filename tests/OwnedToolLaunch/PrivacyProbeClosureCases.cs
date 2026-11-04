using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

internal static class PrivacyProbeClosureCases
{
    internal static void Run(Assembly library,Func<uint,uint,SafeProcessHandle> openProcess)
    {
        var probe=library.GetType("ProtectionLifecycle.HostPrivacyProbe",true)!;
        var seal=library.GetType("ProtectionLifecycle.WindowsPathSeal",true)!;
        const BindingFlags flags=BindingFlags.Static|BindingFlags.NonPublic;
        var checks=new List<string>();
        void Require(bool condition,string reason){if(!condition)throw new InvalidDataException(reason);checks.Add(reason);}
        object? Call(Type type,string name,params object?[] args)
        {
            try{return type.GetMethod(name,flags)!.Invoke(null,args);}
            catch(TargetInvocationException error)when(error.InnerException is not null){ExceptionDispatchInfo.Capture(error.InnerException).Throw();throw;}
        }
        void Refuse(Action action,string reason)
        {try{action();}catch(Exception e)when(e is InvalidDataException or Win32Exception or ObjectDisposedException){checks.Add(reason);return;}throw new InvalidDataException("Accepted "+reason);}
        Refuse(()=>Call(probe,"RequireExitedProbe",new object?[]{null}),"null process cannot prove exit");
        using(var invalid=new SafeProcessHandle(IntPtr.Zero,false))Refuse(()=>Call(probe,"RequireExitedProbe",invalid),"invalid process cannot prove exit");
        foreach(var zero in new[]{true,false})
        {
            var host=Environment.ProcessPath??throw new InvalidDataException("Test host missing");
            if(!string.Equals(host,@"C:\Program Files\dotnet\dotnet.exe",StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Original test host required");
            var start=new ProcessStartInfo(host){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=AppContext.BaseDirectory};
            start.Environment.Clear();foreach(var name in new[]{"SystemRoot","windir","SystemDrive","TEMP","TMP"})if(Environment.GetEnvironmentVariable(name) is string value)start.Environment[name]=value;
            foreach(var arg in new[]{"exec","--fx-version","8.0.28",Assembly.GetExecutingAssembly().Location,zero?"privacy-probe-exit-child":"workspace-caller-lifetime-child"})start.ArgumentList.Add(arg);
            using var child=Process.Start(start)??throw new IOException("Own fixed ordinary child not created");
            try
            {
                Require(child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult()=="READY","fixed own child ready: "+zero);
                using var held=openProcess(0x101000,(uint)child.Id);
                Require(!held.IsInvalid,"own query/wait handle obtained: "+zero);
                Refuse(()=>Call(probe,"RequireExitedProbe",held),"live child cannot authorize compiler: "+zero);
                using(var noWait=openProcess(0x1000,(uint)child.Id))
                {Require(!noWait.IsInvalid,"own query-only handle obtained: "+zero);Refuse(()=>Call(probe,"RequireExitedProbe",noWait),"query-only unknown wait cannot authorize compiler: "+zero);}
                child.StandardInput.Close();Require(child.WaitForExit(5000),"own child terminal: "+zero);
                Require(child.ExitCode==(zero?0:259),"actual own exit code: "+zero);
                if(zero){Call(probe,"RequireExitedProbe",held);checks.Add("signaled held exit0 accepted");}
                else Refuse(()=>Call(probe,"RequireExitedProbe",held),"signaled exit259 is not exit0");
                held.Dispose();Refuse(()=>Call(probe,"RequireExitedProbe",held),"closed process cannot prove exit: "+zero);
                Require(child.StandardError.ReadToEnd().Length==0,"own child error pipe empty: "+zero);
            }
            finally
            {
                if(!child.HasExited){child.StandardInput.Close();if(!child.WaitForExit(5000))throw new IOException("Own child not terminal; retain its exact process for observation");}
            }
        }
        var root=Path.Combine(AppContext.BaseDirectory,"own-probe-closure-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        var payload="OWN_NONSECRET_TRANSIENT_PLAN_V1"u8.ToArray();var hash=Convert.ToHexString(SHA256.HashData(payload));
        File.WriteAllBytes(Path.Combine(root,"retained-payload.bin"),payload);
        foreach(var delayed in new[]{false,true})
        {
            var folder=Path.Combine(root,delayed?"pending-reader":"closed-reader");Directory.CreateDirectory(folder);
            var path=Path.Combine(folder,"host-privacy-plan.json");
            using var file=new FileStream((SafeFileHandle)Call(seal,"CreateWithdrawableProbeFile",path)!,FileAccess.ReadWrite);
            file.Write(payload);file.Flush(true);
            using var reader=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);
            Refuse(()=>Call(probe,"AssertPlanAbsent",folder),"present own plan not absence: "+delayed);
            if(!delayed)reader.Dispose();
            if(delayed)Refuse(()=>Call(probe,"WithdrawPlanFile",file,folder),"delete pending while reader holds file is not exact absence");
            else{Call(probe,"WithdrawPlanFile",file,folder);checks.Add("original held plan withdrawn and exact absence accepted");}
            reader.Dispose();Call(probe,"AssertPlanAbsent",folder);checks.Add("closed original handles yield exact absence: "+delayed);
            Require(!File.Exists(path),"only operation-owned transient plan absent: "+delayed);
            Refuse(()=>Call(probe,"WithdrawPlanFile",file,folder),"disposed plan handle cannot withdraw twice: "+delayed);
        }
        Refuse(()=>Call(probe,"AssertPlanAbsent",Path.Combine(root,"missing-parent")),"missing parent is not exact plan absence");
        File.WriteAllBytes(Path.Combine(root,"checks.json"),JsonSerializer.SerializeToUtf8Bytes(new{Checks=checks,TransientPayloadSHA256=hash,OnlyOperationOwnedTransientPlanRemoved=true,FixtureRetained=true}));
        Console.WriteLine(JsonSerializer.Serialize(new{Status="OWN_ORDINARY_PROBE_CLOSURE_COMPONENTS_PASSED",Checks=checks.Count,Fixture=root,TransientPayloadSHA256=hash,
            OwnChildrenExitCodes=new[]{0,259},ProbeOrCompilerLpacQualified=false,NativeJobQualified=false,HostTargetsRead=false,Installed=false,Elevated=false,NetworkUsed=false,FixtureRetained=true}));
    }
}
