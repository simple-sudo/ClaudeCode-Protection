using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using ProtectionLifecycle;

internal static class GpuWin32kBoundary
{
    private const int SystemCallDisablePolicy=4;
    private const uint DisallowWin32k=1;
    private const BindingFlags HiddenStatic=BindingFlags.NonPublic|BindingFlags.Static;
    private static readonly Assembly Lifecycle=typeof(InstalledBroker).Assembly;
    private static bool FixedWorkload(string name)=>name is "wddm" or "cuda-identity" or "pnp" or "nvml" or "compute";

    internal static int Run(string timing,string workload,string rawPath)
    {
        if(timing is not ("ordinary" or "cold" or "warm" or "creation") || !FixedWorkload(workload))return 64;
        using var phases=timing=="creation"?new StreamWriter(new FileStream(rawPath+".phases",FileMode.CreateNew,FileAccess.Write,FileShare.Read)):null;
        var output=phases??Console.Out;
        using var raw=new FileStream(rawPath,FileMode.CreateNew,FileAccess.Write,FileShare.None);
        object? before=null;
        if(timing=="warm")
        {
            before=Read(workload,output);
            Emit(new{Phase="WARMED",Workload=workload,Result=Summary(workload,before)});
        }

        int? setError=null;
        if(timing is "cold" or "warm")
        {
            uint requested=DisallowWin32k;
            if(!SetProcessMitigationPolicy(SystemCallDisablePolicy,ref requested,sizeof(uint)))setError=Marshal.GetLastWin32Error();
        }
        var read=GetProcessMitigationPolicy(GetCurrentProcess(),SystemCallDisablePolicy,out var flags,sizeof(uint));
        int? readError=read?null:Marshal.GetLastWin32Error();
        var blocked=read && (flags&DisallowWin32k)!=0;
        Emit(new{Phase="POLICY",Timing=timing,Workload=workload,SetError=setError,ReadError=readError,Win32kDisabled=blocked});
        if(!read || blocked!=(timing!="ordinary") || setError.HasValue)
        {
            Save(before,null);
            return 4;
        }

        var after=Read(workload,output);
        Save(before,after);
        Emit(new{Phase="RESULT",Workload=workload,Win32kDisabled=blocked,Result=Summary(workload,after)});
        return 0;

        void Save(object? pre,object? post)
        {
            JsonSerializer.Serialize(raw,new{Timing=timing,Workload=workload,SetError=setError,ReadError=readError,Win32kDisabled=blocked,Before=pre,After=post});
            raw.Flush(true);
        }
        void Emit(object row){output.WriteLine(JsonSerializer.Serialize(row));output.Flush();}
    }

    private static object Read(string workload,TextWriter output)=>workload switch
    {
        "wddm"=>Call("WddmAdapterProbe","Read"),
        "cuda-identity"=>Call("GpuIdentityObservation","Read"),
        "pnp"=>Call("GpuDeviceIdentitySurvey","ReadPnp"),
        "nvml"=>Call("GpuDeviceIdentitySurvey","ReadNvml"),
        "compute"=>Compute(output),
        _=>throw new InvalidOperationException("Fixed GPU test workload required")
    };

    private static object Compute(TextWriter output)
    {
        var job=new string('a',32);
        var plan=Activator.CreateInstance(Lifecycle.GetType("ProtectionLifecycle.GpuProbePlan",true)!,
            BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Instance,null,[job,1],null)!;
        var progress=Activator.CreateInstance(Lifecycle.GetType("ProtectionLifecycle.GpuCallProgressWriter",true)!,
            BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Instance,null,[output,job,Environment.ProcessId],null)!;
        var report=Call("GpuQualification","ComputeWithSplitInit",plan,"ORDINARY_WIN32K_GPU_CONTROL",progress);
        return new{Qualified=(bool)Call("GpuQualification","Qualified",report),Report=report};
    }

    private static object Summary(string workload,object value)
    {
        var item=JsonSerializer.SerializeToElement(value,value.GetType());
        return workload switch
        {
            "wddm"=>new{Size=item.GetProperty("SizeStatus"),Read=item.GetProperty("ReadStatus"),Count=item.GetProperty("Count"),
                CloseFailures=item.GetProperty("Adapters").EnumerateArray().Count(a=>a.GetProperty("CloseStatus").GetInt32()!=0)},
            "cuda-identity"=>new{Init=item.GetProperty("Steps")[0].GetProperty("Result"),
                Uuid=item.GetProperty("UuidV2").ValueKind==JsonValueKind.String},
            "pnp"=>new{Size=item.GetProperty("SizeCode"),Read=item.GetProperty("ListCode"),Count=item.GetProperty("Devices").GetArrayLength()},
            "nvml"=>new{Init=item.GetProperty("InitCode"),LoadError=item.GetProperty("LoadError"),Shutdown=item.GetProperty("ShutdownCode"),
                Count=item.GetProperty("Devices").EnumerateArray().Count(d=>d.GetProperty("Uuid").ValueKind==JsonValueKind.String)},
            "compute"=>new{Qualified=item.GetProperty("Qualified"),Matched=item.GetProperty("Report").GetProperty("ComputeMatched"),
                Cleanup=item.GetProperty("Report").GetProperty("ResourceCleanupSucceeded")},
            _=>throw new InvalidOperationException("Fixed GPU test workload required")
        };
    }

    private static object Call(string type,string method,params object[] arguments)=>
        Lifecycle.GetType("ProtectionLifecycle."+type,true)!.GetMethod(method,HiddenStatic)!.Invoke(null,arguments)!;

    internal static int RunAtCreation(string workload,string rawPath)
    {
        if(!FixedWorkload(workload) || Environment.ProcessPath is not { } image || !Environment.Is64BitProcess)return 64;
        rawPath=Path.GetFullPath(rawPath);
        if(rawPath.IndexOfAny(['"','\r','\n'])>=0 || Path.GetExtension(rawPath)!=".json" || File.Exists(rawPath) || File.Exists(rawPath+".phases"))return 64;
        const uint extendedStartupInfo=0x00080000,createNoWindow=0x08000000,createSuspended=0x00000004;
        const ulong disableWin32kAtCreation=1UL<<28;
        nuint bytes=0;
        _=InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref bytes);
        if(bytes is 0 or >16384)return 3;
        var attributes=Marshal.AllocHGlobal(checked((int)bytes));
        var policy=Marshal.AllocHGlobal(sizeof(ulong));
        var initialized=false;
        try
        {
            initialized=InitializeProcThreadAttributeList(attributes,1,0,ref bytes);
            if(!initialized)return Error("InitializeAttribute");
            Marshal.WriteInt64(policy,checked((long)disableWin32kAtCreation));
            if(!UpdateProcThreadAttribute(attributes,0,0x20007,policy,sizeof(ulong),IntPtr.Zero,IntPtr.Zero))return Error("SetCreationPolicy");
            var startup=new StartupInfoEx{Info=new StartupInfo{Size=Marshal.SizeOf<StartupInfoEx>()},Attributes=attributes};
            var command=new StringBuilder($"\"{image}\" host-gpu-win32k creation {workload} \"{rawPath}\"");
            if(!CreateProcess(image,command,IntPtr.Zero,IntPtr.Zero,false,extendedStartupInfo|createNoWindow|createSuspended,
                IntPtr.Zero,null,ref startup,out var child))return Error("CreateProcess");
            try
            {
                var read=GetProcessMitigationPolicy(child.Process,SystemCallDisablePolicy,out var flags,sizeof(uint));
                int? readError=read?null:Marshal.GetLastWin32Error();
                var enabled=read && (flags&DisallowWin32k)!=0;
                Console.WriteLine(JsonSerializer.Serialize(new{Phase="PARENT_POLICY",Workload=workload,Win32kDisabled=enabled,ReadError=readError}));
                if(ResumeThread(child.Thread)!=1)return Error("ResumeCreatedTest");
                var wait=WaitForSingleObject(child.Process,20000);
                if(wait!=0 || !GetExitCodeProcess(child.Process,out var exit))return Error("ReadTerminal",wait);
                Console.WriteLine(JsonSerializer.Serialize(new{Phase="CHILD_TERMINAL",Workload=workload,ExitCode=exit}));
                if(File.Exists(rawPath+".phases"))Console.Write(File.ReadAllText(rawPath+".phases"));
                return enabled?0:3;
            }
            finally{CloseHandle(child.Thread);CloseHandle(child.Process);}
        }
        finally
        {
            if(initialized)DeleteProcThreadAttributeList(attributes);
            Marshal.FreeHGlobal(policy);Marshal.FreeHGlobal(attributes);
        }

        static int Error(string stage,uint? wait=null)
        {
            var code=Marshal.GetLastWin32Error();
            Console.WriteLine(JsonSerializer.Serialize(new{Phase=stage,Win32Error=code,Wait=wait}));
            return 3;
        }
    }

    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
    private struct StartupInfo
    {
        internal int Size;
        internal string? Reserved,Desktop,Title;
        internal uint X,Y,XSize,YSize,XCount,YCount,Fill,Flags;
        internal ushort Show,ReservedBytes;
        internal IntPtr ReservedPointer,Input,Output,Error;
    }
    [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx {internal StartupInfo Info;internal IntPtr Attributes;}
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInfo {internal IntPtr Process,Thread;internal uint Pid,Tid;}

    [DllImport("kernel32.dll",ExactSpelling=true)] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessMitigationPolicy(int policy,ref uint flags,nuint size);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessMitigationPolicy(IntPtr process,int policy,out uint flags,nuint size);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr attributes,int count,uint flags,ref nuint size);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(IntPtr attributes,uint flags,nuint attribute,IntPtr value,nuint size,IntPtr previous,IntPtr returned);
    [DllImport("kernel32.dll",ExactSpelling=true)] private static extern void DeleteProcThreadAttributeList(IntPtr attributes);
    [DllImport("kernel32.dll",EntryPoint="CreateProcessW",ExactSpelling=true,CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcess(string image,StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)]bool inherit,uint flags,IntPtr environment,string? directory,ref StartupInfoEx startup,out ProcessInfo child);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)] private static extern uint WaitForSingleObject(IntPtr process,uint timeout);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr process,out uint exit);
    [DllImport("kernel32.dll",ExactSpelling=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)] private static extern uint ResumeThread(IntPtr thread);
}
