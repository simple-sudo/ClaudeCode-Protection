using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Separate the System32 loader, export resolver and first driver call. The
// diagnostic caller supplies only an observer; neither path nor export is input.
internal sealed class GpuInitLoader : IDisposable
{
    [JsonConverter(typeof(JsonStringEnumConverter<Phase>))]
    internal enum Phase { Load,Resolve,Invoke }
    internal sealed record Checkpoint(Phase Phase,bool Returned,int? Code,bool? InDriverImage=null);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int Init(uint flags);
    private readonly DriverModule module;
    private readonly Init init;
    private bool invoked;

    private GpuInitLoader(DriverModule module,Init init){this.module=module;this.init=init;}

    internal static GpuInitLoader Open(Action<Checkpoint> observe)
    {
        observe(new(Phase.Load,false,null));
        var module=LoadLibraryEx("nvcuda.dll",IntPtr.Zero,0x800); // LOAD_LIBRARY_SEARCH_SYSTEM32.
        try
        {
            if(module.IsInvalid)throw Failed(Phase.Load,observe);
            observe(new(Phase.Load,true,0));
            observe(new(Phase.Resolve,false,null));
            var address=GetProcAddress(module,"cuInit");
            if(address==IntPtr.Zero)throw Failed(Phase.Resolve,observe);
            if(!GetModuleHandleEx(6,address,out var containing))throw Failed(Phase.Resolve,observe); // FROM_ADDRESS | UNCHANGED_REFCOUNT.
            var owned=containing==module.DangerousGetHandle();
            if(!owned)
            {
                observe(new(Phase.Resolve,true,0,false));
                throw new InvalidDataException("CudaInitExportOutsideRequestedImage");
            }
            var init=Marshal.GetDelegateForFunctionPointer<Init>(address);
            observe(new(Phase.Resolve,true,0,true));
            return new(module,init);
        }
        catch{module.Dispose();throw;}
    }

    internal int Invoke(Action<Checkpoint> observe)
    {
        if(invoked || module.IsClosed)throw new InvalidOperationException("CudaInitCallAlreadyUsed");
        invoked=true;
        bool held=false;
        try
        {
            module.DangerousAddRef(ref held);
            observe(new(Phase.Invoke,false,null));
            int code=init(0);
            observe(new(Phase.Invoke,true,code));
            return code;
        }
        finally{if(held)module.DangerousRelease();}
    }

    private static Win32Exception Failed(Phase phase,Action<Checkpoint> observe)
    {
        var code=Marshal.GetLastWin32Error();
        observe(new(phase,true,code));
        return new Win32Exception(code);
    }

    public void Dispose()=>module.Dispose();

    private sealed class DriverModule : SafeHandleZeroOrMinusOneIsInvalid
    {
        private DriverModule():base(true){}
        protected override bool ReleaseHandle()=>FreeLibrary(handle);
    }

    [DllImport("kernel32.dll",EntryPoint="LoadLibraryExW",ExactSpelling=true,CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern DriverModule LoadLibraryEx(string leaf,IntPtr file,uint flags);
    [DllImport("kernel32.dll",ExactSpelling=true,CharSet=CharSet.Ansi,SetLastError=true)]
    private static extern IntPtr GetProcAddress(DriverModule module,string name);
    [DllImport("kernel32.dll",EntryPoint="GetModuleHandleExW",ExactSpelling=true,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetModuleHandleEx(uint flags,IntPtr address,out IntPtr module);
    [DllImport("kernel32.dll",ExactSpelling=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeLibrary(IntPtr module);
}
