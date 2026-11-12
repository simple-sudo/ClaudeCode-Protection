namespace ProtectionLifecycle;

using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

internal sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeJobHandle():base(true){}
    internal SafeJobHandle DuplicateAssignment()
    {
        // The creation attribute needs assignment. Query, terminate and
        // policy changes stay on the original Job owner's handle.
        var current=new IntPtr(-1);
        if(DuplicateHandle(current,this,current,out var assignment,0x0001,false,0))return assignment;
        var error=new Win32Exception(Marshal.GetLastWin32Error());
        assignment?.Dispose();error.Data["Stage"]="DuplicateJobAssignmentOnly";throw error;
    }
    protected override bool ReleaseHandle()=>CloseHandle(handle);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess,SafeJobHandle source,IntPtr targetProcess,out SafeJobHandle target,
        uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint options);
}
