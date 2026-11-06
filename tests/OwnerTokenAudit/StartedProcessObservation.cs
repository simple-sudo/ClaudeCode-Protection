using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace OwnerTokenAudit;

// Observation only, using the handle returned to the original launcher. No
// OpenProcess/PID attach, process enumeration, token operation or termination.
// Avoid Process.ExitCode/HasExited: .NET8 ProcessManager's static constructor
// attempts to enable SeDebugPrivilege even for an already-held child handle.
internal static class StartedProcessObservation
{
    private static void Require(SafeProcessHandle handle)
    {if(handle.IsClosed || handle.IsInvalid)throw new ArgumentException("OriginalStartedProcessHandleRequired");}
    internal static uint Id(SafeProcessHandle handle)
    {Require(handle);var id=GetProcessId(handle);return id!=0?id:throw Error();}
    internal static long CreatedFileTime(SafeProcessHandle handle)
    {
        Require(handle);if(!GetProcessTimes(handle,out var created,out _,out _,out _))throw Error();
        return created>0?created:throw new InvalidDataException("StartedProcessCreationTimeMissing");
    }
    internal static bool Terminal(SafeProcessHandle handle,uint milliseconds=0)
    {
        Require(handle);if(milliseconds>1000)throw new ArgumentOutOfRangeException(nameof(milliseconds));
        var status=WaitForSingleObject(handle,milliseconds);
        return status switch{0=>true,258=>false,uint.MaxValue=>throw Error(),_=>throw new InvalidDataException("StartedProcessWaitUnexpected")};
    }
    internal static uint ExitCode(SafeProcessHandle handle)
    {
        // A real exit259 is valid AFTER the process object is signaled. Never
        // infer termination from an exit-code value alone, or reopen by PID.
        if(!Terminal(handle))throw new InvalidOperationException("StartedProcessNotTerminal");
        if(!GetExitCodeProcess(handle,out var code))throw Error();return code;
    }
    private static Win32Exception Error()=>new(Marshal.GetLastWin32Error(),"Observe original started process handle");
    [DllImport("kernel32.dll",SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetProcessId(SafeProcessHandle process);
    [DllImport("kernel32.dll",SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)]private static extern bool GetProcessTimes(SafeProcessHandle process,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll",SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)]private static extern bool GetExitCodeProcess(SafeProcessHandle process,out uint code);
}
