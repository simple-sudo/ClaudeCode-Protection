using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Native ABI declarations used by the AtomicChild partial implementation.
// These declarations do not own policy or resource lifetimes.
internal sealed partial class AtomicChild
{
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] private struct StartupInfo {internal int Size;internal string? Reserved,Desktop,Title;internal int X,Y,XSize,YSize,XCount,YCount,Fill;internal uint Flags;internal ushort Show,ReservedBytes;internal IntPtr ReservedPointer,Input,Output,Error;}
    [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx {internal StartupInfo Basic;internal IntPtr Attributes;}
    [StructLayout(LayoutKind.Sequential)] private struct SecurityCapabilities {internal IntPtr Sid,Capabilities;internal uint Count,Reserved;}
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInfo {internal IntPtr Process,Thread;internal uint ProcessId,ThreadId;}
    [DllImport("kernel32.dll",ExactSpelling=true)] private static extern uint GetThreadId(SafeWaitHandle thread);
    [DllImport("kernel32.dll",ExactSpelling=true)] private static extern uint GetProcessIdOfThread(SafeWaitHandle thread);
    [DllImport("kernel32.dll",EntryPoint="WaitForSingleObject",ExactSpelling=true)] private static extern uint WaitForInitialThread(SafeWaitHandle thread,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref nuint size);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,nuint size,IntPtr previous,IntPtr returned);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll",EntryPoint="CreateProcessW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateProcess(string image,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,[MarshalAs(UnmanagedType.Bool)] bool inherit,uint flags,IntPtr environment,string? cwd,ref StartupInfoEx startup,out ProcessInfo info);
    [DllImport("kernel32.dll",EntryPoint="CreateProcessW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateSealedProcess(string image,StringBuilder command,ref KernelJobSeal.SecurityAttributes processSecurity,ref KernelJobSeal.SecurityAttributes threadSecurity,[MarshalAs(UnmanagedType.Bool)] bool inherit,uint flags,IntPtr environment,string? cwd,ref StartupInfoEx startup,out ProcessInfo info);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint ResumeThread(SafeWaitHandle thread);
    [DllImport("kernel32.dll",EntryPoint="DuplicateHandle",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool DuplicateToolHandle(IntPtr sourceProcess,SafeHandle source,SafeProcessHandle targetProcess,out IntPtr target,uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint options);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint GetProcessId(SafeProcessHandle process);
    [DllImport("kernel32.dll",EntryPoint="CreatePipe",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateToolPipe(out SafeFileHandle read,out SafeFileHandle write,ref KernelJobSeal.SecurityAttributes attributes,uint size);
    [DllImport("kernel32.dll",EntryPoint="SetHandleInformation",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetToolHandleInformation(SafeFileHandle handle,uint mask,uint flags);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool IsProcessInJob(SafeProcessHandle process,IntPtr job,[MarshalAs(UnmanagedType.Bool)]out bool present);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetProcessMitigationPolicy(SafeProcessHandle process,int policy,out uint flags,nuint size);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)] bool inherit,uint pid);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetExitCodeProcess(SafeProcessHandle process,out uint code);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetProcessTimes(SafeProcessHandle process,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll",EntryPoint="QueryFullProcessImageNameW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder path,ref uint size);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool OpenProcessToken(SafeProcessHandle process,uint access,out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetTokenInformation(SafeAccessTokenHandle token,int type,IntPtr data,int size,out int returned);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetTokenInformation(SafeAccessTokenHandle token,int type,IntPtr data,uint size);
    [StructLayout(LayoutKind.Sequential)] private struct GenericMapping {internal uint Read,Write,Execute,All;}
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool DuplicateTokenEx(SafeAccessTokenHandle existing,uint access,IntPtr security,int level,int type,out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool AccessCheck(byte[] descriptor,SafeAccessTokenHandle token,uint desired,ref GenericMapping mapping,[Out]byte[] privileges,ref uint size,out uint granted,[MarshalAs(UnmanagedType.Bool)]out bool allowed);
}
