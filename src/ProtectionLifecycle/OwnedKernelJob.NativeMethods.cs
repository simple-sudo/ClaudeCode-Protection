using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed partial class OwnedKernelJob
{
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits {public long ProcessTime,JobTime;public uint LimitFlags;public UIntPtr MinWorkingSet,MaxWorkingSet;public uint ActiveProcessLimit;public UIntPtr Affinity;public uint PriorityClass,SchedulingClass;}
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters {public ulong ReadOps,WriteOps,OtherOps,ReadBytes,WriteBytes,OtherBytes;}
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits {public BasicLimits Basic;public IoCounters Io;public UIntPtr ProcessMemory,JobMemory,PeakProcessMemory,PeakJobMemory;}
    [StructLayout(LayoutKind.Sequential)] private struct BasicAccounting {public long User,Kernel,PeriodUser,PeriodKernel;public uint PageFaults,TotalProcesses,ActiveProcesses,TerminatedProcesses;}
    [StructLayout(LayoutKind.Sequential)] private struct NativeUnicodeString {internal ushort Length,MaximumLength;internal IntPtr Buffer;}
    [StructLayout(LayoutKind.Sequential)] private struct NativeObjectAttributes {internal int Length;internal IntPtr Root,Name;internal uint Attributes;internal IntPtr SecurityDescriptor,SecurityQualityOfService;}
    [DllImport("ntdll.dll",ExactSpelling=true)] private static extern int NtCreateJobObject(out SafeJobHandle handle,int access,ref NativeObjectAttributes attributes);
    [DllImport("ntdll.dll",ExactSpelling=true)] private static extern int NtQueryObject(SafeJobHandle handle,int info,[Out] uint[] buffer,uint size,out uint returned);
    [DllImport("ntdll.dll",ExactSpelling=true)] private static extern uint RtlNtStatusToDosError(int status);
    [DllImport("kernel32.dll",EntryPoint="CreateJobObjectW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeJobHandle CreateJobObject(ref KernelJobSeal.SecurityAttributes attributes,string name);
    [DllImport("kernel32.dll",EntryPoint="OpenJobObjectW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeJobHandle OpenJobObject(uint access,[MarshalAs(UnmanagedType.Bool)] bool inherit,string name);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetInformationJobObject(SafeJobHandle handle,int info,ref ExtendedLimits limits,uint size);
    [DllImport("kernel32.dll",EntryPoint="QueryInformationJobObject",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryLimits(SafeJobHandle handle,int info,out ExtendedLimits limits,uint size,out uint returned);
    [DllImport("kernel32.dll",EntryPoint="QueryInformationJobObject",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryAccounting(SafeJobHandle handle,int info,out BasicAccounting accounting,uint size,out uint returned);
    [DllImport("kernel32.dll",EntryPoint="QueryInformationJobObject",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryBuffer(SafeJobHandle handle,int info,IntPtr buffer,uint size,out uint returned);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool TerminateJobObject(SafeJobHandle handle,uint exitCode);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool IsProcessInJob(SafeProcessHandle process,SafeJobHandle job,[MarshalAs(UnmanagedType.Bool)] out bool belongs);
}
