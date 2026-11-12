using System.ComponentModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal sealed partial class HostPrivacyProbe
{
    private static string FileIdentity(string path)
    {
        for(var p=path;p is not null;p=Path.GetDirectoryName(p))
            if((File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw WfpNative.Contract("HostPrivacyRedirectedTargetRefused");
        using var handle=CreateFile(path,0x80,7,IntPtr.Zero,3,0x40200000,IntPtr.Zero);
        if(handle.IsInvalid || !GetFileInformationByHandle(handle,out var info))throw new Win32Exception(Marshal.GetLastWin32Error(),"Host privacy file metadata positive control");
        if((info.Attributes&0x410)!=0)throw WfpNative.Contract("HostPrivacyOrdinaryFileRequired");
        return info.Volume.ToString("X8")+info.IndexHigh.ToString("X8")+info.IndexLow.ToString("X8");
    }


    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle process,out uint exitCode);
    [StructLayout(LayoutKind.Sequential)] private struct FileInfo
    {internal uint Attributes;internal System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;internal uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle file,out FileInfo info);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint pid);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",EntryPoint="QueryFullProcessImageNameW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder path,ref int length);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll",EntryPoint="RegOpenKeyExW",CharSet=CharSet.Unicode)] private static extern int RegOpenKeyEx(IntPtr root,string path,uint options,uint access,out SafeRegistryHandle key);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("iphlpapi.dll",ExactSpelling=true)] private static extern uint GetExtendedUdpTable(IntPtr table,ref uint size,[MarshalAs(UnmanagedType.Bool)]bool sorted,uint family,int tableClass,uint reserved);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)] private static extern uint GetSystemFirmwareTable(uint provider,uint table,IntPtr buffer,uint size);
}
