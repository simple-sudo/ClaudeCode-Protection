#nullable enable
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

// Fixed metadata/open matrix, not a general device executor. No IOCTL, object
// security setter, socket bind/connect, inheritance, token adjustment or retry.
internal static class NativeBoundary
{
    internal sealed record Row(string Role,string Path,uint DesiredAccess,string Status,string IoStatus,bool HandleValid,
        bool? Inheritable,bool HandleClosed,string? ManagedError,int? ManagedErrorCode);
    [StructLayout(LayoutKind.Sequential)] private struct UnicodeString {internal ushort Length,MaximumLength;internal IntPtr Buffer;}
    [StructLayout(LayoutKind.Sequential)] private struct Attributes {internal uint Length;internal IntPtr Root,Name;internal uint Flags;internal IntPtr Security,Qos;}
    [StructLayout(LayoutKind.Sequential)] private struct IoStatus {internal IntPtr Status;internal UIntPtr Information;}
    [DllImport("ntdll.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] private static extern int NtOpenDirectoryObject(out IntPtr handle,uint access,ref Attributes attributes);
    [DllImport("ntdll.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] private static extern int NtOpenFile(out IntPtr handle,uint access,ref Attributes attributes,out IoStatus io,uint share,uint options);
    [DllImport("ntdll.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] private static extern int NtCreateFile(out IntPtr handle,uint access,ref Attributes attributes,out IoStatus io,IntPtr allocation,uint fileAttributes,uint share,uint disposition,uint options,byte[] ea,uint length);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetHandleInformation(SafeFileHandle handle,out uint flags);
    internal static Row[] Read()
    {
        if(!Environment.Is64BitProcess || Marshal.SizeOf<Attributes>()!=48)throw new PlatformNotSupportedException("Fixed x64 ABI required");
        return new[]{Open("namespace-traverse",@"\Device",2,0),Open("afd-root-read-control",@"\Device\Afd",0x120000,1),
            Open("endpoint-zero-rights",@"\Device\Afd\Endpoint",0,2),Open("endpoint-read-write-sync",@"\Device\Afd\Endpoint",0xc0100000,2),
            Open("endpoint-original-access",@"\Device\Afd\Endpoint",0xc0140000,2)};
    }
    private static Row Open(string role,string path,uint access,int kind)
    {
        var text=Marshal.StringToHGlobalUni(path);var name=IntPtr.Zero;SafeFileHandle? owned=null;
        int? managedCode=null;string? error=null;string status="NOT_RUN",ioStatus="NOT_RUN";bool valid=false;bool? inherits=null;
        try
        {
            var value=new UnicodeString{Length=checked((ushort)(path.Length*2)),MaximumLength=checked((ushort)(path.Length*2+2)),Buffer=text};
            name=Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());Marshal.StructureToPtr(value,name,false);
            var attrs=new Attributes{Length=48,Name=name,Flags=0x40};IntPtr handle;IoStatus io=default;int code;
            if(kind==0)code=NtOpenDirectoryObject(out handle,access,ref attrs);
            else if(kind==1)code=NtOpenFile(out handle,access,ref attrs,out io,3,0x20);
            else
            {
                var ea=new byte[57];ea[5]=15;ea[6]=30;Encoding.ASCII.GetBytes("AfdOpenPacketXX").CopyTo(ea,8);
                BitConverter.GetBytes(0x01000000u).CopyTo(ea,24);BitConverter.GetBytes(2).CopyTo(ea,32);BitConverter.GetBytes(1).CopyTo(ea,36);BitConverter.GetBytes(6).CopyTo(ea,40);
                code=NtCreateFile(out handle,access,ref attrs,out io,IntPtr.Zero,0,3,3,0,ea,(uint)ea.Length);
            }
            owned=new SafeFileHandle(handle,true);status=Hex(code);ioStatus=kind==0?"NOT_APPLICABLE":Hex(unchecked((int)io.Status.ToInt64()));
            valid=code==0 && !owned.IsInvalid;
            if(valid){if(GetHandleInformation(owned,out var flags))inherits=(flags&1)!=0;else{error="HandleFlagsUnknown";managedCode=Marshal.GetLastWin32Error();}}
        }
        catch(Exception ex) when(ex is DllNotFoundException or EntryPointNotFoundException or ArgumentException)
        {error=ex.GetType().Name;managedCode=ex.HResult;}
        finally{owned?.Dispose();if(name!=IntPtr.Zero)Marshal.FreeHGlobal(name);Marshal.FreeHGlobal(text);}
        return new(role,path,access,status,ioStatus,valid,inherits,owned is null || owned.IsClosed,error,managedCode);
    }
    private static string Hex(int value)=>"0x"+unchecked((uint)value).ToString("X8");
}
