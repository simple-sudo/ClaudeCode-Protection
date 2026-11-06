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
    internal sealed record TimedRow(long StartedFileTime,long FinishedFileTime,uint ThreadId,Row Result);
    [DllImport("kernel32.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetCurrentThreadId();
    [DllImport("kernel32.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void GetSystemTimePreciseAsFileTime(out long value);
    internal static long PreciseFileTime(){GetSystemTimePreciseAsFileTime(out var value);return value;}
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
    // Fixed parser markers for the matched AFD image. A difference is evidence
    // about how far a request may have progressed, never a kernel execution trace
    // or permission to grant access. Keep the original five-row matrix unchanged.
    internal static Row[] ReadDispatchMarkers()
    {
        if(!Environment.Is64BitProcess || Marshal.SizeOf<Attributes>()!=48)throw new PlatformNotSupportedException("Fixed x64 ABI required");
        return new[]{Open("valid-ipv4-tcp-control",@"\Device\Afd\Endpoint",0xc0140000,2),
            Open("invalid-family-35-marker",@"\Device\Afd\Endpoint",0xc0140000,2,35),
            Open("invalid-flags-2-marker",@"\Device\Afd\Endpoint",0xc0140000,2,2,2)};
    }
    // New qualification input only; the original matrices and their historical
    // output schema stay unchanged. Time each synchronous request separately so
    // an ETW event cannot be attributed merely to a reused PID or broad window.
    internal static TimedRow[] ReadTimedDispatchMarkers()
    {
        if(!Environment.Is64BitProcess || Marshal.SizeOf<Attributes>()!=48)throw new PlatformNotSupportedException("Fixed x64 ABI required");
        TimedRow ReadOne(string role,int family,uint flags)
        {
            var thread=GetCurrentThreadId();var start=PreciseFileTime();
            var row=Open(role,@"\Device\Afd\Endpoint",0xc0140000,2,family,flags);
            return new(start,PreciseFileTime(),thread,row);
        }
        return new[]{ReadOne("valid-ipv4-tcp-control",2,0x01000000),ReadOne("invalid-family-35-marker",35,0x01000000),
            ReadOne("invalid-flags-2-marker",2,2)};
    }
    private static Row Open(string role,string path,uint access,int kind,int family=2,uint packetFlags=0x01000000)
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
                BitConverter.GetBytes(packetFlags).CopyTo(ea,24);BitConverter.GetBytes(family).CopyTo(ea,32);BitConverter.GetBytes(1).CopyTo(ea,36);BitConverter.GetBytes(6).CopyTo(ea,40);
                code=NtCreateFile(out handle,access,ref attrs,out io,IntPtr.Zero,0,3,3,0,ea,(uint)ea.Length);
            }
            status=Hex(code);ioStatus=kind==0?"NOT_APPLICABLE":code<0?"UNDEFINED_ON_FAILURE":Hex(unchecked((int)io.Status.ToInt64()));
            // Output handles/IO_STATUS_BLOCK are not proof of valid output when
            // the direct NT return failed. Never adopt a failure output handle.
            if(code>=0)owned=new SafeFileHandle(handle,true);
            valid=owned is not null && !owned.IsInvalid;
            if(valid && owned is not null){if(GetHandleInformation(owned,out var flags))inherits=(flags&1)!=0;else{error="HandleFlagsUnknown";managedCode=Marshal.GetLastWin32Error();}}
        }
        catch(Exception ex) when(ex is DllNotFoundException or EntryPointNotFoundException or ArgumentException)
        {error=ex.GetType().Name;managedCode=ex.HResult;}
        finally{owned?.Dispose();if(name!=IntPtr.Zero)Marshal.FreeHGlobal(name);Marshal.FreeHGlobal(text);}
        return new(role,path,access,status,ioStatus,valid,inherits,owned is null || owned.IsClosed,error,managedCode);
    }
    private static string Hex(int value)=>"0x"+unchecked((uint)value).ToString("X8");
}
