using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ClaudeCodeProtection.Workspaces;

// One names-only query implementation for both trusted lifecycle inventories
// and ordinary result snapshots. Caller supplies a fresh synchronous directory
// handle already bound to its held no-follow NTFS parent, owning its cursor.
internal static class WindowsDirectoryNames
{
    internal static string[] Read(SafeFileHandle directory,int maximum)
    {
        if(maximum is <1 or >32768)throw new ArgumentOutOfRangeException(nameof(maximum));
        if(directory.IsInvalid || directory.IsClosed)throw new ObjectDisposedException(nameof(directory));
        if(IntPtr.Size!=8 || Marshal.SizeOf<IoStatus>()!=16 || Marshal.OffsetOf<IoStatus>(nameof(IoStatus.Information)).ToInt64()!=8)
            throw new PlatformNotSupportedException("Reviewed x64 directory query ABI required");
        var names=new List<string>();var unique=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        const int size=65536;var buffer=Marshal.AllocHGlobal(size);var clock=System.Diagnostics.Stopwatch.StartNew();
        try
        {
            for(var call=0;call<=maximum+2;call++)
            {
                if(clock.ElapsedMilliseconds>5000)throw new IOException("Directory name scan budget exceeded");
                // FILE_NAMES_INFORMATION (12) avoids Wof directory metadata
                // conversion on both preserved crash stacks. No full-metadata
                // enumeration fallback; pending/overflow/partial are refusals.
                var status=NtQueryDirectoryFile(directory,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out var io,buffer,size,12,false,IntPtr.Zero,call==0);
                if(clock.ElapsedMilliseconds>5000)throw new IOException("Directory name scan budget exceeded");
                if(status==unchecked((int)0x80000006))
                {
                    if(io.Information!=0)throw new InvalidDataException("Partial terminal directory name result");
                    return names.ToArray();
                }
                if(status!=0 || io.Status!=0 || io.Information==0 || io.Information>(nuint)size)
                    throw new IOException("Directory name query refused: status=0x"+unchecked((uint)status).ToString("X8")+
                        "; io=0x"+io.Status.ToString("X8")+"; bytes="+io.Information);
                var page=new byte[checked((int)io.Information)];Marshal.Copy(buffer,page,0,page.Length);
                foreach(var name in ProtectionLifecycle.DirectoryNamePage.Parse(page))
                {
                    if(!unique.Add(name))throw new InvalidDataException("Duplicate/case-colliding directory leaf");
                    if(names.Count>=maximum)throw new InvalidDataException("Directory name inventory capacity exceeded");
                    names.Add(name);
                }
            }
            throw new IOException("Directory name scan did not terminate");
        }
        finally{Marshal.FreeHGlobal(buffer);}
    }
    [StructLayout(LayoutKind.Sequential)] private struct IoStatus{internal uint Status;internal nuint Information;}
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("ntdll.dll",ExactSpelling=true)] private static extern int NtQueryDirectoryFile(SafeFileHandle handle,IntPtr completionEvent,IntPtr apcRoutine,IntPtr apcContext,
        out IoStatus status,IntPtr buffer,uint length,int informationClass,[MarshalAs(UnmanagedType.U1)]bool singleEntry,IntPtr name,[MarshalAs(UnmanagedType.U1)]bool restart);
}
