using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace ClaudeProtection;

internal static class ProcessIdentity
{
    internal sealed record Identity(uint Pid, string ImagePath, string CreatedUtc, bool Running);
    internal static Identity Read(uint pid)
    {
        var process = OpenProcess(0x1000, false, pid); // QUERY_LIMITED_INFORMATION; no VM read, no mutation.
        if (process == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var image = new StringBuilder(32768); uint count = (uint)image.Capacity;
            if (!QueryFullProcessImageName(process, 0, image, ref count)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!GetProcessTimes(process, out long created, out _, out _, out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!GetExitCodeProcess(process, out uint code)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return new(pid, image.ToString(), DateTime.FromFileTimeUtc(created).ToString("o"), code == 259);
        }
        finally { CloseHandle(process); }
    }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref uint count);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
}
