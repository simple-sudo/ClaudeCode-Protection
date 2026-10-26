using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ClaudeProtection;

internal static class SandboxToken
{
    internal sealed record Identity(bool IsAppContainer, string? Sid, int CapabilityCount);
    internal static Identity Read(IntPtr process)
    {
        if (!OpenProcessToken(process, 8, out var token)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            bool container = ReadBuffer(token, 29, buffer => Marshal.ReadInt32(buffer) != 0);
            string? sid = ReadBuffer(token, 31, buffer =>
            {
                var pointer = Marshal.ReadIntPtr(buffer);
                return pointer == IntPtr.Zero ? null : new SecurityIdentifier(pointer).Value;
            });
            int count = ReadBuffer(token, 30, Marshal.ReadInt32);
            return new(container, sid, count);
        }
        finally { CloseHandle(token); }
    }
    private static T ReadBuffer<T>(IntPtr token, int type, Func<IntPtr, T> read)
    {
        _ = GetTokenInformation(token, type, IntPtr.Zero, 0, out var size);
        if (size == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
        var buffer = Marshal.AllocHGlobal(size);
        try { if (!GetTokenInformation(token, type, buffer, size, out _)) throw new Win32Exception(Marshal.GetLastWin32Error()); return read(buffer); }
        finally { Marshal.FreeHGlobal(buffer); }
    }
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetTokenInformation(IntPtr token, int type, IntPtr information, int length, out int required);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
}
