using System.ComponentModel;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;

internal static class RestrictingSidCases
{
    internal static void Run(Assembly library)
    {
        var type = library.GetType("ProtectionLifecycle.RestrictingSidToken", true)!;
        const BindingFlags instance = BindingFlags.NonPublic | BindingFlags.Instance;
        const BindingFlags shared = BindingFlags.NonPublic | BindingFlags.Static;
        var installation = new string('a', 32);
        const string registryRead = "S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681";
        object? Call(string name, object? target, params object?[] args)
        {
            try { return type.GetMethod(name, target is null ? shared : instance)!.Invoke(target, args); }
            catch (TargetInvocationException ex) when (ex.InnerException is not null)
            { ExceptionDispatchInfo.Capture(ex.InnerException).Throw(); throw; }
        }
        var checks = 0;
        void Check(bool condition) { if (!condition) throw new InvalidOperationException("Restricting SID access boundary mismatch"); checks++; }
        void Refused(Action action)
        {
            var refused = false; try { action(); } catch (InvalidDataException) { refused = true; }
            Check(refused);
        }
        foreach (var invalid in new[] { "", new string('0', 32), new string('A', 32), installation + "a", "S-1-5-32-544" })
            Refused(() => Call("CreateForCurrentOwner", null, invalid));

        var package = (string)Call("ResourceSidForInstallation", null, installation)!;
        var foreign = (string)Call("ResourceSidForInstallation", null, new string('b', 32))!;
        Check(package == (string)Call("ResourceSidForInstallation", null, installation)! && package != foreign);
        using var restricted = (IDisposable)Call("CreateForCurrentOwner", null, installation)!;
        Call("AssertHeld", restricted);
        using var query = (SafeAccessTokenHandle)Call("OpenAccessCheckToken", restricted)!;
        if (!OpenProcessToken(new IntPtr(-1), 0x000a, out var original)) throw Error("Own source token");
        using (original)
        {
            if (!DuplicateTokenEx(original, 8, IntPtr.Zero, 2, 2, out var source)) throw Error("Source query duplicate");
            using (source)
            {
                var userAndCapability = "(A;;0x1;;;BU)(A;;0x1;;;" + registryRead + ")";
                Check(Allows(source, userAndCapability));
                Check(!Allows(query, userAndCapability));
                Check(Allows(query, userAndCapability + "(A;;0x1;;;" + package + ")"));
                Check(!Allows(query, "(A;;0x1;;;BU)(A;;0x1;;;S-1-15-2-2)"));
                Check(!Allows(query, "(A;;0x1;;;BU)(A;;0x1;;;" + foreign + ")"));
                // The restricting pass cannot replace the ordinary enabled-SID pass.
                Check(!Allows(query, "(A;;0x1;;;" + package + ")"));
                Check(!Allows(query, "(D;;0x1;;;" + package + ")" + userAndCapability + "(A;;0x1;;;" + package + ")"));
                Check(!Allows(query, "(A;;0x2;;;BU)(A;;0x1;;;" + package + ")"));
            }
        }
        restricted.Dispose();
        Refused(() => Call("AssertHeld", restricted));
        Refused(() => Call("OpenAccessCheckToken", restricted));
        Console.WriteLine($"PASS {checks} restricting SID checks: native own-token reduction and synthetic in-memory registry access controls. No impersonation, child process, registry access/change, capability grant, network, installation, LPAC composition or product qualification.");
    }

    private static bool Allows(SafeAccessTokenHandle token, string aces)
    {
        var descriptor = new RawSecurityDescriptor("O:SYG:SYD:P" + aces);
        var bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0);
        var mapping = new GenericMapping { Read = 0x20019, Write = 0x20006, Execute = 0x20019, All = 0xf003f };
        var privileges = Marshal.AllocHGlobal(1024);
        try
        {
            uint size = 1024;
            if (!AccessCheck(bytes, token, 1, ref mapping, privileges, ref size, out var granted, out var allowed))
                throw Error("Synthetic descriptor AccessCheck");
            if (size > 1024 || (allowed && (granted & 1) == 0)) throw new InvalidDataException("AccessCheck result differs");
            return allowed;
        }
        finally { Marshal.FreeHGlobal(privileges); }
    }
    private static Win32Exception Error(string operation) => new(Marshal.GetLastWin32Error(), operation);
    [StructLayout(LayoutKind.Sequential)] private struct GenericMapping { internal uint Read, Write, Execute, All; }
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(SafeAccessTokenHandle source, uint access, IntPtr attributes,
        int level, int type, out SafeAccessTokenHandle result);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AccessCheck(byte[] descriptor, SafeAccessTokenHandle token, uint desired,
        ref GenericMapping mapping, IntPtr privileges, ref uint size, out uint granted,
        [MarshalAs(UnmanagedType.Bool)] out bool allowed);
}
