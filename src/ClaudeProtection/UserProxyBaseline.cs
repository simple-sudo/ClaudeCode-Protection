using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;

namespace ClaudeProtection;

// Read-only. This component must never repair/change the machine's proxy state.
internal static class UserProxyBaseline
{
    internal sealed record Snapshot(string Fingerprint, bool ProxyEnabled, bool APIsAgree, bool ExpectedFlClashProxy, uint ConnectionFlags);
    internal static bool IsExpectedEndpoint(string setting)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in setting.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int equal = part.IndexOf('=');
            if (equal >= 0) map[part[..equal].Trim()] = part[(equal + 1)..].Trim();
            else map["*"] = part;
        }
        bool Endpoint(string protocol)
        {
            var value = map.GetValueOrDefault(protocol, map.GetValueOrDefault("*", ""));
            if (!value.Contains("://", StringComparison.Ordinal)) value = "http://" + value;
            return Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme == "http" && uri.Host == "127.0.0.1" && uri.Port == 7890 && uri.UserInfo.Length == 0 && uri.AbsolutePath == "/" && uri.Query.Length == 0 && uri.Fragment.Length == 0;
        }
        return Endpoint("http") && Endpoint("https");
    }
    internal static Snapshot Read()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings") ?? throw new InvalidOperationException("Missing user internet settings");
        var registryProxy = key.GetValue("ProxyServer") as string ?? "";
        bool enabled = Convert.ToInt32(key.GetValue("ProxyEnable", 0)) == 1;
        string pacRegistry = key.GetValue("AutoConfigURL") as string ?? "";
        if (!WinHttpGetIEProxyConfigForCurrentUser(out var ie)) throw new Win32Exception(Marshal.GetLastWin32Error());
        string ieProxy, iePac, ieBypass;
        try { ieProxy = Marshal.PtrToStringUni(ie.Proxy) ?? ""; iePac = Marshal.PtrToStringUni(ie.Pac) ?? ""; ieBypass = Marshal.PtrToStringUni(ie.Bypass) ?? ""; }
        finally { Free(ie.Proxy); Free(ie.Pac); Free(ie.Bypass); }
        var sizeOfOption = Marshal.SizeOf<Option>();
        var buffer = Marshal.AllocHGlobal(sizeOfOption * 4);
        try
        {
            for (int i = 0; i < 4; i++) Marshal.StructureToPtr(new Option { Id = (uint)(i + 1) }, buffer + sizeOfOption * i, false);
            var list = new OptionList { Size = (uint)Marshal.SizeOf<OptionList>(), Count = 4, Options = buffer };
            uint size = list.Size;
            if (!InternetQueryOption(IntPtr.Zero, 75, ref list, ref size)) throw new Win32Exception(Marshal.GetLastWin32Error());
            var flags = Marshal.PtrToStructure<Option>(buffer).Flags;
            var proxy = Marshal.PtrToStructure<Option>(buffer + sizeOfOption);
            var bypass = Marshal.PtrToStructure<Option>(buffer + sizeOfOption * 2);
            var pac = Marshal.PtrToStructure<Option>(buffer + sizeOfOption * 3);
            string connectionProxy, connectionBypass, connectionPac;
            try
            {
                connectionProxy = Marshal.PtrToStringUni(proxy.Text) ?? "";
                connectionBypass = Marshal.PtrToStringUni(bypass.Text) ?? "";
                connectionPac = Marshal.PtrToStringUni(pac.Text) ?? "";
            }
            finally { Free(proxy.Text); Free(bypass.Text); Free(pac.Text); }
            // Hash full values, but do not output PAC URLs, credentials or bypass hosts.
            var raw = JsonSerializer.SerializeToUtf8Bytes(new { registryProxy, enabled, pacRegistry, ieProxy, iePac, ieBypass, ie.AutoDetect, flags, connectionProxy, connectionBypass, connectionPac });
            bool agree = registryProxy == ieProxy && ieProxy == connectionProxy && enabled == ((flags & 2) != 0);
            bool expected = enabled && agree && IsExpectedEndpoint(registryProxy) && pacRegistry.Length == 0 && iePac.Length == 0 && connectionPac.Length == 0 && ie.AutoDetect == 0;
            return new(ProxySettings.Hash(raw), enabled, agree, expected, flags);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
    private static void Free(IntPtr pointer) { if (pointer != IntPtr.Zero) _ = GlobalFree(pointer); }
    [StructLayout(LayoutKind.Sequential)] private struct IeConfig { public int AutoDetect; public IntPtr Pac, Proxy, Bypass; }
    [StructLayout(LayoutKind.Sequential)] private struct OptionList { public uint Size; public IntPtr Connection; public uint Count, Error; public IntPtr Options; }
    [StructLayout(LayoutKind.Explicit, Size = 16)] private struct Option { [FieldOffset(0)] public uint Id; [FieldOffset(8)] public uint Flags; [FieldOffset(8)] public IntPtr Text; }
    [DllImport("winhttp.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool WinHttpGetIEProxyConfigForCurrentUser(out IeConfig config);
    [DllImport("wininet.dll", EntryPoint = "InternetQueryOptionW", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool InternetQueryOption(IntPtr session, uint option, ref OptionList list, ref uint size);
    [DllImport("kernel32.dll")] private static extern IntPtr GlobalFree(IntPtr memory);
}
