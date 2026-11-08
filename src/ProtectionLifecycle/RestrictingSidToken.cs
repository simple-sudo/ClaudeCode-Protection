using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Lower-only primitive for the original admission owner. Not connected to
// process creation: LPAC composition and usable resource scope are unqualified.
// Handles never carry TOKEN_ASSIGN_PRIMARY, TOKEN_IMPERSONATE or ADJUST rights.
internal sealed class RestrictingSidToken : IDisposable
{
    private static readonly string[] AdministrativeGroups = { "S-1-5-32-544", "S-1-5-114" };
    private readonly SafeAccessTokenHandle token;
    internal string ResourceSid { get; }

    private RestrictingSidToken(SafeAccessTokenHandle token, string resourceSid)
    { this.token = token; ResourceSid = resourceSid; }

    internal static RestrictingSidToken CreateForCurrentOwner(string installationId)
    {
        if (!Environment.Is64BitProcess || Marshal.SizeOf<SidAndAttributes>() != 16)
            throw new PlatformNotSupportedException("RestrictingTokenRequiresX64");
        var resourceSid = ResourceSidForInstallation(installationId);
        if (!OpenProcessToken(new IntPtr(-1), 0x000a, out var source))
            throw Error("RestrictingTokenOpenOwnProcess");
        using (source)
        {
            if (WindowsTokenInformation.Read(source, WindowsTokenInformation.Dword.IsAppContainer, "RestrictingTokenInformation") != 0)
                throw Refuse("RestrictingTokenSourceMustBeHostOwner");
            // CreateRestrictedToken intersects an existing restricting list.
            // Refuse such a source instead of silently changing this contract.
            if (ReadGroups(source, 11).Count != 0 || IsTokenRestricted(source))
                throw Refuse("RestrictingTokenSourceAlreadyRestricted");
            using var disabled = new SidArray(AdministrativeGroups);
            using var restricting = new SidArray(new[] { resourceSid });
            // DISABLE_MAX_PRIVILEGE only. Never WRITE_RESTRICTED or SANDBOX_INERT.
            if (!CreateRestrictedToken(source, 1, 2, disabled.Pointer, 0, IntPtr.Zero,
                1, restricting.Pointer, out var result))
            { var failure = Error("RestrictingTokenCreate"); result?.Dispose(); throw failure; }
            var owner = new RestrictingSidToken(result, resourceSid);
            try { owner.AssertHeld(); return owner; }
            catch { owner.Dispose(); throw; }
        }
    }

    internal void AssertHeld()
    {
        if (token.IsClosed || token.IsInvalid) throw Refuse("RestrictingTokenNotHeld");
        if (!IsTokenRestricted(token)) throw Refuse("RestrictingTokenRestrictionMissing");
        var restricted = ReadGroups(token, 11);
        if (restricted.Count != 1 || restricted[0].Sid != ResourceSid)
            throw Refuse("RestrictingTokenSidSetDiffers");
        foreach (var group in ReadGroups(token, 2))
            if (AdministrativeGroups.Contains(group.Sid, StringComparer.Ordinal) &&
                ((group.Attributes & 0x10) == 0 || (group.Attributes & 0x6) != 0))
                throw Refuse("RestrictingTokenAdministrativeGroupEnabled");
        if (!LookupPrivilegeValue(null, "SeChangeNotifyPrivilege", out var traverse))
            throw Error("RestrictingTokenTraversePrivilege");
        using var privileges = TokenData.Read(token, 3);
        var count = privileges.Count(4, 12);
        for (var i = 0; i < count; i++)
        {
            var entry = IntPtr.Add(privileges.Pointer, 4 + i * 12);
            var low = unchecked((uint)Marshal.ReadInt32(entry));
            var high = Marshal.ReadInt32(entry, 4);
            var attributes = unchecked((uint)Marshal.ReadInt32(entry, 8));
            if ((attributes & 2) != 0 && (low != traverse.Low || high != traverse.High))
                throw Refuse("RestrictingTokenUnexpectedPrivilege");
        }
    }

    // AccessCheck needs an impersonation-type token, but the returned handle
    // permits QUERY only; this class never impersonates or launches a process.
    internal SafeAccessTokenHandle OpenAccessCheckToken()
    {
        AssertHeld();
        if (!DuplicateTokenEx(token, 8, IntPtr.Zero, 2, 2, out var result))
        { var failure = Error("RestrictingTokenQueryDuplicate"); result?.Dispose(); throw failure; }
        return result;
    }

    public void Dispose() => token.Dispose();

    // Use the documented NT-authority GROUP output, not an AppAuthority SID.
    // The former ARP+package candidate returned error 87 and is not a fallback.
    // Nothing is added to TokenGroups or TokenCapabilities by this derivation.
    internal static string ResourceSidForInstallation(string installationId)
    {
        if (installationId is null || installationId.Length != 32 ||
            installationId.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f')) ||
            installationId == new string('0', 32)) throw Refuse("RestrictingTokenInstallationRequired");
        IntPtr groups = IntPtr.Zero, capabilities = IntPtr.Zero;
        uint groupCount = 0, capabilityCount = 0;
        try
        {
            if (!DeriveCapabilitySidsFromName("cpc.session.resources.v1." + installationId,
                out groups, out groupCount, out capabilities, out capabilityCount))
                throw Error("RestrictingTokenDeriveResourceGroup");
            if (groups == IntPtr.Zero || capabilities == IntPtr.Zero || groupCount != 1 || capabilityCount != 1)
                throw Refuse("RestrictingTokenDerivedGroupShape");
            var sid = new SecurityIdentifier(Marshal.ReadIntPtr(groups)).Value;
            if (!sid.StartsWith("S-1-5-32-", StringComparison.Ordinal) || sid.Split('-').Length != 12)
                throw Refuse("RestrictingTokenDerivedGroupAuthority");
            return sid;
        }
        finally { FreeArray(groups, groupCount); FreeArray(capabilities, capabilityCount); }

        static void FreeArray(IntPtr array, uint count)
        {
            if (array == IntPtr.Zero) return;
            if (count <= 16)
                for (var i = 0; i < count; i++)
                { var sid = Marshal.ReadIntPtr(array, i * IntPtr.Size); if (sid != IntPtr.Zero) _ = LocalFree(sid); }
            _ = LocalFree(array);
        }
    }

    private static List<(string Sid, uint Attributes)> ReadGroups(SafeAccessTokenHandle handle, int kind)
    {
        using var data = TokenData.Read(handle, kind);
        var count = data.Count(8, 16);
        var result = new List<(string, uint)>(count);
        for (var i = 0; i < count; i++)
        {
            var entry = Marshal.PtrToStructure<SidAndAttributes>(IntPtr.Add(data.Pointer, 8 + i * 16));
            var offset = entry.Sid.ToInt64() - data.Pointer.ToInt64();
            if (offset < 0 || offset > data.Length - 8) throw Refuse("RestrictingTokenSidBounds");
            var subAuthorities = Marshal.ReadByte(entry.Sid, 1);
            if (Marshal.ReadByte(entry.Sid) != 1 || subAuthorities > 15 ||
                offset + 8 + subAuthorities * 4 > data.Length)
                throw Refuse("RestrictingTokenSidBounds");
            result.Add((new SecurityIdentifier(entry.Sid).Value, entry.Attributes));
        }
        return result;
    }

    private sealed class TokenData : IDisposable
    {
        internal IntPtr Pointer { get; private set; }
        internal int Length { get; }
        private TokenData(int length) { Length = length; Pointer = Marshal.AllocHGlobal(length); }
        internal static TokenData Read(SafeAccessTokenHandle handle, int kind)
        {
            var success = GetTokenInformation(handle, kind, IntPtr.Zero, 0, out var length);
            var error = Marshal.GetLastWin32Error();
            if (success || error != 122 || length < 4 || length > 1048576)
                throw Refuse("RestrictingTokenInformationSize");
            var data = new TokenData(length);
            try
            {
                if (!GetTokenInformation(handle, kind, data.Pointer, length, out var actual))
                    throw Error("RestrictingTokenInformation");
                if (actual != length) throw Refuse("RestrictingTokenInformationChanged");
                return data;
            }
            catch { data.Dispose(); throw; }
        }
        internal int Count(int offset, int stride)
        {
            var count = Marshal.ReadInt32(Pointer);
            if (count < 0 || count > 4096 || (count != 0 && (Length < offset || count > (Length - offset) / stride)))
                throw Refuse("RestrictingTokenEntryBounds");
            return count;
        }
        public void Dispose() { if (Pointer != IntPtr.Zero) { Marshal.FreeHGlobal(Pointer); Pointer = IntPtr.Zero; } }
    }

    private sealed class SidArray : IDisposable
    {
        internal IntPtr Pointer { get; private set; }
        private readonly List<IntPtr> sids = new();
        internal SidArray(string[] values)
        {
            try
            {
                Pointer = Marshal.AllocHGlobal(checked(values.Length * 16));
                for (var i = 0; i < values.Length; i++)
                {
                    var sid = new SecurityIdentifier(values[i]);
                    var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0);
                    var native = Marshal.AllocHGlobal(bytes.Length); sids.Add(native);
                    Marshal.Copy(bytes, 0, native, bytes.Length);
                    Marshal.StructureToPtr(new SidAndAttributes { Sid = native }, IntPtr.Add(Pointer, i * 16), false);
                }
            }
            catch { Dispose(); throw; }
        }
        public void Dispose()
        {
            foreach (var sid in sids) Marshal.FreeHGlobal(sid); sids.Clear();
            if (Pointer != IntPtr.Zero) { Marshal.FreeHGlobal(Pointer); Pointer = IntPtr.Zero; }
        }
    }

    private static InvalidDataException Refuse(string reason) => new(reason);
    private static Win32Exception Error(string operation) => new(Marshal.GetLastWin32Error(), operation);
    [StructLayout(LayoutKind.Sequential)] private struct SidAndAttributes { internal IntPtr Sid; internal uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct Luid { internal uint Low; internal int High; }
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateRestrictedToken(SafeAccessTokenHandle source, uint flags, uint disabledCount,
        IntPtr disabled, uint deletedCount, IntPtr deleted, uint restrictedCount, IntPtr restricted, out SafeAccessTokenHandle result);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(SafeAccessTokenHandle source, uint access, IntPtr attributes,
        int level, int type, out SafeAccessTokenHandle result);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int kind, IntPtr data, int length, out int actual);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsTokenRestricted(SafeAccessTokenHandle token);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", EntryPoint = "LookupPrivilegeValueW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(string? system, string name, out Luid luid);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernelbase.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeriveCapabilitySidsFromName(string name, out IntPtr groups,
        out uint groupCount, out IntPtr capabilities, out uint capabilityCount);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr LocalFree(IntPtr memory);
}
