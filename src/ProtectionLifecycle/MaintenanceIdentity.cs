using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// The shared installation/state/maintenance gate checks the effective token,
// not a caller claim or membership alone. Never elevate, impersonate, adjust,
// assign, or fall back to the process token when a thread is impersonating.
internal static class MaintenanceIdentity
{
    internal readonly record struct TokenFacts(int Type,int AppContainer,int Elevated,int RestrictedSidCount);
    internal static void RequireCurrentAdministrator()
    {
        // Duplicate is used only by WindowsPrincipal's membership query.
        using var identity=WindowsIdentity.GetCurrent(TokenAccessLevels.Query|TokenAccessLevels.Duplicate);
        var facts=ReadFacts(identity.AccessToken);
        RequireEvidence(facts,new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator));
    }
    internal static void RequireEvidence(TokenFacts facts,bool administrator)
    {
        if(facts.Type!=1 || facts.AppContainer!=0 || facts.Elevated!=1 || facts.RestrictedSidCount!=0 || !administrator)
            throw new UnauthorizedAccessException("An unrestricted elevated primary administrator token is required; no automatic elevation");
    }
    internal static TokenFacts ReadFacts(SafeAccessTokenHandle token)
        =>new(ReadInt(token,8),ReadInt(token,29),ReadInt(token,20),ReadRestrictedSidCount(token));
    private static int ReadInt(SafeAccessTokenHandle token,int kind)
    {
        var bytes=new byte[sizeof(int)];
        if(!GetTokenInformation(token,kind,bytes,bytes.Length,out var returned))throw Error();
        if(returned!=bytes.Length)throw new InvalidDataException("Maintenance token information length differs");
        return BitConverter.ToInt32(bytes);
    }
    private static int ReadRestrictedSidCount(SafeAccessTokenHandle token)
    {
        // TOKEN_GROUPS is variable-sized. Only its count is needed; no SID or
        // group names are exported. Refuse failed/oversized/truncated queries.
        if(GetTokenInformation(token,11,null,0,out var size) || Marshal.GetLastWin32Error()!=122 || size is <4 or >65536)
            throw new InvalidDataException("Maintenance restriction query size unconfirmed");
        var bytes=new byte[size];
        if(!GetTokenInformation(token,11,bytes,bytes.Length,out var returned))throw Error();
        if(returned<4 || returned>bytes.Length)throw new InvalidDataException("Maintenance restriction query length differs");
        var count=BitConverter.ToInt32(bytes);
        if(count<0)throw new InvalidDataException("Maintenance restriction count differs");
        return count;
    }
    private static Win32Exception Error()=>new(Marshal.GetLastWin32Error(),"Query maintenance identity");
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token,int kind,[Out] byte[]? bytes,int size,out int returned);
}
