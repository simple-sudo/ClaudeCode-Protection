using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Keep fixed native layouts distinct from variable-sized SID/group buffers.
// Windows does not consistently report ERROR_INSUFFICIENT_BUFFER when a
// fixed-size token field is queried with a null buffer.
internal static class WindowsTokenInformation
{
    internal enum Dword
    {
        Type=8,
        SessionId=12,
        ElevationType=18,
        Elevation=20,
        UiAccess=26,
        IsAppContainer=29
    }

    internal static int Read(SafeAccessTokenHandle token,Dword field,string stage)
    {
        if(!GetTokenInformation(token,field,out var value,sizeof(int),out var returned))
        {
            var error=new Win32Exception(Marshal.GetLastWin32Error(),"Query fixed Windows token information");
            error.Data["Stage"]=stage;
            throw error;
        }
        if(returned!=sizeof(int))
        {
            var error=new InvalidDataException("Fixed Windows token information length differs");
            error.Data["Stage"]=stage;
            throw error;
        }
        return value;
    }

    internal readonly record struct PrimaryBinding(ulong TokenId,ulong ModifiedId);

    internal static PrimaryBinding ReadPrimaryBinding(SafeAccessTokenHandle token)
    {
        var stats=ReadStatistics(token,"ReadCreatorPrimaryTokenBinding");
        if(stats.Type!=1 || stats.TokenId==0 || stats.ModifiedId==0)
            throw WfpNative.Contract("CreatorPrimaryTokenBindingInvalid");
        return new(stats.TokenId,stats.ModifiedId);
    }

    internal static ulong ReadAuthenticationId(SafeAccessTokenHandle token) =>
        ReadStatistics(token,"ReadOwnAuthenticationId").AuthenticationId;

    private static TokenStatistics ReadStatistics(SafeAccessTokenHandle token,string stage)
    {
        var size=Marshal.SizeOf<TokenStatistics>();
        if(!GetTokenStatistics(token,10,out var stats,size,out var returned)) // TokenStatistics.
        {
            var error=new Win32Exception(Marshal.GetLastWin32Error(),"Query fixed token statistics");
            error.Data["Stage"]=stage;
            throw error;
        }
        if(returned!=size)
            throw WfpNative.Contract("CreatorPrimaryTokenBindingInvalid");
        return stats;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenStatistics
    {
        internal ulong TokenId,AuthenticationId;
        internal long ExpirationTime;
        internal uint Type,ImpersonationLevel,DynamicCharged,DynamicAvailable,GroupCount,PrivilegeCount;
        internal ulong ModifiedId;
    }

    [DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token,Dword field,out int value,int size,out int returned);
    [DllImport("advapi32.dll",EntryPoint="GetTokenInformation",ExactSpelling=true,SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenStatistics(SafeAccessTokenHandle token,int field,out TokenStatistics value,int size,out int returned);
}
