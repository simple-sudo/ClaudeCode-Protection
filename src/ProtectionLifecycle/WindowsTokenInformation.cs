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

    [DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token,Dword field,out int value,int size,out int returned);
}
