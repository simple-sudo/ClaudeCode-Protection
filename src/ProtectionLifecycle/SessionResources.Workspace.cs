using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal sealed partial class SessionResources
{
    internal static string ProfileFolder(string sid)
    {
        var status=GetAppContainerFolderPath(sid,out var pointer);
        try
        {
            if(status!=0)throw new WfpFailure("GetOwnedProfileFolder",unchecked((uint)status));
            return WindowsPathSeal.Canonical(Marshal.PtrToStringUni(pointer)??throw WfpNative.Contract("ProfileFolderMissing"));
        }
        finally{if(pointer!=IntPtr.Zero)Marshal.FreeCoTaskMem(pointer);}
    }
owsIdentity.GetCurrent();
        var owner=identity.User?.Value??throw WfpNative.Contract("WorkspaceHumanOwnerMissing");
        using var parent=WindowsPathSeal.LockDirectory(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),PathPolicy.CreationParent);
        profile.PlanTaskWorkspace(session);
        var directory=CreateWorkspace(SessionTaskWorkspace.PathFor(session),owner,sid.Value,true);
        try{profile.RecordTaskWorkspace(session,directory);return directory;}
        catch{directory.Dispose();throw;}
    }
    internal static PathLease CreateWorkspace(string path,string owner,string package,bool mutable)
    {
        using var grant=new WorkspaceDescriptor(owner,package,mutable);
        var attributes=grant.Attributes;
        if(!CreateDirectory(path,ref attributes))throw new WfpFailure("CreateFreshSessionWorkspace",unchecked((uint)Marshal.GetLastWin32Error()));
        var directory=WindowsPathSeal.LockDirectory(path,PathPolicy.Source);
        try{grant.ApplyLowLabelAndVerify(path);return directory;}
        catch{directory.Dispose();throw;}
    }
    internal static void AssertMutableWorkspace(SafeFileHandle handle,string human,string package)
    {using var expected=new WorkspaceDescriptor(human,package,true);expected.AssertApplied(handle);}
    // Recovery may delete only an unrecorded, still-empty directory created
    // after a durable fresh-path intent. Its DACL must remain exact; the low
    // label may be either the expected label or absent if creation was
    // interrupted between CreateDirectoryW and SetSecurityInfo(LABEL).
    internal static void AssertFreshWorkspaceForRecovery(SafeFileHandle handle,string human,string package)
    {using var expected=new WorkspaceDescriptor(human,package,true);expected.AssertApplied(handle,allowMissingLowLabel:true);}
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] private static extern int GetAppContainerFolderPath(string sid,out IntPtr path);
    [DllImport("kernel32.dll",EntryPoint="CreateDirectoryW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateDirectory(string path,ref KernelJobSeal.SecurityAttributes attributes);
}
