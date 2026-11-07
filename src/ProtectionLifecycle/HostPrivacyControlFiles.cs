using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal sealed partial class HostPrivacyProbe
{
    // The original installed owner derives all three paths. No source root,
    // caller path, arbitrary maintenance target or content read is accepted.
    private static string ControlFilePath(string programFiles,string release,HostPrivacyCheck check)
    {
        release=Identifiers.Hex32(release);
        return WindowsPathSeal.Child(programFiles,check.Target switch {
            HostPrivacyTarget.InstallationRecord=>"ClaudeCodeProtection-State/installation.json",
            HostPrivacyTarget.VersionSelection=>"ClaudeCodeProtection-State/current.json",
            HostPrivacyTarget.RuntimeImage=>"ClaudeCodeProtection/versions/"+release+"/bin/admin/ProtectionLifecycle.dll",
            _=>throw WfpNative.Contract("ProtectionControlFileTargetRequired")
        });
    }
    private static void RequireControlFileTarget(string path,int pid,string programFiles,string release,HostPrivacyCheck check)
    {
        if(pid!=0 ||
            !string.Equals(path,ControlFilePath(programFiles,release,check),StringComparison.OrdinalIgnoreCase))
            throw WfpNative.Contract("ProtectionControlFileTargetBindingDiffers");
    }
    private static (Target[] Targets,List<SafeFileHandle> Handles) CaptureControlFiles(string release)
    {
        var programFiles=WindowsPathSeal.Canonical(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        var files=new Dictionary<string,SafeFileHandle>(StringComparer.OrdinalIgnoreCase);var handles=new List<SafeFileHandle>();var targets=new List<Target>();
        try
        {
            foreach(var check in HostPrivacyContract.Checks.Where(check=>check.TargetKind==HostPrivacyTargetKind.ControlFile))
            {
                var path=ControlFilePath(programFiles,release,check);
                if(!files.TryGetValue(path,out var handle))
                {
                    handle=WindowsPathSeal.Open(path,false,false);handles.Add(handle);files.Add(path,handle);
                    WindowsPathSeal.AssertAcl(handle,check.Target==HostPrivacyTarget.InstallationRecord);
                }
                // A write-data open could be refused by the existing owner's
                // immutable read share. Check the trusted token's actual DACL
                // access separately; a sharing violation is never a denial.
                AssertControlFileMaintenanceAccess(handle,check.Access);
                targets.Add(new(check,path,0,FileIdentity(path)));
            }
            return(targets.ToArray(),handles);
        }
        catch{foreach(var handle in handles)handle.Dispose();throw;}
    }
    private static void AssertControlFileMaintenanceAccess(SafeFileHandle file,uint access)
    {
        if(access is not (1 or 2 or 0x40000 or 0x80000))throw WfpNative.Contract("ProtectionControlFileMaintenanceMaskDiffers");
        var status=GetSecurityInfo(file,1,7,out _,out _,out _,out _,out var descriptor);
        if(status!=0)throw new Win32Exception(checked((int)status),"Control file security metadata positive control");
        try
        {
            var size=GetSecurityDescriptorLength(descriptor);
            if(size is <20 or >65536)throw WfpNative.Contract("ProtectionControlFileDescriptorBounds");
            var bytes=new byte[size];Marshal.Copy(descriptor,bytes,0,bytes.Length);
            using var human=WindowsIdentity.GetCurrent();
            if(!DuplicateTokenEx(human.AccessToken,8,IntPtr.Zero,1,2,out var query))throw new Win32Exception(Marshal.GetLastWin32Error(),"Control file query token positive control");
            using(query)
            {
                var mapping=new FileGenericMapping();var privileges=new byte[1024];uint length=(uint)privileges.Length;
                if(!AccessCheck(bytes,query,access,ref mapping,privileges,ref length,out var granted,out var allowed))
                    throw new Win32Exception(Marshal.GetLastWin32Error(),"Control file maintenance positive control");
                if(length>privileges.Length || !allowed || (granted&access)!=access)throw WfpNative.Contract("ProtectionControlFileMaintenanceNotAllowed");
            }
        }
        finally{LocalFree(descriptor);}
    }
    [StructLayout(LayoutKind.Sequential)] private struct FileGenericMapping {internal uint Read,Write,Execute,All;}
    [DllImport("advapi32.dll")] private static extern uint GetSecurityInfo(SafeFileHandle file,int type,uint info,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr pointer);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(SafeAccessTokenHandle existing,uint access,IntPtr security,int level,int type,out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool AccessCheck(byte[] descriptor,SafeAccessTokenHandle token,uint desired,ref FileGenericMapping mapping,[Out]byte[] privileges,ref uint size,out uint granted,[MarshalAs(UnmanagedType.Bool)]out bool allowed);
}
