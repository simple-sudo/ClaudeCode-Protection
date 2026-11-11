using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Separate, protected DACLs prevent same-user processes from changing Git
// inputs while the LPAC is running. Project files are writable by the package;
// Git configuration, hooks, templates and the owner-created pathspec are not.
internal sealed class GitWorkspaceDescriptor : IDisposable
{
    private readonly RawSecurityDescriptor expected;
    private IntPtr descriptor=IntPtr.Zero,label=IntPtr.Zero;

    internal KernelJobSeal.SecurityAttributes Attributes=>new()
    {
        Length=Marshal.SizeOf<KernelJobSeal.SecurityAttributes>(),Descriptor=descriptor,Inherit=0
    };

    internal static string BuildDaclSddl(string packageSid,bool packageWrite)
    {
        var package=new SecurityIdentifier(packageSid).Value;
        if(!package.StartsWith("S-1-15-2-",StringComparison.Ordinal))
            throw new InvalidDataException("AppContainer package SID required for private Git workspace");
        var packageMask=packageWrite?"0x001301bf":"GRGX";
        return "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;"+packageMask+";;;"+package+")(A;OICI;RC;;;S-1-3-4)";
    }

    private GitWorkspaceDescriptor(string packageSid,bool packageWrite)
    {
        var dacl=BuildDaclSddl(packageSid,packageWrite);
        expected=new RawSecurityDescriptor(dacl+"S:(ML;OICI;NW;;;LW)");
        if(!ConvertStringSecurityDescriptorToSecurityDescriptor(dacl,1,out descriptor,out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(),"Build private Git workspace DACL");
        if(!ConvertStringSecurityDescriptorToSecurityDescriptor("S:(ML;OICI;NW;;;LW)",1,out label,out _))
        {
            var error=Marshal.GetLastWin32Error();Dispose();
            throw new Win32Exception(error,"Build private Git workspace low label");
        }
    }

    internal static PathLease Create(PathLease parent,string leaf,string packageSid,bool packageWrite)
    {
        if(leaf is not ("git-project" or "git-control") || (leaf=="git-project")!=packageWrite)
            throw new InvalidDataException("Fixed private Git directory role required");
        parent.AssertHeld();
        var path=WindowsPathSeal.Child(parent.Path,leaf);
        using var grant=new GitWorkspaceDescriptor(packageSid,packageWrite);
        var attributes=grant.Attributes;
        if(!CreateDirectory(path,ref attributes))
            throw new Win32Exception(Marshal.GetLastWin32Error(),"Create private Git workspace directory");
        var lease=WindowsPathSeal.LockDirectory(path,PathPolicy.Source);
        try{grant.ApplyLowLabelAndVerify(path);return lease;}
        catch{lease.Dispose();throw;}
    }

    internal static void AssertPath(string path,string packageSid,bool packageWrite)
    {
        using var grant=new GitWorkspaceDescriptor(packageSid,packageWrite);
        using var handle=WindowsPathSeal.Open(path,true,false);
        grant.AssertApplied(handle);
    }

    private void ApplyLowLabelAndVerify(string path)
    {
        using var handle=CreateFile(path,0x000a0080u,1,IntPtr.Zero,3,0x02200000u,IntPtr.Zero);
        if(handle.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error(),"Open private Git directory for low label");
        WindowsPathSeal.VerifyObject(handle,path,true);
        if(!GetSecurityDescriptorSacl(label,out var present,out var sacl,out _) || !present || sacl==IntPtr.Zero)
            throw new InvalidOperationException("Private Git low-label descriptor missing");
        var status=SetSecurityInfo(handle,1,16,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,sacl);
        if(status!=0)throw new Win32Exception(unchecked((int)status),"Apply private Git low label");
        AssertApplied(handle);
    }

    private void AssertApplied(SafeFileHandle handle)
    {
        var status=GetSecurityInfo(handle,1,1|2|4|16,out _,out _,out _,out _,out var value);
        if(status!=0)throw new Win32Exception(unchecked((int)status),"Read private Git directory security");
        try
        {
            if(value==IntPtr.Zero)throw new InvalidDataException("Private Git security descriptor missing");
            var size=GetSecurityDescriptorLength(value);
            if(size is <20 or >65536)throw new InvalidDataException("Private Git security descriptor bounds");
            var bytes=new byte[checked((int)size)];Marshal.Copy(value,bytes,0,bytes.Length);
            var actual=new RawSecurityDescriptor(bytes,0);
            if(actual.Owner?.Value!=expected.Owner?.Value || actual.Group?.Value!=expected.Group?.Value ||
                !actual.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected) ||
                !Same(actual.DiscretionaryAcl,expected.DiscretionaryAcl) || !Same(actual.SystemAcl,expected.SystemAcl))
                throw new InvalidDataException("Private Git DACL/OWNER RIGHTS/low-label mismatch");
        }
        finally{if(value!=IntPtr.Zero)LocalFree(value);}
    }

    private static bool Same(RawAcl? left,RawAcl? right)
    {
        if(left is null || right is null)return left is null && right is null;
        if(left.BinaryLength!=right.BinaryLength)return false;
        var a=new byte[left.BinaryLength];var b=new byte[right.BinaryLength];
        left.GetBinaryForm(a,0);right.GetBinaryForm(b,0);return a.AsSpan().SequenceEqual(b);
    }

    public void Dispose()
    {
        if(descriptor!=IntPtr.Zero){LocalFree(descriptor);descriptor=IntPtr.Zero;}
        if(label!=IntPtr.Zero){LocalFree(label);label=IntPtr.Zero;}
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",EntryPoint="CreateDirectoryW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateDirectory(string path,ref KernelJobSeal.SecurityAttributes attributes);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll",EntryPoint="ConvertStringSecurityDescriptorToSecurityDescriptorW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint length);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorSacl(IntPtr descriptor,[MarshalAs(UnmanagedType.Bool)] out bool present,out IntPtr sacl,[MarshalAs(UnmanagedType.Bool)] out bool defaulted);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll",SetLastError=true)] private static extern uint GetSecurityInfo(SafeFileHandle handle,int objectType,uint securityInfo,
        out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll",SetLastError=true)] private static extern uint SetSecurityInfo(SafeFileHandle handle,int objectType,uint securityInfo,
        IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}