using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace ProtectionLifecycle;

// File-object ACL checks cannot be reused for a kernel Job. This deliberately
// supports only this product's three-ACE descriptor, not arbitrary job adoption.
internal static class KernelJobSeal
{
    internal const int OwnerRights=0x0002000f; // READ_CONTROL, ASSIGN, SET, QUERY, TERMINATE.
    private const string SystemSid="S-1-5-18",AdminsSid="S-1-5-32-544";
    internal sealed class Descriptor : IDisposable
    {
        private IntPtr value;
        internal Descriptor(CreationTag tag)
        {
            if(tag.Role!=CreationRole.OwnedJob)throw new InvalidDataException("Job creation tag required");
            var sddl="O:BAG:SYD:P(A;;0x0002000f;;;SY)(A;;0x0002000f;;;BA)(A;;RC;;;"+tag.Sid+")";
            if(!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl,1,out value,out _))throw Error("CreateJobDescriptor");
        }
        internal SecurityAttributes Attributes=>value==IntPtr.Zero?throw new ObjectDisposedException(nameof(Descriptor)):
            new(){Length=Marshal.SizeOf<SecurityAttributes>(),Descriptor=value,Inherit=0};
        public void Dispose(){if(value!=IntPtr.Zero){LocalFree(value);value=IntPtr.Zero;}}
    }
    // Used only for the new fixed suspended session root and its primary
    // thread. Default creator-token ACLs must not leave an ordinary same-user
    // process able to resume/inject into the root before full admission.
    internal sealed class SessionObjectDescriptor : IDisposable
    {
        private const int AllRights=0x001fffff;
        private IntPtr value;
        internal SessionObjectDescriptor()
        {
            if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:BAD:P(A;;0x001fffff;;;SY)(A;;0x001fffff;;;BA)",1,out value,out _))
                throw Error("CreateSuspendedSessionObjectDescriptor");
        }
        internal SecurityAttributes Attributes=>value==IntPtr.Zero?throw new ObjectDisposedException(nameof(SessionObjectDescriptor)):
            new(){Length=Marshal.SizeOf<SecurityAttributes>(),Descriptor=value,Inherit=0};
        internal static void AssertSeal(SafeHandle handle)
        {
            if(handle.IsClosed || handle.IsInvalid)throw new InvalidOperationException("Held session object required");
            var sized=GetKernelObjectSecurity(handle,1|4,null,0,out var needed);
            var error=Marshal.GetLastWin32Error();
            if(sized || error!=122 || needed is <20 or >65536)throw new InvalidDataException("SessionObjectDescriptorSizeUnconfirmed");
            var bytes=new byte[checked((int)needed)];
            if(!GetKernelObjectSecurity(handle,1|4,bytes,needed,out var actual))throw Error("ReadSuspendedSessionObjectDescriptor");
            if(actual!=needed)throw new InvalidDataException("SessionObjectDescriptorChanged");
            var descriptor=new RawSecurityDescriptor(bytes,0);
            if(descriptor.Owner?.Value!=AdminsSid || descriptor.DiscretionaryAcl is null || descriptor.DiscretionaryAcl.Count!=2 ||
                (descriptor.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0)throw new InvalidDataException("SessionObjectSecurityBroadened");
            var remaining=new HashSet<string>(new[]{SystemSid,AdminsSid},StringComparer.Ordinal);
            foreach(GenericAce entry in descriptor.DiscretionaryAcl)
                if(entry is not CommonAce ace || ace.IsCallback || ace.AceFlags!=AceFlags.None || ace.AceQualifier!=AceQualifier.AccessAllowed ||
                    ace.AccessMask!=AllRights || !remaining.Remove(ace.SecurityIdentifier.Value))throw new InvalidDataException("SessionObjectUnexpectedAccessGrant");
            if(remaining.Count!=0)throw new InvalidDataException("SessionObjectRequiredOwnerMissing");
        }
        public void Dispose(){if(value!=IntPtr.Zero){LocalFree(value);value=IntPtr.Zero;}}
    }
    internal static void AssertOwned(SafeJobHandle handle,CreationTag expected)
    {
        if(handle.IsInvalid || handle.IsClosed || expected.Role!=CreationRole.OwnedJob)throw new InvalidOperationException("Owned job handle required");
        // SE_KERNEL_OBJECT=6, not SE_FILE_OBJECT. The SID is metadata only.
        var status=GetSecurityInfo(handle,6,1|4,out _,out _,out var dacl,out _,out var descriptor);
        if(status!=0)throw new Win32Exception((int)status,"ReadJobSecurity");
        try
        {
            if(descriptor==IntPtr.Zero || dacl==IntPtr.Zero)throw new InvalidDataException("Job descriptor/DACL missing");
            var size=GetSecurityDescriptorLength(descriptor);if(size is 0 or >65536)throw new InvalidDataException("Job descriptor size refused");
            var bytes=new byte[checked((int)size)];Marshal.Copy(descriptor,bytes,0,bytes.Length);var security=new RawSecurityDescriptor(bytes,0);
            if(security.Owner is null || (security.Owner.Value!=SystemSid && security.Owner.Value!=AdminsSid) ||
                (security.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 || security.DiscretionaryAcl is null || security.DiscretionaryAcl.Count!=3)
                throw new InvalidDataException("Unowned or broadened job security");
            var required=new Dictionary<string,int>(StringComparer.Ordinal){{SystemSid,OwnerRights},{AdminsSid,OwnerRights},{expected.Sid,0x20000}};
            foreach(GenericAce ace in security.DiscretionaryAcl)
                if(ace is not CommonAce common || common.IsCallback || common.AceFlags!=AceFlags.None || common.AceQualifier!=AceQualifier.AccessAllowed ||
                    !required.Remove(common.SecurityIdentifier.Value,out var mask) || common.AccessMask!=mask)
                    throw new InvalidDataException("Unexpected job grant, tag or ACE");
            if(required.Count!=0)throw new InvalidDataException("Job creation identity missing");
        }
        finally{if(descriptor!=IntPtr.Zero)LocalFree(descriptor);}
    }
    private static Win32Exception Error(string stage){var result=new Win32Exception(Marshal.GetLastWin32Error());result.Data["Stage"]=stage;return result;}
    [StructLayout(LayoutKind.Sequential)] internal struct SecurityAttributes {internal int Length;internal IntPtr Descriptor;internal int Inherit;}
    [DllImport("advapi32.dll",EntryPoint="ConvertStringSecurityDescriptorToSecurityDescriptorW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint length);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityInfo(SafeJobHandle handle,int type,uint info,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetKernelObjectSecurity(SafeHandle handle,uint information,[Out] byte[]? descriptor,uint length,out uint needed);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}
