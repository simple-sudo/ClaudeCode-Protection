using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ProtectionLifecycle;

// File-object ACL checks cannot be reused for a kernel Job. Only the two
// registered descriptor shapes may be adopted by the Broker.
internal static class KernelJobSeal
{
    internal const int OwnerRights=0x0002000f; // READ_CONTROL, ASSIGN, SET, QUERY, TERMINATE.
    internal const int CreatorJobOwnerRights=OwnerRights|0x00040000; // Also WRITE_DAC for the one-shot grant.
    private const int CreatorRights=0x00020001; // READ_CONTROL and ASSIGN_PROCESS.
    private const string SystemSid="S-1-5-18",AdminsSid="S-1-5-32-544";
    internal sealed class Descriptor : IDisposable
    {
        private IntPtr value;
        internal Descriptor(OwnedJobIntent intent)
        {
            var ownerMask=intent.CreatorServiceSid is null?OwnerRights:CreatorJobOwnerRights;
            var sddl=$"O:BAG:SYD:P(A;;0x{ownerMask:X};;;SY)(A;;0x{ownerMask:X};;;BA)(A;;RC;;;{intent.Tag.Sid})";
            if(intent.CreatorServiceSid is not null)sddl+="S:(ML;;NW;;;ME)";
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
        private const string LocalServiceSid="S-1-5-19",OwnerRightsSid="S-1-3-4";
        private const int ImplicitOwnerRights=0x000c0000; // READ_CONTROL | WRITE_DAC.
        private IntPtr value;
        internal SessionObjectDescriptor()
        {
            if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:BAD:P(A;;0x001fffff;;;SY)(A;;0x001fffff;;;BA)",1,out value,out _))
                throw Error("CreateSuspendedSessionObjectDescriptor");
        }
        internal SecurityAttributes Attributes=>value==IntPtr.Zero?throw new ObjectDisposedException(nameof(SessionObjectDescriptor)):
            new(){Length=Marshal.SizeOf<SecurityAttributes>(),Descriptor=value,Inherit=0};
        internal static void AssertSeal(SafeHandle handle,bool localService=false)
        {
            if(handle.IsClosed || handle.IsInvalid)throw new InvalidOperationException("Held session object required");
            var sized=GetKernelObjectSecurity(handle,1|4,null,0,out var needed);
            var error=Marshal.GetLastWin32Error();
            if(sized || error!=122 || needed is <20 or >65536)throw new InvalidDataException("SessionObjectDescriptorSizeUnconfirmed");
            var bytes=new byte[checked((int)needed)];
            if(!GetKernelObjectSecurity(handle,1|4,bytes,needed,out var actual))throw Error("ReadSuspendedSessionObjectDescriptor");
            if(actual!=needed)throw new InvalidDataException("SessionObjectDescriptorChanged");
            AssertDescriptor(new RawSecurityDescriptor(bytes,0),localService);
        }
        internal static void AssertDescriptor(RawSecurityDescriptor descriptor,bool localService)
        {
            var acl=descriptor.DiscretionaryAcl;
            if(descriptor.Owner?.Value!=(localService?LocalServiceSid:AdminsSid) || acl is null || acl.Count!=(localService?3:2) ||
                (descriptor.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0)throw new InvalidDataException("SessionObjectSecurityBroadened");
            // Merely omitting LocalService from the allow list leaves the
            // object owner's implicit WRITE_DAC intact.
            if(localService && (acl[0] is not CommonAce deny || deny.IsCallback || deny.AceFlags!=AceFlags.None ||
                deny.AceQualifier!=AceQualifier.AccessDenied || deny.AccessMask!=ImplicitOwnerRights || deny.SecurityIdentifier.Value!=OwnerRightsSid))
                throw new InvalidDataException("SessionObjectOwnerRightsDenialMissing");
            var remaining=new HashSet<string>(new[]{SystemSid,AdminsSid},StringComparer.Ordinal);
            for(var index=localService?1:0;index<acl.Count;index++)
                if(acl[index] is not CommonAce ace || ace.IsCallback || ace.AceFlags!=AceFlags.None || ace.AceQualifier!=AceQualifier.AccessAllowed ||
                    ace.AccessMask!=AllRights || !remaining.Remove(ace.SecurityIdentifier.Value))throw new InvalidDataException("SessionObjectUnexpectedAccessGrant");
            if(remaining.Count!=0)throw new InvalidDataException("SessionObjectRequiredOwnerMissing");
        }
        public void Dispose(){if(value!=IntPtr.Zero){LocalFree(value);value=IntPtr.Zero;}}
    }
    internal static void AssertOwned(SafeJobHandle handle,OwnedJobIntent expected)
        =>_=AssertJobDescriptor(ReadJobDescriptor(handle,expected.CreatorServiceSid is not null),expected);
    internal static bool SetCreatorAccess(SafeJobHandle handle,OwnedJobIntent expected,bool grant)
    {
        var creator=new SecurityIdentifier(expected.CreatorServiceSid??throw new InvalidOperationException("Creator Job required"));
        var before=ReadJobDescriptor(handle,true);
        var granted=AssertJobDescriptor(before,expected);
        if(granted!=grant)
        {
            var acl=before.DiscretionaryAcl!;
            ChangeCreatorAce(acl,creator,grant);
            WriteProtectedDacl(handle,acl);
        }
        if(AssertJobDescriptor(ReadJobDescriptor(handle,true),expected)!=grant)throw new InvalidDataException("Creator Job DACL change unconfirmed");
        return granted;
    }
    internal static void ChangeCreatorAce(RawAcl acl,SecurityIdentifier creator,bool grant)
    {
        if(grant)acl.InsertAce(acl.Count,new CommonAce(AceFlags.None,AceQualifier.AccessAllowed,CreatorRights,creator,false,null));
        else
        {
            for(var index=0;index<acl.Count;index++)
                if(acl[index] is CommonAce ace && ace.SecurityIdentifier.Equals(creator) && ace.AccessMask==CreatorRights)
                {acl.RemoveAce(index);return;}
            throw new InvalidDataException("Creator Job grant missing");
        }
    }
    internal static void WriteProtectedDacl(SafeHandle handle,RawAcl acl)
    {
        var bytes=new byte[acl.BinaryLength];acl.GetBinaryForm(bytes,0);
        var status=SetSecurityInfo(handle,6,0x80000004,IntPtr.Zero,IntPtr.Zero,bytes,IntPtr.Zero);
        if(status!=0)throw new Win32Exception((int)status,"WriteCreatorJobDacl");
    }
    internal static RawSecurityDescriptor ReadJobDescriptor(SafeHandle handle,bool includeLabel)
    {
        if(handle.IsInvalid || handle.IsClosed)throw new InvalidOperationException("Owned job handle required");
        // Request the mandatory label separately from audit policy (READ_CONTROL).
        var info=includeLabel?0x15u:0x05u;
        var status=GetSecurityInfo(handle,6,info,out _,out _,out var dacl,out _,out var descriptor);
        if(status!=0)throw new Win32Exception((int)status,"ReadJobSecurity");
        try
        {
            if(descriptor==IntPtr.Zero || dacl==IntPtr.Zero)throw new InvalidDataException("Job descriptor/DACL missing");
            var size=GetSecurityDescriptorLength(descriptor);if(size is 0 or >65536)throw new InvalidDataException("Job descriptor size refused");
            var bytes=new byte[checked((int)size)];Marshal.Copy(descriptor,bytes,0,bytes.Length);
            return new RawSecurityDescriptor(bytes,0);
        }
        finally{if(descriptor!=IntPtr.Zero)LocalFree(descriptor);}
    }
    internal static bool AssertJobDescriptor(RawSecurityDescriptor security,OwnedJobIntent expected)
    {
        var ownerMask=expected.CreatorServiceSid is null?OwnerRights:CreatorJobOwnerRights;
        var required=new Dictionary<string,int>(StringComparer.Ordinal){{SystemSid,ownerMask},{AdminsSid,ownerMask},{expected.Tag.Sid,0x20000}};
        var granted=false;
        if(expected.CreatorServiceSid is { } creator)
        {
            granted=security.DiscretionaryAcl?.Count==4;
            if(granted)required.Add(creator,CreatorRights);
            if(security.SystemAcl is not {Count:1} labels || labels[0] is not CustomAce label || (byte)label.AceType!=0x11 ||
                label.AceFlags!=AceFlags.None || label.GetOpaque() is not {Length:16} policy ||
                BinaryPrimitives.ReadUInt32LittleEndian(policy)!=1 || new SecurityIdentifier(policy,4).Value!="S-1-16-8192")
                throw new InvalidDataException("Session zero job requires medium integrity no-write-up");
        }
        if(security.Owner?.Value is not (SystemSid or AdminsSid) || (security.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 ||
            security.DiscretionaryAcl is not { } grants || grants.Count!=required.Count)
            throw new InvalidDataException("Unowned or broadened job security");
        foreach(GenericAce ace in grants)
            if(ace is not CommonAce common || common.IsCallback || common.AceFlags!=AceFlags.None || common.AceQualifier!=AceQualifier.AccessAllowed ||
                !required.Remove(common.SecurityIdentifier.Value,out var mask) || common.AccessMask!=mask)
                throw new InvalidDataException("Unexpected job grant, tag or ACE");
        return granted;
    }
    private static Win32Exception Error(string stage){var result=new Win32Exception(Marshal.GetLastWin32Error());result.Data["Stage"]=stage;return result;}
    [StructLayout(LayoutKind.Sequential)] internal struct SecurityAttributes {internal int Length;internal IntPtr Descriptor;internal int Inherit;}
    [DllImport("advapi32.dll",EntryPoint="ConvertStringSecurityDescriptorToSecurityDescriptorW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint length);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityInfo(SafeHandle handle,int type,uint info,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DllImport("advapi32.dll",ExactSpelling=true)] private static extern uint SetSecurityInfo(SafeHandle handle,int type,uint info,IntPtr owner,IntPtr group,byte[] dacl,IntPtr sacl);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetKernelObjectSecurity(SafeHandle handle,uint information,[Out] byte[]? descriptor,uint length,out uint needed);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}
