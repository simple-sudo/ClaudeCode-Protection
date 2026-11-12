using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Exact owner/group/DACL and mandatory-label descriptor for a newly created
// task workspace. Kept independently source-linkable so native recovery tests
// can exercise the production descriptor checks without importing all of
// SessionResources and its unrelated lifecycle dependencies.
internal sealed class WorkspaceDescriptor : IDisposable
    {
        private IntPtr descriptor,label;
        private readonly RawSecurityDescriptor expected;
        internal WorkspaceDescriptor(string humanSid,string packageSid,bool mutable)
        {
            _=new SecurityIdentifier(humanSid);_=new SecurityIdentifier(packageSid);
            // Git needs atomic lock-file replacement. DELETE is confined to
            // this freshly created task tree; no DELETE_CHILD/WRITE_DAC/OWNER
            // or existing host directory grant is added. Held input/root
            // handles still prohibit replacement of the owner's trust inputs.
            var mask=mutable?"0x001301bf":"0x001201bf";
            var text="O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;"+mask+";;;"+humanSid+")(A;OICI;"+mask+";;;"+packageSid+")";
            expected=new RawSecurityDescriptor(text+"S:(ML;OICI;NW;;;LW)");
            if(!ConvertStringSecurityDescriptorToSecurityDescriptor(text,1,out descriptor,out _))
                throw new WfpFailure("CreateWorkspaceDescriptor",unchecked((uint)Marshal.GetLastWin32Error()));
            if(!ConvertStringSecurityDescriptorToSecurityDescriptor("S:(ML;OICI;NW;;;LW)",1,out label,out _))
            {var error=Marshal.GetLastWin32Error();Dispose();throw new WfpFailure("CreateWorkspaceLowLabel",unchecked((uint)error));}
        }
        internal KernelJobSeal.SecurityAttributes Attributes=>new(){Length=Marshal.SizeOf<KernelJobSeal.SecurityAttributes>(),Descriptor=descriptor,Inherit=0};
        internal void ApplyLowLabelAndVerify(string path)
        {
            using var handle=CreateFile(path,0x000a0080,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero); // WRITE_OWNER, READ_CONTROL, attributes; no data write.
            if(handle.IsInvalid)throw new WfpFailure("OpenNewWorkspaceForLowLabel",unchecked((uint)Marshal.GetLastWin32Error()));
            WindowsPathSeal.VerifyObject(handle,path,true);
            if(!GetSecurityDescriptorSacl(label,out var present,out var sacl,out _) || !present || sacl==IntPtr.Zero)
                throw WfpNative.Contract("WorkspaceLowLabelDescriptorMissing");
            var status=SetSecurityInfo(handle,1,16,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,sacl); // LABEL only, never SACL_SECURITY_INFORMATION.
            if(status!=0)throw new WfpFailure("SetNewWorkspaceLowLabel",status);
            AssertApplied(handle);
        }
        internal void AssertApplied(SafeFileHandle handle,bool allowMissingLowLabel=false)
        {
            var status=GetSecurityInfo(handle,1,1|2|4|16,out _,out _,out _,out _,out var value);
            if(status!=0)throw new WfpFailure("ReadWorkspaceGrant",status);
            try
            {
                if(value==IntPtr.Zero)throw WfpNative.Contract("WorkspaceDescriptorMissing");
                var size=GetSecurityDescriptorLength(value);if(size is <20 or >65536)throw WfpNative.Contract("WorkspaceDescriptorBounds");
                var bytes=new byte[checked((int)size)];Marshal.Copy(value,bytes,0,bytes.Length);var actual=new RawSecurityDescriptor(bytes,0);
                var labelMatches=Same(actual.SystemAcl,expected.SystemAcl) || allowMissingLowLabel && actual.SystemAcl is null &&
                    (actual.ControlFlags&ControlFlags.SystemAclPresent)==0;
                if(actual.Owner?.Value!=expected.Owner?.Value || actual.Group?.Value!=expected.Group?.Value ||
                    (actual.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 ||
                    !Same(actual.DiscretionaryAcl,expected.DiscretionaryAcl) || !labelMatches)
                    throw WfpNative.Contract("WorkspaceGrantOrLowIntegrityMismatch");
            }
            finally{if(value!=IntPtr.Zero)LocalFree(value);}
        }
        private static bool Same(RawAcl? left,RawAcl? right)
        {
            if(left is null || right is null || left.Count!=right.Count)return false;
            for(var i=0;i<left.Count;i++)
            {
                var a=new byte[left[i].BinaryLength];left[i].GetBinaryForm(a,0);
                var b=new byte[right[i].BinaryLength];right[i].GetBinaryForm(b,0);
                if(!a.AsSpan().SequenceEqual(b))return false;
            }
            return true;
        }
        public void Dispose(){if(descriptor!=IntPtr.Zero){LocalFree(descriptor);descriptor=IntPtr.Zero;}if(label!=IntPtr.Zero){LocalFree(label);label=IntPtr.Zero;}}
        [DllImport("advapi32.dll",EntryPoint="ConvertStringSecurityDescriptorToSecurityDescriptorW",CharSet=CharSet.Unicode,SetLastError=true)]
        [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint length);
        [DllImport("advapi32.dll)] private static extern uint GetSecurityInfo(SafeFileHandle handle,int type,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
        [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("advapi32.dll",SetLastError=true)]
        [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetSecurityDescriptorSacl(IntPtr descriptor,[MarshalAs(UnmanagedType.Bool)] out bool present,out IntPtr sacl,[MarshalAs(UnmanagedType.Bool)] out bool defaulted);
        [DllImport("advapi32.dll")] private static extern uint SetSecurityInfo(SafeFileHandle handle,int type,uint information,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
        [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]
        private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr attributes,uint disposition,uint flags,IntPtr template);
        [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr value);
    }
