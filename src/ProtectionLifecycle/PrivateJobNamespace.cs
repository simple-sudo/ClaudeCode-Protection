using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Both boundary membership and an explicit DACL are required. A boundary alone
// does not restrict all OpenPrivateNamespace callers. There is no global-name
// fallback, and namespace-open failure never proves job/process absence.
internal sealed class PrivateJobNamespace : IDisposable
{
    private readonly ProtectedState state;
    private readonly SafeNamespaceHandle handle;
    private PrivateJobNamespace(ProtectedState state,SafeNamespaceHandle handle){this.state=state;this.handle=handle;}
    internal static PrivateJobNamespace CreateNew(ProtectedState state,OwnedJobIntent intent)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();if(intent.InstallationId!=state.InstallationId)throw new InvalidDataException("Foreign job namespace");
        using var boundary=new Boundary(intent);IntPtr descriptor=IntPtr.Zero;
        try
        {
            if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:BAG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)",1,out descriptor,out _))throw Error("CreatePrivateNamespaceDescriptor");
            var attributes=new KernelJobSeal.SecurityAttributes{Length=Marshal.SizeOf<KernelJobSeal.SecurityAttributes>(),Descriptor=descriptor,Inherit=0};
            var created=CreatePrivateNamespace(ref attributes,boundary.Value,intent.Alias);var error=Marshal.GetLastWin32Error();
            if(created.IsInvalid){created.Dispose();throw new Win32Exception(error,"CreateFreshPrivateJobNamespace");}
            return new(state,created);
        }
        finally{if(descriptor!=IntPtr.Zero)LocalFree(descriptor);}
    }
    internal static PrivateJobNamespace OpenExisting(ProtectedState state,OwnedJobIntent intent)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();if(intent.InstallationId!=state.InstallationId)throw new InvalidDataException("Foreign job namespace");
        using var boundary=new Boundary(intent);var opened=OpenPrivateNamespace(boundary.Value,intent.Alias);var error=Marshal.GetLastWin32Error();
        if(opened.IsInvalid)
        {
            opened.Dispose();
            // Creator exit can prevent reopening while existing object handles
            // remain usable. Do not recreate a namespace to get an empty query.
            throw new Win32Exception(error,"PrivateJobNamespaceUnavailable_NOT_A_ZERO_OBSERVATION");
        }
        return new(state,opened);
    }
    internal void AssertHeld(){state.AssertHeld();if(handle.IsClosed || handle.IsInvalid)throw new ObjectDisposedException(nameof(PrivateJobNamespace));}
    public void Dispose()=>handle.Dispose(); // No DESTROY flag or absence claim.
    private sealed class Boundary : IDisposable
    {
        internal IntPtr Value;
        internal Boundary(OwnedJobIntent intent)
        {
            Value=CreateBoundaryDescriptor("CPCBoundary."+Identifiers.Hex32(intent.InstallationId)+"."+Identifiers.Hex32(intent.JobId),0);
            if(Value==IntPtr.Zero)throw Error("CreateJobBoundary");
            var pointer=IntPtr.Zero;
            try
            {
                var sid=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);var bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);
                pointer=Marshal.AllocHGlobal(bytes.Length);Marshal.Copy(bytes,0,pointer,bytes.Length);
                if(!AddSIDToBoundaryDescriptor(ref Value,pointer))throw Error("RequireAdministratorBoundary");
            }
            catch{Dispose();throw;}finally{if(pointer!=IntPtr.Zero)Marshal.FreeHGlobal(pointer);}
        }
        public void Dispose(){if(Value!=IntPtr.Zero){DeleteBoundaryDescriptor(Value);Value=IntPtr.Zero;}}
    }
    private sealed class SafeNamespaceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeNamespaceHandle():base(true){}
        protected override bool ReleaseHandle()=>ClosePrivateNamespace(handle,0);
    }
    private static Win32Exception Error(string stage){var result=new Win32Exception(Marshal.GetLastWin32Error());result.Data["Stage"]=stage;return result;}
    [DllImport("kernel32.dll",EntryPoint="CreateBoundaryDescriptorW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern IntPtr CreateBoundaryDescriptor(string name,uint flags);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool AddSIDToBoundaryDescriptor(ref IntPtr boundary,IntPtr sid);
    [DllImport("kernel32.dll")] private static extern void DeleteBoundaryDescriptor(IntPtr boundary);
    [DllImport("kernel32.dll",EntryPoint="CreatePrivateNamespaceW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeNamespaceHandle CreatePrivateNamespace(ref KernelJobSeal.SecurityAttributes attributes,IntPtr boundary,string alias);
    [DllImport("kernel32.dll",EntryPoint="OpenPrivateNamespaceW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeNamespaceHandle OpenPrivateNamespace(IntPtr boundary,string alias);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.U1)] private static extern bool ClosePrivateNamespace(IntPtr handle,uint flags);
    [DllImport("advapi32.dll",EntryPoint="ConvertStringSecurityDescriptorToSecurityDescriptorW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint size);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}
