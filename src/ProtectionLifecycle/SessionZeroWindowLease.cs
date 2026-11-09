using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Runs inside the dedicated window owner process. The original creator still
// creates and hands off the suspended LPAC process. No window handles are inherited.
internal sealed class SessionZeroWindowLease : IDisposable
{
    private const int NotFound=2;
    private const uint CreateOnly=1,UserObjectFlags=1,UserObjectName=2,Visible=1;
    private const uint StationCreateAccess=0x0002000a,DesktopCreateAccess=0x00020083;
    private readonly SessionZeroWindowPolicy policy;
    private readonly StationHandle station;
    private readonly DesktopHandle desktop;

    private SessionZeroWindowLease(SessionZeroWindowPolicy policy,StationHandle station,DesktopHandle desktop)
    {this.policy=policy;this.station=station;this.desktop=desktop;}

    internal static SessionZeroWindowLease Create(OwnedJobIntent job,bool stationReadControl)
    {
        using var identity=WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        using var impersonating=WindowsIdentity.GetCurrent(ifImpersonating:true);
        if(impersonating is not null || identity.User?.IsWellKnown(WellKnownSidType.LocalSystemSid)!=true ||
            !ProcessIdToSessionId((uint)Environment.ProcessId,out var session) || session!=0)
            throw WfpNative.Contract("PrivateWindowOwnerMustBeSessionZeroSystem");
        var policy=new SessionZeroWindowPolicy(job,stationReadControl);
        var originalStation=GetProcessWindowStation();
        var originalDesktop=GetThreadDesktop(GetCurrentThreadId());
        if(originalStation==IntPtr.Zero || originalDesktop==IntPtr.Zero)
            throw Error("ReadWindowOwnerOriginalContext");
        if((ReadObjectFlags(originalStation).Flags&Visible)!=0)
            throw WfpNative.Contract("PrivateWindowOwnerRequiresNoninteractiveContext");
        StationHandle? station=null;
        DesktopHandle? desktop=null;
        try
        {
            Exception? creationFailure=null;
            try
            {
                using var stationSecurity=new CreationDescriptor(policy.Descriptor(station:true));
                var attributes=stationSecurity.Attributes;
                station=CreateWindowStation(policy.StationName,CreateOnly,StationCreateAccess,ref attributes);
                if(station.IsInvalid)throw Error("CreateFreshPrivateWindowStation");
                AssertObject(station,policy,stationObject:true);
                if(!SetProcessWindowStation(station.DangerousGetHandle()))throw Error("SelectPrivateWindowStationForCreation");
                using(var prior=OpenDesktop(SessionZeroWindowPolicy.DesktopName,0,false,0x1))
                {
                    if(!prior.IsInvalid || Marshal.GetLastWin32Error()!=NotFound)
                        throw WfpNative.Contract("PrivateDesktopNameNotConfirmedFresh");
                }
                using var desktopSecurity=new CreationDescriptor(policy.Descriptor(station:false));
                attributes=desktopSecurity.Attributes;
                desktop=CreateDesktop(SessionZeroWindowPolicy.DesktopName,IntPtr.Zero,IntPtr.Zero,0,DesktopCreateAccess,ref attributes);
                if(desktop.IsInvalid)throw Error("CreateFreshPrivateDesktop");
                AssertObject(desktop,policy,stationObject:false);
            }
            catch(Exception error){creationFailure=error;throw;}
            finally
            {
                try
                {
                    if(GetProcessWindowStation()!=originalStation && !SetProcessWindowStation(originalStation))
                        throw Error("RestoreWindowOwnerStation");
                    if(GetThreadDesktop(GetCurrentThreadId())!=originalDesktop && !SetThreadDesktop(originalDesktop))
                        throw Error("RestoreWindowOwnerDesktop");
                }
                catch(Exception restoreFailure) when(creationFailure is not null)
                {throw new AggregateException("Private window creation and context restoration both failed",creationFailure,restoreFailure);}
            }
            return new(policy,station,desktop);
        }
        catch(Exception failure)
        {
            desktop?.Dispose();
            station?.Dispose();
            if((desktop?.CloseError??0)!=0 || (station?.CloseError??0)!=0)
                throw new AggregateException("Private window creation and handle cleanup both failed",failure,
                    CloseFailure(desktop,station));
            throw;
        }
    }

    internal void CloseAndConfirmAbsent()
    {
        Dispose();
        if(desktop.CloseError!=0 || station.CloseError!=0)
            throw CloseFailure(desktop,station);
        using var remaining=OpenWindowStation(policy.StationName,false,0x2);
        if(!remaining.IsInvalid || Marshal.GetLastWin32Error()!=NotFound)
            throw WfpNative.Contract("PrivateWindowStationAbsenceUnconfirmed");
    }

    public void Dispose()
    {
        desktop.Dispose();
        station.Dispose();
    }

    private static void AssertObject(SafeHandle handle,SessionZeroWindowPolicy policy,bool stationObject)
    {
        var value=handle.DangerousGetHandle();
        var name=ReadObjectName(value);
        var flags=ReadObjectFlags(value);
        if(flags.Inheritable!=0 || (stationObject && (flags.Flags&Visible)!=0) ||
            !string.Equals(name,stationObject?policy.StationName:SessionZeroWindowPolicy.DesktopName,StringComparison.Ordinal))
            throw WfpNative.Contract("PrivateWindowObjectIdentityMismatch");
        var status=GetSecurityInfo(handle,7,0x17,out _,out _,out _,out _,out var native);
        try
        {
            if(status!=0)throw new Win32Exception(unchecked((int)status),"ReadPrivateWindowObjectDescriptor");
            if(native==IntPtr.Zero)throw WfpNative.Contract("PrivateWindowObjectDescriptorMissing");
            var sizeBytes=GetSecurityDescriptorLength(native);
            if(sizeBytes is <20 or >65536)throw WfpNative.Contract("PrivateWindowObjectDescriptorSizeRefused");
            var bytes=new byte[sizeBytes];
            Marshal.Copy(native,bytes,0,bytes.Length);
            policy.AssertDescriptor(stationObject,new RawSecurityDescriptor(bytes,0));
        }
        finally{if(native!=IntPtr.Zero)LocalFree(native);}
    }

    // Borrowed handles from the running workload. No name or handle leaves it.
    internal static void AssertCurrentPrivateDesktop(string jobId)
    {
        var target=SessionZeroWindowPolicy.DesktopPathForJob(jobId);
        var separator=target.IndexOf('\\');
        if(GetDesktopWindow()==IntPtr.Zero)throw Error("PrivateConsoleDesktopUnavailable");
        var station=GetProcessWindowStation();
        var desktop=GetThreadDesktop(GetCurrentThreadId());
        if(station==IntPtr.Zero || desktop==IntPtr.Zero || (ReadObjectFlags(station).Flags&Visible)!=0 ||
            !ReadObjectName(station).AsSpan().SequenceEqual(target.AsSpan(0,separator)) ||
            !string.Equals(ReadObjectName(desktop),SessionZeroWindowPolicy.DesktopName,StringComparison.Ordinal))
            throw WfpNative.Contract("PrivateConsoleDesktopMismatch");
    }

    private static string ReadObjectName(IntPtr handle)
    {
        var name=new StringBuilder(128);
        if(!GetObjectName(handle,UserObjectName,name,(uint)(name.Capacity*sizeof(char)),out var size))throw Error("ReadPrivateWindowObjectName");
        if(size!=(name.Length+1)*sizeof(char))throw WfpNative.Contract("PrivateWindowObjectNameSizeMismatch");
        return name.ToString();
    }

    private static ObjectFlags ReadObjectFlags(IntPtr handle)
    {
        if(!GetObjectFlags(handle,UserObjectFlags,out var flags,12,out var size))throw Error("ReadPrivateWindowObjectFlags");
        if(size!=12)throw WfpNative.Contract("PrivateWindowObjectFlagSizeMismatch");
        return flags;
    }

    private static Win32Exception CloseFailure(DesktopHandle? desktop,StationHandle? station)=>
        new(desktop is {CloseError:not 0}?desktop.CloseError:station?.CloseError??0,"ClosePrivateWindowObjects");

    private sealed class CreationDescriptor : IDisposable
    {
        private GCHandle pinned;
        internal CreationDescriptor(RawSecurityDescriptor descriptor)
        {
            var bytes=new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(bytes,0);
            pinned=GCHandle.Alloc(bytes,GCHandleType.Pinned);
        }
        internal KernelJobSeal.SecurityAttributes Attributes=>new(){Length=Marshal.SizeOf<KernelJobSeal.SecurityAttributes>(),
            Descriptor=pinned.AddrOfPinnedObject()};
        public void Dispose()=>pinned.Free();
    }

    private abstract class WindowHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        protected WindowHandle():base(true){}
        internal int CloseError {get;private set;}
        protected sealed override bool ReleaseHandle()
        {
            if(Close(handle))return true;
            var error=Marshal.GetLastWin32Error();
            CloseError=error==0?13:error;
            return false;
        }
        protected abstract bool Close(IntPtr value);
    }
    private sealed class StationHandle : WindowHandle
    {
        public StationHandle(){}
        protected override bool Close(IntPtr value)=>CloseWindowStation(value);
    }
    private sealed class DesktopHandle : WindowHandle
    {
        public DesktopHandle(){}
        protected override bool Close(IntPtr value)=>CloseDesktop(value);
    }

    private static Win32Exception Error(string stage)=>new(Marshal.GetLastWin32Error(),stage);
    [StructLayout(LayoutKind.Sequential)] private struct ObjectFlags {internal int Inheritable,Reserved;internal uint Flags;}
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool ProcessIdToSessionId(uint processId,out uint sessionId);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr value);
    [DllImport("user32.dll",SetLastError=true)] private static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll")] private static extern IntPtr GetDesktopWindow();
    [DllImport("user32.dll",SetLastError=true)] private static extern IntPtr GetThreadDesktop(uint threadId);
    [DllImport("user32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetProcessWindowStation(IntPtr station);
    [DllImport("user32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetThreadDesktop(IntPtr desktop);
    [DllImport("user32.dll",EntryPoint="CreateWindowStationW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern StationHandle CreateWindowStation(string name,uint flags,uint access,ref KernelJobSeal.SecurityAttributes attributes);
    [DllImport("user32.dll",EntryPoint="CreateDesktopW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern DesktopHandle CreateDesktop(string name,IntPtr device,IntPtr mode,uint flags,uint access,ref KernelJobSeal.SecurityAttributes attributes);
    [DllImport("user32.dll",EntryPoint="OpenWindowStationW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern StationHandle OpenWindowStation(string name,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint access);
    [DllImport("user32.dll",EntryPoint="OpenDesktopW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern DesktopHandle OpenDesktop(string name,uint flags,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint access);
    [DllImport("user32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CloseWindowStation(IntPtr station);
    [DllImport("user32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CloseDesktop(IntPtr desktop);
    [DllImport("user32.dll",EntryPoint="GetUserObjectInformationW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetObjectName(IntPtr handle,uint index,StringBuilder value,uint length,out uint needed);
    [DllImport("user32.dll",EntryPoint="GetUserObjectInformationW",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetObjectFlags(IntPtr handle,uint index,out ObjectFlags value,uint length,out uint needed);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr value);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityInfo(SafeHandle handle,int type,uint information,
        out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
}
