using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// The fixed Broker apphost can enter this role only through the SCM. No
// console fallback and no caller-controlled arguments or executable path.
internal static class SessionZeroCreatorService
{
    private static readonly ServiceMain Callback=Run;
    private static readonly ServiceControlHandler Control=(_,_,_,_)=>120; // ERROR_CALL_NOT_IMPLEMENTED.
    private static int exit=125;
    internal enum FailurePhase:uint {ReportStarting=1,VerifyToken,ResolveImage,SealProcess,ReportReady,OfflineProtocol}
    private const uint FailureTag=0xc5000000;

    internal static int Dispatch()
    {
        var table=new[]{new TableEntry{Name="",Main=Marshal.GetFunctionPointerForDelegate(Callback)},new TableEntry()};
        if(!StartServiceCtrlDispatcher(table))return Marshal.GetLastWin32Error()==1063?124:126;
        return Volatile.Read(ref exit);
    }

    private static void Run(uint argc,IntPtr argv)
    {
        if(argc!=1 || argv==IntPtr.Zero)return;
        var name=Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv));
        if(name is null)return;
        string jobId;
        try{jobId=JobIdFromServiceName(name);}catch(InvalidDataException){return;}
        var service=RegisterServiceCtrlHandlerEx(name,Control,IntPtr.Zero);
        if(service==IntPtr.Zero)return;
        var status=new Status{ServiceType=0x10,State=2,CheckPoint=1,WaitHint=10000}; // Own process, start pending.
        var phase=FailurePhase.ReportStarting;
        uint result=0;
        try
        {
            Publish();
            phase=FailurePhase.VerifyToken;
            _=SessionZeroCreatorClient.VerifyCurrentService(name);
            phase=FailurePhase.ResolveImage;
            _=AtomicChild.ResolveSessionZeroImage(FixedLayout.FromWindows(),Environment.ProcessPath);
            phase=FailurePhase.SealProcess;
            GrantOwnObservation();
            phase=FailurePhase.ReportReady;
            status.State=4;status.CheckPoint=0;status.WaitHint=0;
            Publish();
            phase=FailurePhase.OfflineProtocol;
            SessionZeroCreatorClient.RunOfflineCreator(jobId);
        }
        catch(Exception error)
        {
            result=EncodeFailure(phase,unchecked((uint)(error is Win32Exception native?native.NativeErrorCode:error.HResult)));
        }
        status.State=1;status.CheckPoint=0;status.WaitHint=0; // Stopped.
        status.Win32Code=result==0?0u:1066u;status.ServiceCode=result;
        if(SetServiceStatus(service,ref status) && result==0)Volatile.Write(ref exit,0);

        void Publish()
        {
            if(!SetServiceStatus(service,ref status))throw new Win32Exception(Marshal.GetLastWin32Error(),"SetCreatorServiceStatus");
        }
    }

    // SCM offers a single 32-bit service-specific field. Keep the phase and
    // exact Win32/common HRESULT values; explicitly mark an unencoded family.
    // This conveys diagnostics only and grants no cleanup or resume authority.
    internal static uint EncodeFailure(FailurePhase phase,uint code)
    {
        if(phase is <FailurePhase.ReportStarting or >FailurePhase.OfflineProtocol)
            throw new ArgumentOutOfRangeException(nameof(phase));
        if(code==0)code=13;
        var kind=(code&0xffff0000u) switch {0u=>0u,0x80130000u=>1u,0x80070000u=>2u,0x80000000u=>3u,_=>15u};
        return FailureTag|((uint)phase<<20)|(kind<<16)|(kind==15?0u:code&0xffffu);
    }

    internal static WfpFailure DescribeStopped(uint win32,uint specific)
    {
        if(win32!=1066)return new("CreatorServiceStoppedBeforeBinding",win32==0?13u:win32);
        var phase=(FailurePhase)((specific>>20)&15);
        var kind=(specific>>16)&15;
        if((specific&0xff000000)!=FailureTag || phase is <FailurePhase.ReportStarting or >FailurePhase.OfflineProtocol ||
            kind is >3 and not 15 || (kind==15 && (specific&0xffff)!=0))
            return new("CreatorServiceStoppedBeforeBinding",specific==0?13u:specific);
        var name="CreatorService"+phase;
        if(kind==15)return new(name+"CodeNotEncoded",specific);
        var prefix=kind switch {0u=>0u,1u=>0x80130000u,2u=>0x80070000u,_=>0x80000000u};
        var code=prefix|(specific&0xffff);
        return code==0?new("CreatorServiceStoppedBeforeBinding",specific):new(name,code);
    }

    internal static string JobIdFromServiceName(string name)
    {
        var prefix=SessionZeroCreatorChannel.ServicePrefix;
        if(!name.StartsWith(prefix,StringComparison.Ordinal))throw WfpNative.Contract("CreatorServiceNameInvalid");
        return Identifiers.Hex32(name[prefix.Length..]);
    }

    private static void GrantOwnObservation()
    {
        using var self=OpenProcess(0x00060000,false,(uint)Environment.ProcessId); // READ_CONTROL and WRITE_DAC, retained across sealing.
        var descriptor=KernelJobSeal.ReadOwnerDacl(self);
        if(descriptor.Owner?.IsWellKnown(WellKnownSidType.LocalServiceSid)!=true || descriptor.DiscretionaryAcl is null)
            throw WfpNative.Contract("CreatorServiceProcessDescriptorInvalid");
        var acl=CreateObserverDacl();
        KernelJobSeal.WriteProtectedDacl(self,acl);
        var actual=KernelJobSeal.ReadOwnerDacl(self);
        var wanted=new byte[acl.BinaryLength];acl.GetBinaryForm(wanted,0);
        var actualAcl=actual.DiscretionaryAcl??throw WfpNative.Contract("CreatorServiceProcessDaclMissing");
        var observed=new byte[actualAcl.BinaryLength];actualAcl.GetBinaryForm(observed,0);
        if(actual.Owner?.IsWellKnown(WellKnownSidType.LocalServiceSid)!=true || (actual.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 ||
            !wanted.AsSpan().SequenceEqual(observed))throw WfpNative.Contract("CreatorServiceObservationDaclDiffers");
    }

    // Keep SCM authority. Elevated Broker observers get only wait/query, and
    // other processes sharing the LocalService user cannot rewrite the DACL.
    internal static RawAcl CreateObserverDacl()=>new RawSecurityDescriptor(
        "D:P(D;;0x000c0000;;;S-1-3-4)(A;;0x001fffff;;;SY)(A;;0x00101000;;;BA)").DiscretionaryAcl!;

    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate void ServiceMain(uint argc,IntPtr argv);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint ServiceControlHandler(uint control,uint type,IntPtr data,IntPtr context);
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] private struct TableEntry {internal string? Name;internal IntPtr Main;}
    [StructLayout(LayoutKind.Sequential)] private struct Status {internal uint ServiceType,State,Controls,Win32Code,ServiceCode,CheckPoint,WaitHint;}
    [DllImport("advapi32.dll",EntryPoint="StartServiceCtrlDispatcherW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool StartServiceCtrlDispatcher([In] TableEntry[] table);
    [DllImport("advapi32.dll",EntryPoint="RegisterServiceCtrlHandlerExW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern IntPtr RegisterServiceCtrlHandlerEx(string name,ServiceControlHandler handler,IntPtr context);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetServiceStatus(IntPtr service,ref Status status);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]
    private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint pid);
}
