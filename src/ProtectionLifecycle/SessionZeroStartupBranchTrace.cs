using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// One diagnostic, only on the original fixed startup witness after admission.
// The file pins bind the x64 RVAs to the exact System32 images under observation.
internal sealed partial class SessionZeroStartupBranchTrace : IDisposable
{
    private const uint ExceptionEvent=1,CreateProcessEvent=3,ExitProcessEvent=5,LoadDllEvent=6;
    private const uint Continue=0x10002,ExceptionNotHandled=0x80010001;
    private const uint Breakpoint=0x80000003,SingleStep=0x80000004;
    private readonly FileStream user32,gdi;
    private readonly string user32Identity,gdiIdentity;
    private bool attempted,attached,terminal,detached;
    private bool user32Mapped,gdiMapped;
    private uint? csrStatus,gdiStatus,failureValue;
    private bool? gdiInit2ReturnedNull;

    internal sealed record Evidence(bool Attached,bool ExitEventContinued,bool Detached,bool User32Mapped,bool Gdi32FullMapped,
        uint? CsrStatus,uint? GdiStatus,uint? FailureValue,bool? GdiInit2ReturnedNull);
    internal Evidence Snapshot()=>new(attached,terminal,detached,user32Mapped,gdiMapped,csrStatus,gdiStatus,failureValue,gdiInit2ReturnedNull);
    internal static FileStream HoldWindowQueryImage()=>Hold("win32u.dll","8C623A46434E33D2B5AA7CBAFF9FB2BF30B51DE4F57C4717334F07CA9342A361");

    internal SessionZeroStartupBranchTrace()
    {
        if(RuntimeInformation.ProcessArchitecture!=Architecture.X64)
            throw new PlatformNotSupportedException("Startup trace requires native x64");
        user32=Hold("user32.dll","6FCD82185566DB70CA0A7BC5CF08FBE448D407928990FD58EEC32C06B240B1BC");
        try
        {
            user32Identity=WindowsPathSeal.Identity(user32.SafeFileHandle);
            gdi=Hold("gdi32full.dll","6E7D2B41054202648D161684B7D4B76731A25E72B4C06E805A79A3F8A960BE74");
            try{gdiIdentity=WindowsPathSeal.Identity(gdi.SafeFileHandle);}
            catch{gdi.Dispose();throw;}
        }
        catch{user32.Dispose();throw;}
    }

    private static FileStream Hold(string leaf,string hash)
    {
        var handle=WindowsPathSeal.OpenStartupTraceModule(leaf);
        try
        {
            var stream=new FileStream(handle,FileAccess.Read);
            if(stream.Length is <=0 or >4*1024*1024 || Convert.ToHexString(SHA256.HashData(stream))!=hash)
            {stream.Dispose();throw WfpNative.Contract("StartupTraceSystemImageChanged");}
            return stream;
        }
        catch{handle.Dispose();throw;}
    }

    // A single synchronous call owns both attachment and every debug event.
    // It never opens an unrelated process or changes code, token or loader flags.
    internal void Observe(SafeProcessHandle process,uint pid,uint tid,Action assertHealthy)
    {
        if(attempted || GetProcessId(process)!=pid || pid==0 || tid==0)
            throw WfpNative.Contract("StartupTraceOriginalProcessRequired");
        attempted=true;
        // GET_CONTEXT | SET_CONTEXT | SUSPEND_RESUME | QUERY_LIMITED_INFORMATION | SYNCHRONIZE
        using var thread=OpenThread(0x10081a,false,tid);
        if(thread.IsInvalid)throw WindowsPathSeal.Error("OpenStartupTracePrimaryThread");
        if(GetProcessIdOfThread(thread)!=pid || WaitForSingleObject(thread,0)!=258 || WaitForSingleObject(process,0)!=258)
            throw WfpNative.Contract("StartupTraceOriginalThreadRequired");
        assertHealthy();
        using var context=new Breakpoints(thread);
        if(!DebugActiveProcess(pid))throw WindowsPathSeal.Error("AttachStartupTrace");
        attached=true;
        try
        {
            var clock=Stopwatch.StartNew();
            long nextCheck=0;
            var attachBreakSeen=false;
            for(var events=0;events<192 && clock.ElapsedMilliseconds<7000;)
            {
                if(clock.ElapsedMilliseconds>=nextCheck){assertHealthy();nextCheck=clock.ElapsedMilliseconds+100;}
                if(!WaitForDebugEventEx(out var evt,50))
                {
                    if(Marshal.GetLastWin32Error()==121)continue;
                    throw WindowsPathSeal.Error("WaitStartupTraceEvent");
                }
                events++;
                using var image=evt.Kind is CreateProcessEvent or LoadDllEvent?new SafeFileHandle(evt.File,true):null;
                var disposition=evt.Kind==ExceptionEvent?ExceptionNotHandled:Continue;
                try
                {
                    if(evt.Pid!=pid)throw WfpNative.Contract("StartupTraceEventProcessDiffers");
                    if(evt.Kind==LoadDllEvent && image is {IsInvalid:false})
                    {
                        var identity=WindowsPathSeal.Identity(image);
                        if(!user32Mapped && identity==user32Identity)
                        {
                            RequirePrimaryMapping();
                            assertHealthy();
                            context.Arm(0,evt.ModuleBase+0x6c8aa);
                            context.Arm(1,evt.ModuleBase+0x6cfb6);
                            context.Arm(2,evt.ModuleBase+0x6cfc5);
                            user32Mapped=true;
                        }
                        if(!gdiMapped && identity==gdiIdentity)
                        {
                            RequirePrimaryMapping();
                            assertHealthy();
                            context.Arm(3,evt.ModuleBase+0x89ffa);
                            gdiMapped=true;
                        }
                    }
                    if(evt.Kind==ExceptionEvent && evt.FirstChance==1)
                    {
                        if(!attachBreakSeen && evt.Code==Breakpoint && evt.Tid!=tid)
                        {attachBreakSeen=true;disposition=Continue;}
                        if(evt.Code==SingleStep && evt.Tid==tid && context.Take(evt.Address) is { } hit)
                        {
                            switch(hit.Slot)
                            {
                                case 0:csrStatus=unchecked((uint)hit.ReturnValue);break;
                                case 1:gdiStatus=unchecked((uint)hit.ReturnValue);break;
                                case 2:failureValue=unchecked((uint)hit.ReturnValue);break;
                                case 3:gdiInit2ReturnedNull=hit.ReturnValue==0;break;
                            }
                            disposition=Continue;
                        }
                    }
                    void RequirePrimaryMapping()
                    {
                        if(evt.Tid!=tid || evt.ModuleBase<0x10000)throw WfpNative.Contract("StartupTraceModuleThreadDiffers");
                    }
                }
                catch
                {
                    if(evt.Pid==pid)context.ClearWhileStopped();
                    throw;
                }
                finally
                {
                    if(!ContinueDebugEvent(evt.Pid,evt.Tid,disposition))throw WindowsPathSeal.Error("ContinueStartupTraceEvent");
                }
                if(evt.Kind==ExitProcessEvent){terminal=true;return;}
            }
            throw new TimeoutException("Startup trace exit event unavailable");
        }
        finally
        {
            if(!terminal)
            {
                try{context.ClearBeforeDetach();}
                finally
                {
                    detached=DebugActiveProcessStop(pid);
                    if(!detached)
                    {
                        var error=WindowsPathSeal.Error("DetachStartupTrace");
                        if(WaitForSingleObject(process,0)!=0)throw error;
                    }
                }
            }
        }
    }

    public void Dispose(){gdi.Dispose();user32.Dispose();}

    // x64 CONTEXT uses 16-byte alignment. Only the debug register portion
    // is written. Returned instruction and accumulator values are read only.
    internal sealed class Breakpoints(SafeWaitHandle thread) : IDisposable
    {
        private const int ContextFlags=48,Dr0=72,Dr6=104,Dr7=112,Rax=120,Rip=248;
        private const int DebugRegisters=0x100010,ControlAndInteger=3;
        private readonly nint storage=Marshal.AllocHGlobal(1232+15);
        private readonly long[] locations=new long[4];
        private nint Buffer=>(storage+15)&~(nint)15;
        private long enabled;

        internal void Arm(int slot,long address)
        {
            Read();
            var flags=Marshal.ReadInt64(Buffer,Dr7);
            if((flags&0xff)!=enabled || (enabled&(1L<<(slot*2)))!=0)
                throw WfpNative.Contract("StartupTraceDebugRegistersAlreadyInUse");
            locations[slot]=address;
            Marshal.WriteInt64(Buffer,Dr0+slot*8,address);
            var next=enabled|(1L<<(slot*2));
            Marshal.WriteInt64(Buffer,Dr7,(flags&~((0xfL<<(16+slot*4))|0xff))|next);
            Write();
            enabled=next;
        }

        internal (int Slot,long ReturnValue)? Take(long address)
        {
            var slot=Array.IndexOf(locations,address);
            if(slot<0 || (enabled&(1L<<(slot*2)))==0)return null;
            Read();
            if(Marshal.ReadInt64(Buffer,Rip)!=address || (Marshal.ReadInt64(Buffer,Dr6)&15)!=(1L<<slot))
                throw WfpNative.Contract("StartupTraceBreakpointIdentityDiffers");
            var value=Marshal.ReadInt64(Buffer,Rax);
            var next=enabled&~(1L<<(slot*2));
            Marshal.WriteInt64(Buffer,Dr6,0);
            Marshal.WriteInt64(Buffer,Dr7,(Marshal.ReadInt64(Buffer,Dr7)&~0xffL)|next);
            Write();
            enabled=next;
            return(slot,value);
        }

        internal void ClearBeforeDetach()
        {
            if(enabled==0 || WaitForSingleObject(thread,0)==0)return;
            if(SuspendThread(thread)==uint.MaxValue)throw WindowsPathSeal.Error("SuspendStartupTraceForDetach");
            try{ClearWhileStopped();}
            finally{if(ResumeThread(thread)==uint.MaxValue)throw WindowsPathSeal.Error("RestoreStartupTraceSuspendCount");}
        }

        internal void ClearWhileStopped()
        {
            if(enabled==0 || WaitForSingleObject(thread,0)==0)return;
            Read();
            Marshal.WriteInt64(Buffer,Dr6,0);
            Marshal.WriteInt64(Buffer,Dr7,Marshal.ReadInt64(Buffer,Dr7)&~enabled);
            Write();
            enabled=0;
        }

        private void Read()
        {
            Marshal.WriteInt32(Buffer,ContextFlags,DebugRegisters|ControlAndInteger);
            if(!GetThreadContext(thread,Buffer))throw WindowsPathSeal.Error("ReadStartupTraceContext");
        }
        private void Write()
        {
            Marshal.WriteInt32(Buffer,ContextFlags,DebugRegisters);
            if(!SetThreadContext(thread,Buffer))throw WindowsPathSeal.Error("WriteStartupTraceDebugRegisters");
        }
        public void Dispose()=>Marshal.FreeHGlobal(storage);
    }

    [StructLayout(LayoutKind.Explicit,Size=176)]
    private struct DebugEvent
    {
        [FieldOffset(0)] internal uint Kind;
        [FieldOffset(4)] internal uint Pid;
        [FieldOffset(8)] internal uint Tid;
        [FieldOffset(16)] internal IntPtr File;
        [FieldOffset(16)] internal uint Code;
        [FieldOffset(24)] internal long ModuleBase;
        [FieldOffset(24)] internal IntPtr DebugProcess;
        [FieldOffset(32)] internal long Address;
        [FieldOffset(40)] internal uint NumberParameters;
        [FieldOffset(48)] internal ulong AccessOperation;
        [FieldOffset(56)] internal ulong AccessAddress;
        [FieldOffset(168)] internal uint FirstChance;
    }

    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint GetProcessId(SafeProcessHandle process);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint GetProcessIdOfThread(SafeWaitHandle thread);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeWaitHandle OpenThread(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint tid);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint WaitForSingleObject(SafeHandle handle,uint timeout);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool DebugActiveProcess(uint pid);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool DebugActiveProcessStop(uint pid);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool WaitForDebugEventEx(out DebugEvent evt,uint timeout);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ContinueDebugEvent(uint pid,uint tid,uint disposition);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetThreadContext(SafeWaitHandle thread,nint context);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetThreadContext(SafeWaitHandle thread,nint context);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint SuspendThread(SafeWaitHandle thread);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint ResumeThread(SafeWaitHandle thread);
}
