using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed partial class SessionZeroStartupBranchTrace
{
    // The observer consumes only native debug events for the held root. It
    // never reads process memory or handles a driver exception for the child.
    internal sealed class CudaAccessTrace : IDisposable
    {
        private const uint AccessViolation=0xc0000005;
        private const uint UnloadDllEvent=7;
        private readonly FileStream driver=HoldCudaImage();
        private readonly string driverIdentity;
        private readonly uint imageSize;
        private long? mappedBase;
        private bool used,attached,terminal,detached;
        private Fault? firstChance,lastChance;

        internal sealed record Fault(string Access,string TargetAddressClass,string InstructionImage,uint? RelativeVirtualAddress);
        internal sealed record Evidence(bool Attached,bool ExitEventContinued,bool Detached,bool DriverMappingObserved,
            Fault? FirstChance,Fault? LastChance);
        private bool driverMapped;

        internal CudaAccessTrace()
        {
            try
            {
                driverIdentity=WindowsPathSeal.Identity(driver.SafeFileHandle);
                using var pe=new PEReader(driver,PEStreamOptions.LeaveOpen);
                var size=pe.PEHeaders.PEHeader?.SizeOfImage??0;
                if(size<=0 || size>32*1024*1024)throw WfpNative.Contract("CudaTraceImageSizeRefused");
                imageSize=(uint)size;
            }
            catch{driver.Dispose();throw;}
        }

        internal Evidence Snapshot()=>new(attached,terminal,detached,driverMapped,firstChance,lastChance);

        internal static void WaitForObserver()
        {
            var elapsed=Stopwatch.StartNew();
            while(!IsDebuggerPresent())
            {
                if(elapsed.ElapsedMilliseconds>=2000)throw WfpNative.Contract("CudaAccessTraceObserverMissing");
                Thread.Sleep(5);
            }
        }

        internal void Observe(SafeProcessHandle process,uint pid,uint tid,Action assertHealthy)
        {
            if(!Environment.Is64BitProcess || used || pid==0 || tid==0 || GetProcessId(process)!=pid ||
                WaitForSingleObject(process,0)!=258)throw WfpNative.Contract("CudaTraceOriginalRootRequired");
            used=true;
            assertHealthy();
            if(!DebugActiveProcess(pid))throw WindowsPathSeal.Error("AttachCudaAccessTrace");
            attached=true;
            try
            {
                var elapsed=Stopwatch.StartNew();
                var attachBreakSeen=false;
                for(int count=0;count<256 && elapsed.ElapsedMilliseconds<6500;)
                {
                    assertHealthy();
                    if(!WaitForDebugEventEx(out var evt,50))
                    {
                        if(Marshal.GetLastWin32Error()==121)continue;
                        throw WindowsPathSeal.Error("WaitCudaAccessTrace");
                    }
                    count++;
                    using var image=evt.Kind is CreateProcessEvent or LoadDllEvent?new SafeFileHandle(evt.File,true):null;
                    var disposition=evt.Kind==ExceptionEvent?ExceptionNotHandled:Continue;
                    try
                    {
                        if(evt.Pid!=pid)throw WfpNative.Contract("CudaTraceEventProcessDiffers");
                        if(evt.Kind==LoadDllEvent && image is {IsInvalid:false} && WindowsPathSeal.Identity(image)==driverIdentity)
                        {
                            if(evt.ModuleBase<0x10000 || mappedBase.HasValue)
                                throw WfpNative.Contract("CudaTraceMappedDriverIdentityDiffers");
                            mappedBase=evt.ModuleBase;
                            driverMapped=true;
                        }
                        if(evt.Kind==UnloadDllEvent && evt.File.ToInt64()==mappedBase)mappedBase=null;
                        if(evt.Kind==ExceptionEvent && evt.FirstChance==1 && evt.Code==Breakpoint &&
                            !attachBreakSeen && evt.Tid!=tid)
                        {
                            attachBreakSeen=true;
                            disposition=Continue;
                        }
                        if(evt.Kind==ExceptionEvent && evt.Code==AccessViolation)
                        {
                            var fault=DescribeFault(evt.Address,evt.NumberParameters,evt.AccessOperation,evt.AccessAddress,mappedBase,imageSize);
                            if(evt.FirstChance==1)firstChance??=fault;
                            else lastChance=fault;
                        }
                    }
                    finally
                    {
                        if(!ContinueDebugEvent(evt.Pid,evt.Tid,disposition))throw WindowsPathSeal.Error("ContinueCudaAccessTrace");
                    }
                    if(evt.Kind==ExitProcessEvent){terminal=true;return;}
                }
                throw new TimeoutException("CudaAccessTraceExitUnavailable");
            }
            finally
            {
                if(!terminal)
                {
                    detached=DebugActiveProcessStop(pid);
                    if(!detached && WaitForSingleObject(process,0)!=0)throw WindowsPathSeal.Error("DetachCudaAccessTrace");
                }
            }
        }

        internal static Fault DescribeFault(long instruction,uint parameters,ulong operation,ulong target,long? imageBase,uint size)
        {
            var access=parameters is >=2 and <=15?operation switch {0=>"READ",1=>"WRITE",8=>"EXECUTE",_=>"UNKNOWN"}:"UNKNOWN";
            var address=parameters is >=2 and <=15?target switch {0=>"NULL",<0x10000=>"LOW_ADDRESS",_=>"OTHER_ADDRESS"}:"UNKNOWN";
            uint? rva=imageBase is { } start && instruction>=start && (ulong)(instruction-start)<size?
                (uint)(instruction-start):null;
            return new(access,address,rva.HasValue?"PINNED_NVCUDA":"UNATTRIBUTED",rva);
        }

        private static FileStream HoldCudaImage()
        {
            var handle=WindowsPathSeal.OpenStartupTraceModule("nvcuda.dll");
            try
            {
                var stream=new FileStream(handle,FileAccess.Read);
                if(stream.Length is <=0 or >8*1024*1024 ||
                    Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream))!=
                    "B53D1E3E49B2D1BC33480243017AF6847E4809B7ACDD7C121EA294F05AFE6FD3")
                {
                    stream.Dispose();
                    throw WfpNative.Contract("CudaTraceDriverBytesDiffer");
                }
                stream.Position=0;
                return stream;
            }
            catch{handle.Dispose();throw;}
        }

        public void Dispose()=>driver.Dispose();

        [DllImport("kernel32.dll",ExactSpelling=true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsDebuggerPresent();
    }
}
