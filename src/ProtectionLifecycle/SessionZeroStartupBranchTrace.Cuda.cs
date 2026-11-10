using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed partial class SessionZeroStartupBranchTrace
{
    // The observer uses native debug events and, for the reviewed image, the
    // root thread's hardware debug registers. Driver exceptions go to the child.
    internal sealed class CudaAccessTrace : IDisposable
    {
        private const uint AccessViolation=0xc0000005;
        private const uint UnloadDllEvent=7;
        private readonly FileStream driver=HoldCudaImage("nvcuda.dll",8*1024*1024,
            "B53D1E3E49B2D1BC33480243017AF6847E4809B7ACDD7C121EA294F05AFE6FD3");
        private readonly CudaInitializationTrace? initialization;
        private readonly string driverIdentity;
        private readonly uint imageSize;
        private long? mappedBase;
        private bool used,attached,terminal,detached;
        private Fault? firstChance,lastChance;

        internal sealed record Fault(string Access,string TargetAddressClass,string InstructionImage,uint? RelativeVirtualAddress)
        {
            public bool? MatchesObservedStoreDisplacement {get;init;}
            [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
            public bool? ExactImplementationImage {get;init;}
        }
        internal sealed record Evidence(bool Attached,bool ExitEventContinued,bool Detached,bool DriverMappingObserved,
            Fault? FirstChance,Fault? LastChance)
        {
            [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
            public CudaInitializationTrace.Evidence? Initialization {get;init;}
        }
        private bool driverMapped;

        internal CudaAccessTrace():this(false){}

        internal CudaAccessTrace(bool observeInitialization)
        {
            try
            {
                driverIdentity=WindowsPathSeal.Identity(driver.SafeFileHandle);
                using var pe=new PEReader(driver,PEStreamOptions.LeaveOpen);
                var size=pe.PEHeaders.PEHeader?.SizeOfImage??0;
                if(size<=0 || size>32*1024*1024)throw WfpNative.Contract("CudaTraceImageSizeRefused");
                imageSize=(uint)size;
                if(observeInitialization)initialization=new CudaInitializationTrace();
            }
            catch{driver.Dispose();throw;}
        }

        internal Evidence Snapshot()=>new(attached,terminal,detached,driverMapped,firstChance,lastChance)
            {Initialization=initialization?.Snapshot()};

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
            using var thread=initialization is null?null:OpenThread(0x10081a,false,tid);
            if(thread is not null && (thread.IsInvalid || GetProcessIdOfThread(thread)!=pid || WaitForSingleObject(thread,0)!=258))
                throw WfpNative.Contract("CudaTraceOriginalThreadRequired");
            using var context=thread is null?null:new Breakpoints(thread);
            if(!DebugActiveProcess(pid))throw WindowsPathSeal.Error("AttachCudaAccessTrace");
            attached=true;
            try
            {
                var elapsed=Stopwatch.StartNew();
                var attachBreakSeen=false;
                IntPtr debugProcess=IntPtr.Zero;
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
                        if(evt.Kind==CreateProcessEvent)debugProcess=evt.DebugProcess;
                        if(evt.Kind==LoadDllEvent && image is {IsInvalid:false})
                        {
                            var identity=WindowsPathSeal.Identity(image);
                            if(identity==driverIdentity)
                            {
                                if(evt.ModuleBase<0x10000 || mappedBase.HasValue)
                                    throw WfpNative.Contract("CudaTraceMappedDriverIdentityDiffers");
                                mappedBase=evt.ModuleBase;
                                driverMapped=true;
                            }
                            if(context is not null)initialization!.OnMapping(context,identity,evt.ModuleBase);
                        }
                        if(evt.Kind==UnloadDllEvent)
                        {
                            if(evt.File.ToInt64()==mappedBase)mappedBase=null;
                            if(context is not null)initialization!.OnUnmapping(context,evt.File.ToInt64());
                        }
                        if(evt.Kind==ExceptionEvent && evt.FirstChance==1 && evt.Code==Breakpoint &&
                            !attachBreakSeen && evt.Tid!=tid)
                        {
                            attachBreakSeen=true;
                            disposition=Continue;
                        }
                        if(evt.Kind==ExceptionEvent && evt.FirstChance==1 && evt.Code==SingleStep && evt.Tid==tid &&
                            context?.Take(evt.Address) is { } hit)
                        {
                            initialization!.Record(hit.Slot,hit.ReturnValue);
                            disposition=Continue;
                        }
                        if(evt.Kind==ExceptionEvent && evt.Code==AccessViolation)
                        {
                            var fault=DescribeFault(evt.Address,evt.NumberParameters,evt.AccessOperation,evt.AccessAddress,mappedBase,imageSize);
                            if(initialization?.ImplementationRva(evt.Address) is { } rva)
                                fault=fault with {InstructionImage="nvcuda64.dll",RelativeVirtualAddress=rva,ExactImplementationImage=true};
                            else if(fault.InstructionImage=="UNATTRIBUTED")
                                fault=ReadMappedInstruction(debugProcess,pid,evt.Address,fault);
                            if(fault is {Access:"WRITE",InstructionImage:"nvcuda64.dll",RelativeVirtualAddress:0x3a062e})
                                fault=fault with {MatchesObservedStoreDisplacement=evt.AccessAddress==0x293c};
                            if(evt.FirstChance==1)firstChance??=fault;
                            else lastChance=fault;
                        }
                    }
                    catch
                    {
                        if(evt.Pid==pid)context?.ClearWhileStopped();
                        throw;
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
                    try{context?.ClearBeforeDetach();}
                    finally
                    {
                        detached=DebugActiveProcessStop(pid);
                        if(!detached && WaitForSingleObject(process,0)!=0)throw WindowsPathSeal.Error("DetachCudaAccessTrace");
                    }
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

        private static Fault ReadMappedInstruction(IntPtr debugProcess,uint pid,long instruction,Fault fault)
        {
            const uint memImage=0x01000000;
            using var process=new SafeProcessHandle(debugProcess,ownsHandle:false); // Windows closes its debug-event handle.
            if(process.IsInvalid || GetProcessId(process)!=pid || instruction<0x10000)return fault;
            var address=new IntPtr(instruction);
            var size=(nuint)Marshal.SizeOf<MemoryRegion>();
            if(VirtualQueryEx(process,address,out var region,size)!=size || region.Type!=memImage)return fault;
            var offset=instruction-region.AllocationBase;
            if(offset is <0 or >uint.MaxValue)return fault;
            var path=new StringBuilder(1024);
            var length=GetMappedFileName(process,address,path,(uint)path.Capacity);
            if(length==0 || length>=path.Capacity)return fault;
            var leaf=Path.GetFileName(path.ToString()).ToLowerInvariant();
            if(!IsReviewedModuleLeaf(leaf))return fault;
            return fault with {InstructionImage=leaf,RelativeVirtualAddress=(uint)offset};
        }

        private static bool IsReviewedModuleLeaf(string leaf)
        {
            if(leaf is "ntdll.dll" or "kernelbase.dll" or "kernel32.dll" or "ucrtbase.dll" or "coreclr.dll" or
                "user32.dll" or "gdi32.dll" or "gdi32full.dll" or "win32u.dll" or "dxgi.dll" or "d3d12.dll")return true;
            if(!leaf.StartsWith("nv",StringComparison.Ordinal) || !leaf.EndsWith(".dll",StringComparison.Ordinal) ||
                leaf.Length is <7 or >48)return false;
            return leaf.All(c=>char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');
        }

        [StructLayout(LayoutKind.Explicit,Size=48)]
        private struct MemoryRegion
        {
            [FieldOffset(8)] internal long AllocationBase;
            [FieldOffset(40)] internal uint Type;
        }

        private static FileStream HoldCudaImage(string leaf,int maxBytes,string sha256)
        {
            var handle=WindowsPathSeal.OpenStartupTraceModule(leaf);
            try
            {
                var stream=new FileStream(handle,FileAccess.Read);
                if(stream.Length<=0 || stream.Length>maxBytes ||
                    Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream))!=sha256)
                {
                    stream.Dispose();
                    throw WfpNative.Contract("CudaTraceDriverBytesDiffer");
                }
                stream.Position=0;
                return stream;
            }
            catch{handle.Dispose();throw;}
        }

        public void Dispose(){initialization?.Dispose();driver.Dispose();}

        internal sealed class CudaInitializationTrace : IDisposable
        {
            // Return sites for the allocator, indirect callback and helper, followed by the store.
            private static readonly int[] Locations=[0x39ff31,0x39ffbe,0x3a04d8,0x3a062e];
            private readonly FileStream image=HoldCudaImage("nvcuda64.dll",64*1024*1024,
                "8AE9D817499BF3BF7DF7A91A3F57574335DCDE42AFF130F46C86C68F38B27521");
            private readonly string identity;
            private readonly uint size;
            private readonly bool?[] zero=new bool?[4];
            private long? mapping;
            private bool observed;

            internal sealed record Evidence(bool ExactImageMapped,bool? AllocatorReturnedNull,bool? CallbackReturnedZero,
                bool? HelperReturnedZero,bool? StoreBaseWasNull);

            internal CudaInitializationTrace()
            {
                try
                {
                    identity=WindowsPathSeal.Identity(image.SafeFileHandle);
                    using var pe=new PEReader(image,PEStreamOptions.LeaveOpen);
                    var imageSize=pe.PEHeaders.PEHeader?.SizeOfImage??0;
                    if(pe.PEHeaders.CoffHeader.Machine!=Machine.Amd64 || imageSize<=Locations[^1] || imageSize>64*1024*1024)
                        throw WfpNative.Contract("CudaInitializationTraceImageRefused");
                    size=(uint)imageSize;
                }
                catch{image.Dispose();throw;}
            }

            internal void OnMapping(Breakpoints context,string fileIdentity,long address)
            {
                if(fileIdentity!=identity)return;
                if(observed || address<0x10000)throw WfpNative.Contract("CudaInitializationTraceMappingDiffers");
                mapping=address;
                observed=true;
                for(var slot=0;slot<Locations.Length;slot++)context.Arm(slot,checked(address+Locations[slot]));
            }

            internal void OnUnmapping(Breakpoints context,long address)
            {
                if(address!=mapping)return;
                context.ClearWhileStopped();
                mapping=null;
            }

            internal void Record(int slot,long value)=>zero[slot]=slot is 1 or 2?unchecked((uint)value)==0:value==0;
            internal uint? ImplementationRva(long address)=>mapping is { } start && address>=start && (ulong)(address-start)<size
                ?(uint)(address-start):null;
            internal Evidence Snapshot()=>new(observed,zero[0],zero[1],zero[2],zero[3]);
            public void Dispose()=>image.Dispose();
        }

        [DllImport("kernel32.dll",ExactSpelling=true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll",ExactSpelling=true)]
        private static extern nuint VirtualQueryEx(SafeProcessHandle process,IntPtr address,out MemoryRegion info,nuint length);

        [DllImport("kernel32.dll",EntryPoint="K32GetMappedFileNameW",ExactSpelling=true,CharSet=CharSet.Unicode)]
        private static extern uint GetMappedFileName(SafeProcessHandle process,IntPtr address,StringBuilder path,uint size);
    }
}
