using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record GpuProbePlan(string Nonce)
{
    internal void Validate()=>_=Identifiers.Hex32(Nonce);
}
internal sealed record CudaStep(string Stage,int Result);
internal sealed record GpuChildReport(int SchemaVersion,int Pid,string Nonce,string Scope,int? DriverVersion,string? Device,
    int AllocatedBytes,int Elements,string? ResultSHA256,bool ComputeMatched,bool ResourceCleanupSucceeded,CudaStep[] Steps,string? FailureType);

// Fixed 1 KiB, 256-element integer kernel. No models, files, network, external
// compiler, supplied PTX, device-policy changes or CPU fallback. This tests only
// this installed driver API workload; PyTorch/toolchain compatibility is separate.
internal static class GpuQualification
{
    internal const string LpacScope="LPAC_LOW_ZERO_CAPABILITIES";
    private const int Count=256,Bytes=Count*4;
    private const string Kernel="""
        .version 7.0
        .target sm_75
        .address_size 64
        .visible .entry cpc_add7(.param .u64 data)
        {
            .reg .pred %p;
            .reg .b32 %r<4>;
            .reg .b64 %rd<4>;
            mov.u32 %r1, %tid.x;
            setp.ge.u32 %p, %r1, 256;
            @%p bra DONE;
            ld.param.u64 %rd1, [data];
            mul.wide.u32 %rd2, %r1, 4;
            add.s64 %rd3, %rd1, %rd2;
            ld.global.u32 %r2, [%rd3];
            add.u32 %r3, %r2, 7;
            st.global.u32 [%rd3], %r3;
        DONE:
            ret;
        }
        """;
    internal static GpuChildReport Compute(GpuProbePlan plan,string scope)
    {
        plan.Validate();var steps=new List<CudaStep>();IntPtr context=IntPtr.Zero,module=IntPtr.Zero,host=IntPtr.Zero,arg=IntPtr.Zero,args=IntPtr.Zero,ptx=IntPtr.Zero;
        ulong deviceMemory=0;int? driver=null;string? deviceName=null,hash=null,failure=null;var allocated=0;var matched=false;var clean=true;
        var previousCache=Environment.GetEnvironmentVariable("CUDA_CACHE_DISABLE");
        try
        {
            Environment.SetEnvironmentVariable("CUDA_CACHE_DISABLE","1");
            Check("cuInit",Cuda.Init(0));Check("cuDriverGetVersion",Cuda.DriverVersion(out var version));driver=version;
            Check("cuDeviceGetCount",Cuda.DeviceCount(out var count));if(count<1)throw new InvalidOperationException("NoCudaDevice");
            Check("cuDeviceGet",Cuda.DeviceGet(out var device,0));var name=new StringBuilder(128);Check("cuDeviceGetName",Cuda.DeviceName(name,128,device));deviceName=name.ToString();
            Check("cuCtxCreate_v2",Cuda.ContextCreate(out context,0,device));Check("cuMemAlloc_v2",Cuda.Allocate(out deviceMemory,(nuint)Bytes));allocated=Bytes;
            host=Marshal.AllocHGlobal(Bytes);var input=Enumerable.Range(0,Count).Select(i=>i*3).ToArray();Marshal.Copy(input,0,host,Count);
            Check("cuMemcpyHtoD_v2",Cuda.CopyToDevice(deviceMemory,host,(nuint)Bytes));
            ptx=Marshal.StringToHGlobalAnsi(Kernel);Check("cuModuleLoadData",Cuda.ModuleLoad(out module,ptx));
            Check("cuModuleGetFunction",Cuda.Function(out var function,module,"cpc_add7"));
            arg=Marshal.AllocHGlobal(8);Marshal.WriteInt64(arg,unchecked((long)deviceMemory));args=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(args,arg);
            Check("cuLaunchKernel",Cuda.Launch(function,1,1,1,Count,1,1,0,IntPtr.Zero,args,IntPtr.Zero));
            Check("cuCtxSynchronize",Cuda.Synchronize());Check("cuMemcpyDtoH_v2",Cuda.CopyFromDevice(host,deviceMemory,(nuint)Bytes));
            var output=new int[Count];Marshal.Copy(host,output,0,Count);matched=output.Select((v,i)=>v==input[i]+7).All(v=>v);
            var result=new byte[Bytes];Buffer.BlockCopy(output,0,result,0,Bytes);hash=Convert.ToHexString(SHA256.HashData(result));
            if(!matched)throw new InvalidDataException("CudaResultMismatch");
        }
        catch(Exception ex){failure=ex.GetType().Name;}
        finally
        {
            // Continue every exact owned cleanup even after one driver error.
            if(module!=IntPtr.Zero)Release("cuModuleUnload",()=>Cuda.ModuleUnload(module));
            if(deviceMemory!=0)Release("cuMemFree_v2",()=>Cuda.Free(deviceMemory));
            if(context!=IntPtr.Zero)Release("cuCtxDestroy_v2",()=>Cuda.ContextDestroy(context));
            foreach(var pointer in new[]{host,arg,args,ptx})if(pointer!=IntPtr.Zero)Marshal.FreeHGlobal(pointer);
            Environment.SetEnvironmentVariable("CUDA_CACHE_DISABLE",previousCache);
        }
        return new(1,Environment.ProcessId,plan.Nonce,scope,driver,deviceName,allocated,Count,hash,matched,clean,steps.ToArray(),failure);
        void Check(string stage,int code){steps.Add(new(stage,code));if(code!=0)throw new InvalidOperationException("CudaCallFailed");}
        void Release(string stage,Func<int> call)
        {try{var code=call();steps.Add(new(stage,code));if(code!=0)clean=false;}catch(Exception ex){clean=false;failure??=ex.GetType().Name;}}
    }
    internal static bool Qualified(GpuChildReport report)=>report.ComputeMatched && report.ResourceCleanupSucceeded && report.FailureType is null &&
        report.DriverVersion is >0 && report.Device is {Length:>0 and <=127} && !report.Device.Any(char.IsControl) &&
        report.AllocatedBytes==Bytes && report.Elements==Count && report.ResultSHA256==ExpectedHash && report.Steps is {Length:16} && report.Steps.All(s=>s is {Result:0}) &&
        report.Steps.Select(s=>s.Stage).SequenceEqual(new[]{"cuInit","cuDriverGetVersion","cuDeviceGetCount","cuDeviceGet","cuDeviceGetName","cuCtxCreate_v2",
            "cuMemAlloc_v2","cuMemcpyHtoD_v2","cuModuleLoadData","cuModuleGetFunction","cuLaunchKernel","cuCtxSynchronize","cuMemcpyDtoH_v2","cuModuleUnload","cuMemFree_v2","cuCtxDestroy_v2"});
    internal static bool QualifiedChild(GpuChildReport report,string nonce,uint pid,uint exit,GpuChildReport baseline)=>
        pid!=0 && report.SchemaVersion==1 && report.Pid>0 && (uint)report.Pid==pid && report.Nonce==nonce &&
        report.Scope==LpacScope && exit==0 && Qualified(report) && report.DriverVersion==baseline.DriverVersion;
    private static string ExpectedHash
    {
        get{var bytes=new byte[Bytes];Buffer.BlockCopy(Enumerable.Range(0,Count).Select(i=>i*3+7).ToArray(),0,bytes,0,Bytes);return Convert.ToHexString(SHA256.HashData(bytes));}
    }
    internal static (int ExitCode,string Report) Run(FixedLayout layout,ProtectedState state,VerifiedVersion version)
    {
        state.AssertHeld();version.AssertHeld(state);LifecycleRecovery.AssertNoPending(state);InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var intent in OwnedJobIntent.ReadAll(state))if(AtomicJobCompletion.ReadClosed(state,intent) is null)throw WfpNative.Contract("GpuRequiresPriorAdmissionsClosed");
        var plans=FencePlan.ReadAll(state);if(plans.Count==0)throw WfpNative.Contract("GpuRequiresQuarantine");
        var fences=new List<PersistentFence>();var failures=new List<Exception>();
        var id=Guid.NewGuid().ToString("N");var plan=new GpuProbePlan(id);
        GpuChildReport? baseline=null,observed=null;RuntimeStop? stopped=null;uint? exit=null;string? jobId=null;
        try
        {
            foreach(var fence in plans)fences.Add(PersistentFence.OpenExisting(state,fence.Data.FenceId));
            AssertQuarantine();baseline=Compute(plan,"HOST_CONTROL");
            state.WriteNew("gpu-host-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(baseline));
            if(!Qualified(baseline))throw WfpNative.Contract("GpuHostControlNotQualified");
            using var profile=InstallationProfileLease.Create(state);using var job=OwnedKernelJob.CreateEmpty(state,version);jobId=job.JobId;
            using var pipe=new AnonymousPipeServerStream(PipeDirection.In,HandleInheritability.Inheritable);using var reader=new StreamReader(pipe,Encoding.UTF8,false,4096,true);
            var text=ReadBounded(reader);
            AtomicChild? child=null;ProtectionRuntimeLease? runtime=null;
            try
            {
                child=AtomicChild.CreateCanary(layout,state,version,job,profile,output:pipe.ClientSafePipeHandle.DangerousGetHandle(),gpu:plan);
                pipe.DisposeLocalCopyOfClientHandle();
                runtime=ProtectionRuntimeLease.ForFixedGpu(state,version,job,fences,child,id);
                runtime.Activate(30000);_=child.ResumeQuarantined();
                do{runtime.AssertHealthy();exit=child.ObserveFixedGpuExit();}while(exit is null);
                runtime.AssertHealthy();
                observed=JsonSerializer.Deserialize<GpuChildReport>(text.WaitAsync(TimeSpan.FromSeconds(3)).GetAwaiter().GetResult())??throw WfpNative.Contract("GpuReportMissing");
                if(!QualifiedChild(observed,id,child.Pid,exit.Value,baseline))
                    throw WfpNative.Contract("GpuIsolatedComputationNotQualified");
            }
            catch(Exception ex){failures.Add(ex);}
            finally
            {
                try
                {
                    if(runtime is not null)
                    {
                        stopped=runtime.Stop(RuntimeStop.GpuTerminalReason);
                        if(stopped.FinalJob is not null)profile.AfterOwnedJobZero(stopped.FinalJob);
                        if(!stopped.ConfirmsClosedGpu(id,job.JobId))throw WfpNative.Contract("GpuQualificationStopUnconfirmed");
                    }
                    else if(job.AtomicAdmissionReserved)
                    {
                        // A startup failure must still close its reserved Job.
                        // The fallback has no successful runtime stop receipt.
                        foreach(var fence in fences)
                            try{if(!fence.Observe().FullQuarantineObserved)_=fence.ReinstateQuarantine();}
                            catch(Exception ex){failures.Add(ex);}
                        try{AssertQuarantine();}catch(Exception ex){failures.Add(ex);}
                        profile.AfterOwnedJobZero(job.CloseAtomicAdmissionAndStop());
                    }
                }
                catch(Exception ex){failures.Add(ex);}
                try{child?.Dispose();}catch(Exception ex){failures.Add(ex);}
                try{pipe.DisposeLocalCopyOfClientHandle();}catch(Exception ex){failures.Add(ex);}
            }
        }
        catch(Exception ex){failures.Add(ex);}
        finally
        {
            try{AssertQuarantine();}catch(Exception ex){failures.Add(ex);}
            foreach(var fence in fences)try{fence.Dispose();}catch(Exception ex){failures.Add(ex);}
        }
        var closed=jobId is not null && stopped?.ConfirmsClosedGpu(id,jobId)==true;
        var complete=failures.Count==0 && observed is not null && closed;
        var report=JsonSerializer.Serialize(new {SchemaVersion=1,state.InstallationId,RequestId=id,version.Package.Release,JobId=jobId,
            Status=complete?"BOUNDED_CUDA_KERNEL_IN_LPAC_OBSERVED":"ISOLATED_GPU_NOT_CONFIRMED",Host=baseline,Child=observed,ChildExit=exit,
            OneShotAdmissionClosedAndMembersZero=closed,StopObservation=stopped,Failures=failures.SelectMany(WfpNative.Describe).ToArray(),
            NetworkOpened=false,PyTorchQualified=false,OtherProcessGpuMemoryIsolationQualified=false,HostResourceIsolationQualified=false,ClaudeLaunched=false});
        state.WriteNew("gpu-after-"+id+".json",Encoding.UTF8.GetBytes(report));return(complete?0:3,report);
        void AssertQuarantine()
        {
            if(fences.Count!=plans.Count || fences.Any(f=>!f.Observe().FullQuarantineObserved))throw WfpNative.Contract("GpuFullQuarantineRequired");
        }
    }
    private static async Task<string> ReadBounded(StreamReader reader)
    {
        var data=new char[16385];var total=0;while(total<data.Length){var count=await reader.ReadAsync(data.AsMemory(total));if(count==0)return new string(data,0,total);total+=count;}
        throw WfpNative.Contract("GpuReportTooLarge");
    }
    private static class Cuda
    {
        [DllImport("nvcuda.dll",EntryPoint="cuInit"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int Init(uint flags);
        [DllImport("nvcuda.dll",EntryPoint="cuDriverGetVersion"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int DriverVersion(out int version);
        [DllImport("nvcuda.dll",EntryPoint="cuDeviceGetCount"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int DeviceCount(out int count);
        [DllImport("nvcuda.dll",EntryPoint="cuDeviceGet"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int DeviceGet(out int device,int ordinal);
        [DllImport("nvcuda.dll",EntryPoint="cuDeviceGetName",CharSet=CharSet.Ansi),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int DeviceName(StringBuilder name,int size,int device);
        [DllImport("nvcuda.dll",EntryPoint="cuCtxCreate_v2"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int ContextCreate(out IntPtr context,uint flags,int device);
        [DllImport("nvcuda.dll",EntryPoint="cuCtxDestroy_v2"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int ContextDestroy(IntPtr context);
        [DllImport("nvcuda.dll",EntryPoint="cuMemAlloc_v2"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int Allocate(out ulong pointer,nuint size);
        [DllImport("nvcuda.dll",EntryPoint="cuMemFree_v2"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int Free(ulong pointer);
        [DllImport("nvcuda.dll",EntryPoint="cuMemcpyHtoD_v2"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int CopyToDevice(ulong target,IntPtr source,nuint size);
        [DllImport("nvcuda.dll",EntryPoint="cuMemcpyDtoH_v2"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int CopyFromDevice(IntPtr target,ulong source,nuint size);
        [DllImport("nvcuda.dll",EntryPoint="cuModuleLoadData"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int ModuleLoad(out IntPtr module,IntPtr ptx);
        [DllImport("nvcuda.dll",EntryPoint="cuModuleUnload"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int ModuleUnload(IntPtr module);
        [DllImport("nvcuda.dll",EntryPoint="cuModuleGetFunction",CharSet=CharSet.Ansi),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int Function(out IntPtr function,IntPtr module,string name);
        [DllImport("nvcuda.dll",EntryPoint="cuLaunchKernel"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int Launch(IntPtr function,uint gx,uint gy,uint gz,uint bx,uint by,uint bz,uint shared,IntPtr stream,IntPtr parameters,IntPtr extra);
        [DllImport("nvcuda.dll",EntryPoint="cuCtxSynchronize"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int Synchronize();
    }
}
