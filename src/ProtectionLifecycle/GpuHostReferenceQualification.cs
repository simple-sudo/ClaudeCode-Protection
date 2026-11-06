using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record GpuHostReferenceResult(string RequestId,string? JobId,uint? ChildPid,uint? ChildExit,GpuHostTokenFacts? CreatedToken,GpuChildReport? Child,
    GpuReportedCall? LastReportedCall,bool Complete,RuntimeStop? Stop,WfpErrorEvidence[] Failures);

// The original installed owner manages a finite ordinary reference child. No
// CUDA entry point runs on its management thread and no target/input is supplied.
internal static class GpuHostReferenceQualification
{
    internal const string Scope="TRUSTED_LINKED_ORDINARY_HOST_GPU_REFERENCE_NOT_LPAC";
    internal static bool Qualified(GpuChildReport child,string nonce,uint pid,uint exit,bool progressComplete,RuntimeStop? stop,string jobId)
        =>pid>0 && child.SchemaVersion==1 && child.Pid==pid && child.Nonce==nonce && child.Scope==Scope && exit==0 && progressComplete &&
          GpuQualification.Qualified(child) && stop?.ConfirmsClosedHostGpu(nonce,jobId)==true;
    internal static int RunChild()
    {
        try
        {
            using var identity=WindowsIdentity.GetCurrent(TokenAccessLevels.Query|TokenAccessLevels.Duplicate);
            GpuHostToken.RequireNormal(GpuHostToken.Capture(identity.AccessToken));
            if(new[]{"CPC_GPU_PLAN","CPC_NETWORK_PLAN","CPC_RESOURCE_PLAN","CPC_SESSION_ID","CPC_SESSION_SECRET"}.Any(n=>Environment.GetEnvironmentVariable(n) is not null))
                throw WfpNative.Contract("HostGpuCannotBorrowProtectedWorkloadPlan");
            var raw=Environment.GetEnvironmentVariable("CPC_HOST_GPU_REFERENCE");if(raw is null || raw.Length>256)throw WfpNative.Contract("HostGpuPlanBounds");
            var plan=JsonSerializer.Deserialize<GpuProbePlan>(raw)??throw WfpNative.Contract("HostGpuPlanMissing");plan.Validate();
            if(plan.ProgressProtocol!=1)throw WfpNative.Contract("HostGpuProgressRequired");
            var writer=new GpuCallProgressWriter(Console.Out,plan.Nonce,Environment.ProcessId);
            var report=GpuQualification.Compute(plan,Scope,writer);Console.WriteLine(JsonSerializer.Serialize(report));
            return GpuQualification.Qualified(report)?0:3;
        }
        catch(Exception error){Console.Error.WriteLine("Host GPU reference child not confirmed: "+error.GetType().Name+"; code="+error.HResult);return 125;}
    }
    internal static GpuHostReferenceResult Run(ProtectedState state,VerifiedVersion version,FixedLayout layout,IReadOnlyList<PersistentFence> fences)
    {
        state.AssertHeld();version.AssertHeld(state);LifecycleRecovery.AssertNoPending(state);InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var intent in OwnedJobIntent.ReadAll(state))if(AtomicJobCompletion.ReadClosed(state,intent) is null)throw WfpNative.Contract("HostGpuRequiresPriorAdmissionsClosed");
        var id=Guid.NewGuid().ToString("N");var plan=new GpuProbePlan(id,1);var progress=new GpuCallProgressReader(id,true);
        var errors=new List<Exception>();string? jobId=null;uint? pid=null,exit=null;GpuHostTokenFacts? createdToken=null;GpuChildReport? observed=null;RuntimeStop? stop=null;
        AssertQuarantine();
        using(var job=OwnedKernelJob.CreateEmpty(state,version))
        using(var pipe=new AnonymousPipeServerStream(PipeDirection.In,HandleInheritability.Inheritable))
        using(var reader=new StreamReader(pipe,Encoding.UTF8,false,4096,true))
        {
            jobId=job.JobId;var text=progress.ReadAsync(reader);AtomicChild.HostGpuReferenceChild? child=null;ProtectionRuntimeLease? runtime=null;
            try
            {
                child=AtomicChild.CreateHostGpuReference(layout,state,version,job,plan,pipe.ClientSafePipeHandle.DangerousGetHandle());pid=child.Pid;createdToken=child.VerifiedToken;
                progress.Bind(checked((int)child.Pid));pipe.DisposeLocalCopyOfClientHandle();
                runtime=ProtectionRuntimeLease.ForHostGpuReference(state,version,job,fences,child,id);runtime.Activate(30000);child.Resume();
                do{runtime.AssertHealthy();if(text.IsFaulted)_=text.GetAwaiter().GetResult();exit=child.ObserveExit();}while(exit is null);
                runtime.AssertHealthy();
                observed=JsonSerializer.Deserialize<GpuChildReport>(text.WaitAsync(TimeSpan.FromSeconds(3)).GetAwaiter().GetResult())??throw WfpNative.Contract("HostGpuReportMissing");
            }
            catch(Exception error){errors.Add(error);}
            finally
            {
                try
                {
                    if(runtime is not null)
                    {stop=runtime.Stop(RuntimeStop.HostGpuTerminalReason);if(!stop.ConfirmsClosedHostGpu(id,jobId))throw WfpNative.Contract("HostGpuStopUnconfirmed");}
                    else if(job.AtomicAdmissionReserved)
                    {
                        // Startup failure still closes only this original Job.
                        // It cannot produce a successful runtime-stop receipt.
                        try{AssertQuarantine();}catch(Exception error){errors.Add(error);}
                        _=job.CloseAtomicAdmissionAndStop();
                    }
                }
                catch(Exception error){errors.Add(error);}
                try{child?.Dispose();}catch(Exception error){errors.Add(error);}
                try{pipe.DisposeLocalCopyOfClientHandle();}catch(Exception error){errors.Add(error);}
                try{_=text.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();}catch(Exception error){errors.Add(error);}
            }
        }
        try{AssertQuarantine();}catch(Exception error){errors.Add(error);}
        var complete=errors.Count==0 && createdToken is not null && observed is not null && pid is not null && exit is not null &&
            Qualified(observed,id,pid.Value,exit.Value,progress.ReportsCompleteSuccessfulSequence,stop,jobId);
        var result=new GpuHostReferenceResult(id,jobId,pid,exit,createdToken,observed,progress.Snapshot(),complete,stop,errors.SelectMany(WfpNative.Describe).ToArray());
        state.WriteNew("gpu-host-reference-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(result));return result;
        void AssertQuarantine(){if(fences.Count==0 || fences.Any(f=>!f.Observe().FullQuarantineObserved))throw WfpNative.Contract("HostGpuFullQuarantineRequired");}
    }
    internal static (int ExitCode,string Report) RunInstalled(FixedLayout layout,ProtectedState state,VerifiedVersion version)
    {
        var fences=new List<PersistentFence>();
        try
        {
            foreach(var plan in FencePlan.ReadAll(state))fences.Add(PersistentFence.OpenExisting(state,plan.Data.FenceId));
            var result=Run(state,version,layout,fences);
            return(result.Complete?0:3,JsonSerializer.Serialize(new{SchemaVersion=1,Status=result.Complete?"BOUNDED_ORDINARY_HOST_CUDA_REFERENCE_OBSERVED":"HOST_CUDA_REFERENCE_NOT_CONFIRMED",
                Result=result,CallProgressEvidence="BOUND_CHILD_SELF_REPORT_NOT_ADMISSION_OR_CLEANUP_AUTHORITY",OriginalOwnerExecutedCuda=false,LpacExecuted=false,NetworkGrant=false,FormalAdmissionIssued=false,LaunchAuthorized=false,ClaudeLaunched=false}));
        }
        catch(Exception error)
        {
            return(125,JsonSerializer.Serialize(new{SchemaVersion=1,Status="HOST_CUDA_REFERENCE_NOT_CONFIRMED",Failures=WfpNative.Describe(error),
                OriginalOwnerExecutedCuda=false,LpacExecuted=false,NetworkGrant=false,FormalAdmissionIssued=false,LaunchAuthorized=false,ClaudeLaunched=false}));
        }
        finally{foreach(var fence in fences)fence.Dispose();}
    }
}
