using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

// The existing installed owner runs a fixed LPAC child under full
// quarantine. No gateway, lease, TLS peer or caller-supplied options.
internal static class SchannelQualification
{
    internal static (int ExitCode,string Report) Run(FixedLayout layout,ProtectedState state,VerifiedVersion version)
    {
        state.AssertHeld();version.AssertHeld(state);
        LifecycleRecovery.AssertNoPending(state);InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var intent in OwnedJobIntent.ReadAll(state))
            if(AtomicJobCompletion.ReadClosed(state,intent) is null)throw WfpNative.Contract("SchannelRequiresPriorAdmissionsClosed");
        var plans=FencePlan.ReadAll(state);
        if(plans.Count==0)throw WfpNative.Contract("SchannelRequiresExistingQuarantine");

        var id=Guid.NewGuid().ToString("N");
        var failures=new List<Exception>();
        var fences=new List<PersistentFence>();
        RuntimeStop? stopped=null;
        SchannelAcquisition? childReport=null;
        string? jobId=null;
        uint? exit=null;
        bool resumed=false;
        try
        {
            foreach(var plan in plans)fences.Add(PersistentFence.OpenExisting(state,plan.Data.FenceId));
            AssertQuarantine();
            using var profile=InstallationProfileLease.Create(state);
            using var job=OwnedKernelJob.CreateEmpty(state,version);
            jobId=job.JobId;
            using var pipe=new AnonymousPipeServerStream(PipeDirection.In,HandleInheritability.Inheritable);
            using var reader=new StreamReader(pipe,new UTF8Encoding(false,true),false,4096,true);
            var output=GatewayChildReport.ReadBounded(reader);
            AtomicChild? child=null;
            ProtectionRuntimeLease? runtime=null;
            try
            {
                child=AtomicChild.CreateSchannelQualification(layout,state,version,job,profile,id,pipe.ClientSafePipeHandle.DangerousGetHandle());
                pipe.DisposeLocalCopyOfClientHandle();
                runtime=ProtectionRuntimeLease.ForFixedSchannel(state,version,job,fences,child,id);
                runtime.Activate(12000);
                _=child.ResumeQuarantined();
                resumed=true;
                do
                {
                    runtime.AssertHealthy();
                    if(output.IsFaulted)_=output.GetAwaiter().GetResult();
                    exit=child.ObserveFixedSchannelExit();
                }while(exit is null);
                runtime.AssertHealthy();
                if(exit!=0)throw WfpNative.Contract("SchannelWorkerDidNotReport");
                childReport=SchannelAcquisition.Parse(output.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult(),
                    id,child.Pid,child.ExpectedCreatedFileTime);
                if(!childReport.Complete)throw WfpNative.Contract("SchannelAcquisitionCleanupUnconfirmed");
            }
            catch(Exception error){failures.Add(error);}
            finally
            {
                try
                {
                    if(runtime is not null)
                    {
                        stopped=runtime.Stop(RuntimeStop.SchannelTerminalReason);
                        if(stopped.FinalJob is not null)profile.AfterOwnedJobZero(stopped.FinalJob);
                        if(!stopped.ConfirmsClosedSchannel(id,job.JobId))throw WfpNative.Contract("SchannelQualificationStopUnconfirmed");
                    }
                    else if(job.AtomicAdmissionReserved)
                    {
                        foreach(var fence in fences)
                            try{if(!fence.Observe().FullQuarantineObserved)_=fence.ReinstateQuarantine();}
                            catch(Exception error){failures.Add(error);}
                        profile.AfterOwnedJobZero(job.CloseAtomicAdmissionAndStop());
                    }
                }
                catch(Exception error){failures.Add(error);}
                try{child?.Dispose();}catch(Exception error){failures.Add(error);}
                try{pipe.DisposeLocalCopyOfClientHandle();}catch(Exception error){failures.Add(error);}
                try{_=output.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();}
                catch(Exception error){failures.Add(error);}
            }
        }
        catch(Exception error){failures.Add(error);}
        finally
        {
            try{AssertQuarantine();}catch(Exception error){failures.Add(error);}
            foreach(var fence in fences)try{fence.Dispose();}catch(Exception error){failures.Add(error);}
        }
        bool closed=jobId is not null && stopped?.ConfirmsClosedSchannel(id,jobId)==true;
        bool complete=failures.Count==0 && closed && childReport?.Complete==true;
        var report=JsonSerializer.Serialize(new {
            SchemaVersion=1,Scope="FIXED_OFFLINE_LPAC_SCHANNEL_ACQUISITION",state.InstallationId,SessionId=id,JobId=jobId,
            version.Package.Release,version.Package.ManifestHash,Status=complete?"ACQUISITION_OBSERVATIONS_CLOSED":"ACQUISITION_OBSERVATIONS_UNCONFIRMED",
            ExpectedCapabilitiesSHA256=LpacCapabilityProfile.InternetClientQualification.SHA256,Child=childReport,ChildExit=exit,
            ProcessResumed=resumed,OriginalOwnerClosed=closed,StopObservation=stopped,Failures=failures.SelectMany(WfpNative.Describe).ToArray(),
            GatewayOpened=false,WinsockLeaseApplied=false,TlsHandshakeObserved=false,NetworkQualified=false,ClaudeLaunched=false
        });
        state.WriteNew("schannel-after-"+id+".json",Encoding.UTF8.GetBytes(report));
        return(complete?0:3,report);

        void AssertQuarantine()
        {
            if(fences.Count!=plans.Count || fences.Any(f=>!f.Observe().FullQuarantineObserved))
                throw WfpNative.Contract("SchannelFullQuarantineRequired");
        }
    }
}
