using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

internal enum OfflineTlsProbe { Schannel, OpenSsl }

// Both fixed diagnostics use the same installed owner, Job and quarantine.
// Only the self-developed OpenSSL fixture has an in-memory peer.
internal static class OfflineTlsQualification
{
    internal static string ChildCommand(OfflineTlsProbe probe)=>probe switch {
        OfflineTlsProbe.Schannel=>"schannel-acquisition-child",
        OfflineTlsProbe.OpenSsl=>"openssl-offline-child",
        _=>throw WfpNative.Contract("UnknownOfflineTlsProbe")
    };
    internal static string SessionVariable(OfflineTlsProbe probe)=>probe switch {
        OfflineTlsProbe.Schannel=>"CPC_SCHANNEL_SESSION",
        OfflineTlsProbe.OpenSsl=>"CPC_OPENSSL_OFFLINE_SESSION",
        _=>throw WfpNative.Contract("UnknownOfflineTlsProbe")
    };
    internal static (int ExitCode,string Report) Run(FixedLayout layout,ProtectedState state,VerifiedVersion version,OfflineTlsProbe probe)
    {
        state.AssertHeld();version.AssertHeld(state);
        var stopReason=RuntimeStop.OfflineTlsTerminalReason(probe);
        bool openSsl=probe==OfflineTlsProbe.OpenSsl;
        if(openSsl)OpenSslModuleLease.AssertOwnedPackage(version.Package);
        LifecycleRecovery.AssertNoPending(state);InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var intent in OwnedJobIntent.ReadAll(state))
            if(AtomicJobCompletion.ReadClosed(state,intent) is null)throw WfpNative.Contract("OfflineTlsRequiresPriorAdmissionsClosed");
        var plans=FencePlan.ReadAll(state);
        if(plans.Count==0)throw WfpNative.Contract("OfflineTlsRequiresExistingQuarantine");

        var id=Guid.NewGuid().ToString("N");
        var failures=new List<Exception>();
        var fences=new List<PersistentFence>();
        RuntimeStop? stopped=null;
        SchannelAcquisition? schannel=null;
        OpenSslOfflineWitness? witness=null;
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
                child=AtomicChild.CreateOfflineTlsQualification(layout,state,version,job,profile,id,
                    pipe.ClientSafePipeHandle.DangerousGetHandle(),probe);
                pipe.DisposeLocalCopyOfClientHandle();
                runtime=ProtectionRuntimeLease.ForFixedOfflineTls(state,version,job,fences,child,id,probe);
                runtime.Activate(12000);
                _=child.ResumeQuarantined();
                resumed=true;
                do
                {
                    runtime.AssertHealthy();
                    if(output.IsFaulted)_=output.GetAwaiter().GetResult();
                    exit=child.ObserveFixedOfflineTlsExit();
                }while(exit is null);
                runtime.AssertHealthy();
                if(exit is not (0 or 3) || !openSsl && exit!=0)throw WfpNative.Contract("OfflineTlsWorkerDidNotReport");
                var raw=output.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
                if(openSsl)
                    witness=OpenSslOfflineWitness.Parse(raw,id,child.Pid,child.ExpectedCreatedFileTime,exit.Value);
                else
                {
                    schannel=SchannelAcquisition.Parse(raw,id,child.Pid,child.ExpectedCreatedFileTime);
                    if(!schannel.Complete)throw WfpNative.Contract("SchannelAcquisitionCleanupUnconfirmed");
                }
            }
            catch(Exception error){failures.Add(error);}
            finally
            {
                try
                {
                    if(runtime is not null)
                    {
                        stopped=runtime.Stop(stopReason);
                        if(stopped.FinalJob is not null)profile.AfterOwnedJobZero(stopped.FinalJob);
                        if(!stopped.ConfirmsClosedOfflineTls(probe,id,job.JobId))throw WfpNative.Contract("OfflineTlsQualificationStopUnconfirmed");
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
        bool closed=jobId is not null && stopped?.ConfirmsClosedOfflineTls(probe,id,jobId)==true;
        bool complete=failures.Count==0 && closed && (openSsl?witness?.Complete==true:schannel?.Complete==true);
        var status=openSsl?(complete?"OFFLINE_TLS_EXCHANGE_CLOSED":"OFFLINE_TLS_EXCHANGE_UNCONFIRMED"):
            (complete?"ACQUISITION_OBSERVATIONS_CLOSED":"ACQUISITION_OBSERVATIONS_UNCONFIRMED");
        var report=JsonSerializer.Serialize(new {
            SchemaVersion=1,Scope=openSsl?"FIXED_OFFLINE_LPAC_OPENSSL_EXCHANGE":"FIXED_OFFLINE_LPAC_SCHANNEL_ACQUISITION",state.InstallationId,SessionId=id,JobId=jobId,
            version.Package.Release,version.Package.ManifestHash,Status=status,
            ExpectedCapabilitiesSHA256=LpacCapabilityProfile.InternetClientQualification.SHA256,Child=openSsl?(object?)witness:schannel,ChildExit=exit,
            ProcessResumed=resumed,OriginalOwnerClosed=closed,StopObservation=stopped,Failures=failures.SelectMany(WfpNative.Describe).ToArray(),
            GatewayOpened=false,WinsockLeaseApplied=false,TlsHandshakeObserved=witness?.ExchangeVerified==true,NetworkQualified=false,ClaudeLaunched=false
        });
        state.WriteNew((openSsl?"openssl-offline-after-":"schannel-after-")+id+".json",Encoding.UTF8.GetBytes(report));
        return(complete?0:3,report);

        void AssertQuarantine()
        {
            if(fences.Count!=plans.Count || fences.Any(f=>!f.Observe().FullQuarantineObserved))
                throw WfpNative.Contract("OfflineTlsFullQuarantineRequired");
        }
    }
}
