using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

internal enum WatchdogCase { LeaseExpiry,NarrowingFenceDrift }
internal static class WatchdogQualification
{
    internal static (int ExitCode,string Report) Run(FixedLayout layout,ProtectedState state,VerifiedVersion version)
    {
        state.AssertHeld();version.AssertHeld(state);LifecycleRecovery.AssertNoPending(state);InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var intent in OwnedJobIntent.ReadAll(state))if(!SessionZeroCreatorRecovery.IsAdmissionResolved(state,intent))throw WfpNative.Contract("WatchdogRequiresPriorAdmissionsClosed");
        var plans=FencePlan.ReadAll(state);if(plans.Count==0)throw WfpNative.Contract("WatchdogRequiresFence");
        var fences=new List<PersistentFence>();var results=new List<object>();Exception? failure=null;var id=Guid.NewGuid().ToString("N");
        try
        {
            foreach(var plan in plans){var fence=PersistentFence.OpenExisting(state,plan.Data.FenceId);fences.Add(fence);if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("WatchdogInitialQuarantineRequired");}
            using var proxy=ProxyChannelLease.Open(state);if(ProxyChannelLease.CheckTransport().GetAwaiter().GetResult() is <200 or >=400)throw WfpNative.Contract("WatchdogProxyControlFailed");
            using var receivers=new NetworkReceivers();var control=receivers.Plan(NetworkProbeKind.Control);
            var baseline=NetworkQualification.RawCases(control).GetAwaiter().GetResult();Thread.Sleep(200);receivers.AssertCollecting();
            if(baseline.Any(c=>!c.SocketCallSucceeded) || receivers.ReceiptCounts(control).Any(c=>c<1))throw WfpNative.Contract("WatchdogReceiverControlFailed");
            foreach(var kind in new[]{WatchdogCase.LeaseExpiry,WatchdogCase.NarrowingFenceDrift})RunCase(kind,proxy,receivers);
        }
        catch(Exception ex){failure=ex;}
        finally
        {
            foreach(var fence in fences)
            {
                try{if(!fence.Observe().FullQuarantineObserved)_=fence.ReinstateQuarantine();if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("WatchdogFinalQuarantineFailed");}
                catch(Exception ex){failure=failure is null?ex:new AggregateException(failure,ex);}
                finally{fence.Dispose();}
            }
        }
        var report=JsonSerializer.Serialize(new {SchemaVersion=1,state.InstallationId,RequestId=id,version.Package.Release,
            Status=failure is null?"BOUNDED_WATCHDOG_EXPIRY_AND_NARROWING_DRIFT_OBSERVED":"WATCHDOG_NOT_CONFIRMED",Results=results,
            Failures=failure is null?Array.Empty<WfpErrorEvidence>():WfpNative.Describe(failure),ProxyProcessCrashQualified=false,ControllerCrashQualified=false,
            UnsafeRuleRemovalQualified=false,AuthenticatedControllerRenewalQualified=false,ExternalPhysicalEgressQualified=false,ClaudeLaunched=false});
        state.WriteNew("watchdog-after-"+id+".json",Encoding.UTF8.GetBytes(report));return(failure is null?0:3,report);

        void RunCase(WatchdogCase kind,ProxyChannelLease proxy,NetworkReceivers receivers)
        {
            var plan=receivers.Plan(NetworkProbeKind.ProxySession);using var profile=InstallationProfileLease.Create(state);
            using var loopback=InstallationLoopbackLease.Enable(state,false);using var job=OwnedKernelJob.CreateEmpty(state,version);
            using var pipe=new AnonymousPipeServerStream(PipeDirection.In,HandleInheritability.Inheritable);using var reader=new StreamReader(pipe,Encoding.UTF8,false,4096,true);
            var ready=ReadLine(reader);ProtectionRuntimeLease? runtime=null;RuntimeStop? stop=null;Exception? phaseFailure=null;
            NetworkChildReport? childReport=null;uint? childExit=null;string? detected=null;long detectionMs=-1;int[]? counts=null;
            try
            {
                using var child=AtomicChild.CreateCanary(layout,state,version,job,profile,plan,pipe.ClientSafePipeHandle.DangerousGetHandle());pipe.DisposeLocalCopyOfClientHandle();
                foreach(var fence in fences)_=fence.OpenQualifiedIPv4Proxy(proxy);runtime=new(state,version,job,fences,proxy);
                _=child.ResumeQuarantined(proxy);
                while(!ready.Wait(100)){runtime.AssertHealthy();if(!child.IsRunning)throw WfpNative.Contract("WatchdogChildExitedBeforeReady");}
                runtime.AssertHealthy();childReport=JsonSerializer.Deserialize<NetworkChildReport>(ready.GetAwaiter().GetResult())??throw WfpNative.Contract("WatchdogReadyReportMissing");
                if(childReport.SchemaVersion!=1 || childReport.Pid!=child.Pid || childReport.Nonce!=plan.Nonce || childReport.Kind!=plan.Kind || childReport.FailureMask!=0 ||
                    childReport.ProxyHttpStatus is not (>=200 and <400) || childReport.ProxySocket?.SocketCallSucceeded!=true ||
                    !NetworkQualification.NegativeCasesEligible(childReport.Cases) || !child.IsRunning)throw WfpNative.Contract("WatchdogReadyReportRefused");
                var members=job.Observe();
                AtomicChild.InspectMembers(job,members,inspected=>
                {
                var afterInspection=job.Observe();
                state.WriteNew("watchdog-members-"+job.JobId+".json",JsonSerializer.SerializeToUtf8Bytes(new {Before=members,Members=inspected,After=afterInspection}));
                // Pre-resume admission remains strictly one suspended target; this
                // post-resume check can additionally accept one verified OS console host.
                WatchdogMemberPolicy.Verify(members,inspected,afterInspection,child.Pid,child.ExpectedCreatedFileTime,child.ExpectedPackageSid,
                    child.ExpectedImagePath,Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"conhost.exe"));
                });
                runtime.Activate(kind==WatchdogCase.LeaseExpiry?1000:5000);var clock=Stopwatch.StartNew();
                if(kind==WatchdogCase.NarrowingFenceDrift)foreach(var fence in fences)_=fence.ReinstateQuarantine(); // Narrows only our own SID; never deletes a guard.
                while(clock.ElapsedMilliseconds<6000)
                {
                    try{runtime.AssertHealthy();}
                    catch(Exception ex)
                    {
                        detected=ex is WfpFailure w?w.Stage:ex.Data["Stage"]?.ToString()??ex.GetType().Name;detectionMs=clock.ElapsedMilliseconds;
                        var expected=kind==WatchdogCase.LeaseExpiry?"RuntimeLeaseExpired":"RuntimeFenceDrift";
                        if(detected!=expected)throw;
                        stop=runtime.Stop(expected);break;
                    }
                    if(!child.IsRunning)throw WfpNative.Contract("WatchdogTargetExitedWithoutTrigger");Thread.Sleep(100);
                }
                if(stop is null)throw WfpNative.Contract("WatchdogTriggerNotDetected");
                childExit=child.WaitForCanaryExit();Thread.Sleep(200);receivers.AssertCollecting();counts=receivers.ReceiptCounts(plan);
                if(stop.Failures.Length!=0 || !stop.QuarantineObservedBeforeStop || stop.QuarantineAtMs>stop.JobStopAtMs || stop.FinalJob?.ObservedZero!=true || childExit!=125 || counts.Any(c=>c!=0))
                    throw WfpNative.Contract("WatchdogOrderedStopNotConfirmed");
            }
            catch(Exception ex){phaseFailure=ex;}
            finally
            {
                try
                {
                    if(runtime is not null){stop=runtime.Stop(phaseFailure is null?"QUALIFICATION_END":"QUALIFICATION_FAILURE");if(stop.Failures.Length!=0)throw WfpNative.Contract("WatchdogStopFailure");if(stop.FinalJob is not null)profile.AfterOwnedJobZero(stop.FinalJob);}
                    else
                    {
                        foreach(var fence in fences)if(!fence.Observe().FullQuarantineObserved)_=fence.ReinstateQuarantine();
                        if(job.AtomicAdmissionReserved)profile.AfterOwnedJobZero(job.CloseAtomicAdmissionAndStop());else _=job.StopAndRetireUnadmitted();
                    }
                }
                catch(Exception ex){phaseFailure=phaseFailure is null?ex:new AggregateException(phaseFailure,ex);}
                pipe.DisposeLocalCopyOfClientHandle();
            }
            var result=new {Case=kind,job.JobId,Child=childReport,Detected=detected,DetectionMs=detectionMs,ChildExit=childExit,Stop=stop,ReceiverCounts=counts,
                Matched=phaseFailure is null,Failures=phaseFailure is null?Array.Empty<WfpErrorEvidence>():WfpNative.Describe(phaseFailure)};
            results.Add(result);state.WriteNew("watchdog-case-"+id+"-"+((int)kind)+".json",JsonSerializer.SerializeToUtf8Bytes(result));if(phaseFailure is not null)throw phaseFailure;
        }
    }
    private static async Task<string> ReadLine(StreamReader reader)
    {
        var data=new char[16385];var length=0;
        while(length<data.Length){var count=await reader.ReadAsync(data.AsMemory(length,1));if(count==0)throw WfpNative.Contract("WatchdogReportEndedEarly");if(data[length]=='\n')return new string(data,0,length).TrimEnd('\r');length++;}
        throw WfpNative.Contract("WatchdogReportTooLarge");
    }
}
