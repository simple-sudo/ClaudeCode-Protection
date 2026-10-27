using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record RuntimeStop(string SessionId,string Reason,bool AdmissionClosed,bool QuarantineObservedBeforeStop,
    long QuarantineAtMs,long JobStopAtMs,JobSnapshot? FinalJob,WfpErrorEvidence[] Failures);

// Owns the active one-shot Job's health/deadline and stop ordering. This is not
// the whole-installation update/uninstall authority or a generic launch API.
internal sealed class ProtectionRuntimeLease
{
    private readonly ProtectedState state;
    private readonly VerifiedVersion version;
    private readonly OwnedKernelJob job;
    private readonly IReadOnlyList<PersistentFence> fences;
    private readonly ProxyChannelLease proxy;
    private readonly SessionProxy? gateway;
    private ProtectedSession.Admission? admission;
    private readonly ProtectedSession.Preparation? preparation;
    private bool startupObserved;
    internal bool StartupGuardObserved=>preparation is not null && startupObserved && !closed && clock.ElapsedMilliseconds<deadlineMs;
    private readonly Stopwatch clock=Stopwatch.StartNew();
    private readonly string pointerSHA256,id=Guid.NewGuid().ToString("N");
    private long deadlineMs=25000;
    private bool activated,closed;
    private RuntimeStop? stopped;
    internal ProtectionRuntimeLease(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,IReadOnlyList<PersistentFence> fences,ProxyChannelLease proxy,
        SessionProxy? gateway=null,ProtectedSession.Admission? admission=null,ProtectedSession.Preparation? preparation=null)
    {
        this.state=state;this.version=version;this.job=job;this.fences=fences;this.proxy=proxy;
        if(gateway is null?(admission is not null || preparation is not null):(admission is null)==(preparation is null))
            throw WfpNative.Contract("SessionGatewayAndExactlyOneOwnerAuthorityRequired");
        if(admission is not null && !ReferenceEquals(gateway,admission.Gateway))throw WfpNative.Contract("SessionRuntimeGatewayMismatch");
        if(preparation is not null && !ReferenceEquals(gateway,preparation.Gateway))throw WfpNative.Contract("StartupGatewayMismatch");
        admission?.AssertRuntimeObjects(job,version,fences);
        preparation?.AssertRuntimeObjects(job,version,fences);
        this.gateway=gateway;this.admission=admission;this.preparation=preparation;
        if(gateway is not null)id=gateway.SessionId;
        pointerSHA256=state.Read("current.json",4096).SHA256;
        if(fences.Count==0 || !job.AtomicAdmissionReserved)throw WfpNative.Contract("RuntimeRequiresAtomicAdmissionAndFence");
        AssertHealthy();
        state.WriteNew("session-open-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,SessionId=id,job.JobId,
            version.Package.Release,version.Package.ManifestHash,CurrentPointerSHA256=pointerSHA256,StartupDeadlineMs=deadlineMs,
            Scope=gateway is null?"SINGLE_ATOMIC_JOB_COMPILED_PROXY":admission is null?"QUARANTINED_SUSPENDED_SESSION_STARTUP":"SINGLE_AUTHORIZED_SESSION_GATEWAY",
            FormalSessionResumeAuthorized=admission is not null,AdmissionReusable=false,
            SessionBindingSHA256=admission?.BindingSHA256,AtUtc=DateTime.UtcNow.ToString("o")}));
    }
    internal void AssertHealthy()
    {
        if(closed)throw WfpNative.Contract("RuntimeAdmissionClosed");
        state.AssertHeld();version.AssertHeld(state);
        if(state.Read("current.json",4096).SHA256!=pointerSHA256)throw WfpNative.Contract("RuntimeInstalledSelectionDrift");
        if(clock.ElapsedMilliseconds>=deadlineMs)throw WfpNative.Contract("RuntimeLeaseExpired");
        proxy.AssertHealthy();
        if(admission is not null)admission.AssertCurrent();else preparation?.AssertCurrent();
        gateway?.AssertHealthy();
        foreach(var fence in fences)
        {
            var observed=fence.Observe();
            if(preparation is not null && admission is null?!observed.FullQuarantineObserved:!observed.IPv4ProxyOnlyObserved)
                throw WfpNative.Contract("RuntimeFenceDrift");
        }
        if(gateway is not null && fences.Any(f=>!f.IsSessionChannel))throw WfpNative.Contract("SessionRawProxyPolicyDrift");
        if(!job.Observe().ExpectedLimits)throw WfpNative.Contract("RuntimeJobLimitsDrift");
        // Renew only after every check succeeded. A delayed/dead owner cannot
        // let an existing socket retain its old forwarding permission forever.
        admission?.ObserveRuntimeHealthy(this,deadlineMs-clock.ElapsedMilliseconds);
        startupObserved=true;
    }
    internal void AttachAdmission(ProtectedSession.Admission permit)
    {
        if(preparation is null || admission is not null || activated || closed || !permit.Matches(preparation))
            throw WfpNative.Contract("StartupGuardAdmissionTransitionRefused");
        permit.AssertRuntimeObjects(job,version,fences);admission=permit;AssertHealthy();
    }
    // One transition from bounded startup to a bounded active lease. A later
    // authenticated controller heartbeat/renewal path is not implemented here.
    internal void Activate(int durationMs)
    {
        if(activated || durationMs is <250 or >60000 || preparation is not null && admission is null)throw WfpNative.Contract("RuntimeActivationRefused");
        AssertHealthy();activated=true;deadlineMs=checked(clock.ElapsedMilliseconds+durationMs);
        admission?.ObserveRuntimeHealthy(this,deadlineMs-clock.ElapsedMilliseconds);
        state.WriteNew("session-active-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,SessionId=id,job.JobId,
            ActiveDurationMs=durationMs,DeadlineMs=deadlineMs,Renewable=false,AtUtc=DateTime.UtcNow.ToString("o")}));
    }
    internal RuntimeStop Stop(string reason)
    {
        if(stopped is not null)return stopped;
        closed=true;var errors=new List<Exception>();var quarantined=true;long quarantineAt=-1,jobAt=-1;JobSnapshot? zero=null;
        admission?.Revoke();
        preparation?.Revoke();
        try{gateway?.Revoke();}catch(Exception ex){errors.Add(ex);}
        try{state.WriteNew("session-stop-intent-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,SessionId=id,job.JobId,
            Reason=reason,AdmissionClosed=true,AtMs=clock.ElapsedMilliseconds}));}catch(Exception ex){errors.Add(ex);}
        foreach(var fence in fences)
        {
            try
            {
                if(!fence.Observe().FullQuarantineObserved)_=fence.ReinstateQuarantine();
                if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("RuntimeQuarantineReadbackFailed");
            }
            catch(Exception ex){quarantined=false;errors.Add(ex);}
        }
        if(quarantined)quarantineAt=clock.ElapsedMilliseconds;
        // A failed barrier restore still must not prevent exact Job termination.
        // It remains a failure, never a successful ordered-quarantine claim.
        try{jobAt=clock.ElapsedMilliseconds;zero=job.CloseAtomicAdmissionAndStop();}catch(Exception ex){errors.Add(ex);}
        RuntimeStop Snapshot()=>new(id,reason,true,quarantined,quarantineAt,jobAt,zero,errors.SelectMany(WfpNative.Describe).ToArray());
        try{state.WriteNew("session-stopped-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(Snapshot()));}catch(Exception ex){errors.Add(ex);}
        stopped=Snapshot();return stopped;
    }
}

// Qualification-only member policy: a console host can be created by Windows
// after the canary's suspended admission. Reject arbitrary extra executables,
// foreign tokens, unstable snapshots and missing/uncertain member evidence.
// This is NOT a general Claude child-process admission policy.
internal static class WatchdogMemberPolicy
{
    internal static void Verify(JobSnapshot before,OwnedMemberInspection[] inspected,JobSnapshot after,
        uint primaryPid,long primaryCreatedFileTime,string packageSid,string primaryImage,string consoleHostImage)
    {
        if(before.JobId!=after.JobId || !before.ExpectedLimits || !after.ExpectedLimits ||
            before.ActiveBefore!=before.ActiveAfter || after.ActiveBefore!=after.ActiveAfter ||
            before.ActiveBefore is <1 or >2 || after.ActiveBefore!=before.ActiveBefore || primaryPid==0 || primaryCreatedFileTime<=0 ||
            before.ProcessIds.Length!=checked((int)before.ActiveBefore) || after.ProcessIds.Length!=checked((int)after.ActiveBefore) ||
            before.ProcessIds.Distinct().Count()!=before.ProcessIds.Length ||
            after.ProcessIds.Distinct().Count()!=after.ProcessIds.Length ||
            !before.ProcessIds.Contains(primaryPid) || inspected.Length!=before.ProcessIds.Length ||
            !before.ProcessIds.SequenceEqual(inspected.Select(m=>m.Pid)) ||
            !before.ProcessIds.OrderBy(p=>p).SequenceEqual(after.ProcessIds.OrderBy(p=>p)))
            throw WfpNative.Contract("WatchdogMemberSnapshotUnstableOrUnexpected");

        var expectedPrimary=WindowsPathSeal.Canonical(primaryImage);
        var expectedConsole=WindowsPathSeal.Canonical(consoleHostImage);
        foreach(var member in inspected)
        {
            var token=member.Token;
            if(!member.MembershipConfirmed || member.CreatedFileTime is null or <=0 ||
                (member.Pid==primaryPid && member.CreatedFileTime!=primaryCreatedFileTime) ||
                (member.Pid!=primaryPid && member.CreatedFileTime<primaryCreatedFileTime) ||
                member.Failures is null || member.Failures.Length!=0 ||
                token is null || !token.IsAppContainer || token.PackageSid!=packageSid ||
                token.CapabilityCount!=0 || token.IntegritySid!="S-1-16-4096" ||
                string.IsNullOrWhiteSpace(member.ImagePath))
                throw WfpNative.Contract("WatchdogMemberIdentityNotQualified");

            var observedImage=WindowsPathSeal.Canonical(member.ImagePath);
            var expectedImage=member.Pid==primaryPid?expectedPrimary:expectedConsole;
            if(!string.Equals(observedImage,expectedImage,StringComparison.OrdinalIgnoreCase))
                throw WfpNative.Contract("WatchdogUnexpectedMemberImage");
        }
    }
}

internal enum WatchdogCase { LeaseExpiry,NarrowingFenceDrift }
internal static class WatchdogQualification
{
    internal static (int ExitCode,string Report) Run(FixedLayout layout,ProtectedState state,VerifiedVersion version)
    {
        state.AssertHeld();version.AssertHeld(state);LifecycleRecovery.AssertNoPending(state);InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var intent in OwnedJobIntent.ReadAll(state))if(AtomicJobCompletion.ReadClosed(state,intent) is null)throw WfpNative.Contract("WatchdogRequiresPriorAdmissionsClosed");
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
                        if(job.AtomicAdmissionReserved)profile.AfterOwnedJobZero(job.CloseAtomicAdmissionAndStop());else _=job.StopAndVerifyZero();
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
