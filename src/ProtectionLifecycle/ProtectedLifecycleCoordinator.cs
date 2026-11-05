using System.Diagnostics;

namespace ProtectionLifecycle;

internal enum ProtectedLifecycleState { Idle,Preparing,WaitManualProxy,Checking,PreflightFailed,ReadyToLaunch,Starting,Running,Stopping,SafeToCloseProxy,RestorePending,Restoring,Restored,FaultLockdown }
internal enum ProtectedLifecycleCommand { Prepare,Check,Launch,Stop,RestoreIpv6 }
internal enum ProtectedLifecycleRecovery { NoPendingOwnedGate,OwnedGateRequiresReconciliation,Unknown }
internal enum ProtectedPreflightOutcome { Pass,Fail,Unknown }
internal sealed record ProtectedLifecycleRequest(string FlowId,int Revision,ProtectedLifecycleCommand Command);
internal sealed record ProtectedHostGate(bool PermanentClaudeFenceVerified,bool OwnedHostIpv6GateHeld,bool ExactKernelReadback,bool DurableRecoveryRecord);
internal sealed record ProtectedStopObservation(bool AdmissionClosed,bool IsolationBeforeStop,bool AllOwnedJobsZero,bool ConnectionsDrained,bool NoUnknownClaudeActors,bool PermanentClaudeFenceVerified,bool OwnedHostIpv6GateHeld);
internal sealed record ProtectedRestoreObservation(bool OwnedTemporaryRulesGone,bool PermanentClaudeFenceVerified);
internal sealed record ProtectedStartObservation(bool OriginalOwnerHoldsLiveSession,bool LpacAndOriginalJobVerified,bool RequiredKernelRulesHeld,bool AdmissionConsumed);

// This opaque reference stays inside the original trusted owner. It is never
// deserialized from GUI JSON or a diagnostic report and is rechecked at resume.
internal abstract class ProtectedLifecycleAdmission : IDisposable { public abstract void Dispose(); }
internal sealed record ProtectedLifecyclePreflight(ProtectedPreflightOutcome Outcome,ProtectedLifecycleAdmission? Admission);
internal sealed record ProtectedLifecycleView(string FlowId,int Revision,ProtectedLifecycleState State,bool EvidenceFresh,
    ProtectedLifecycleCommand[] AllowedRequests,string? FailureType,int? FailureCode,bool JournalConfirmed)
{
    // A view permits asking the owner, never executing or granting admission.
    public bool LaunchAuthority=>false;
}
internal sealed record ProtectedLifecycleReply(bool RequestAccepted,string Reason,ProtectedLifecycleView View);

// Future original-owner adapter only. No implementation is selected by this
// module, and no production entry calls it yet. In particular, diagnostics,
// supplied Booleans and a successful fixture cannot implement these checks.
internal interface IProtectedLifecycleOwner
{
    bool SupportsLifecycleV1 {get;}
    void AssertHeld();
    ProtectedLifecycleRecovery ReadRecoveryState();
    void Persist(ProtectedLifecycleView view);
    ProtectedHostGate PrepareAndVerifyHostGate();
    ProtectedLifecyclePreflight CheckFreshAdmission();
    ProtectedStartObservation RevalidateAndStartOfficialClaude(ProtectedLifecycleAdmission admission);
    ProtectedStopObservation RevokeIsolateStopAndDrain();
    bool? ObserveManualProxyClosed();
    ProtectedRestoreObservation RevalidateAndRestoreOwnedIpv6Gate(ProtectedStopObservation closed);
}

// Finite orchestration, not another executor. The interface has no paths,
// commands, arbitrary PID, ACL, proxy-switch or generic elevation operation.
// Native WFP/IPC/admission integration and real lifecycle qualification remain
// required. This class alone does not provide the lifecycle product capability.
internal sealed class ProtectedLifecycleCoordinator : IDisposable
{
    private readonly IProtectedLifecycleOwner owner;
    private readonly Func<long> elapsed;
    private readonly object sync=new();
    private readonly string flowId=Guid.NewGuid().ToString("N");
    private ProtectedLifecycleState state;
    private ProtectedLifecycleAdmission? admission;
    private ProtectedStopObservation? closed;
    private long observedAt=-1,lastClock;
    private int revision;
    private bool journalConfirmed=true,disposed,stopAttempted;
    private string? failureType;
    private int? failureCode;
    private const long FreshMilliseconds=120000;

    internal ProtectedLifecycleCoordinator(IProtectedLifecycleOwner owner,Func<long>? elapsed=null)
    {
        this.owner=owner;var clock=Stopwatch.StartNew();this.elapsed=elapsed??(()=>clock.ElapsedMilliseconds);
        owner.AssertHeld();lastClock=Now();
        state=owner.ReadRecoveryState()==ProtectedLifecycleRecovery.NoPendingOwnedGate?ProtectedLifecycleState.Idle:ProtectedLifecycleState.FaultLockdown;
    }
    internal ProtectedLifecycleView View()
    {
        lock(sync)
        {
            if(disposed)throw new ObjectDisposedException(nameof(ProtectedLifecycleCoordinator));
            try{owner.AssertHeld();return Snapshot(Now());}catch(Exception error){if(state!=ProtectedLifecycleState.FaultLockdown)stopAttempted=false;LockDown(error);return Snapshot(lastClock);}
        }
    }
    internal ProtectedLifecycleReply Execute(ProtectedLifecycleRequest request)
    {
        lock(sync)
        {
            if(disposed)throw new ObjectDisposedException(nameof(ProtectedLifecycleCoordinator));
            if(state!=ProtectedLifecycleState.FaultLockdown)stopAttempted=false;
            long now;
            try{owner.AssertHeld();now=Now();}catch(Exception error){LockDown(error);return Reply(false,"OWNER_OR_CLOCK_UNAVAILABLE",lastClock);}
            if(request.FlowId!=flowId || request.Revision!=revision || !Enum.IsDefined(request.Command))return Reply(false,"STALE_OR_FOREIGN_REQUEST",now);
            if(!owner.SupportsLifecycleV1)return Reply(false,"LIFECYCLE_NATIVE_BACKEND_NOT_QUALIFIED",now);
            if(!Allowed(now).Contains(request.Command))return Reply(false,"REQUEST_NOT_ALLOWED_IN_CURRENT_STATE",now);
            stopAttempted=false;
            try
            {
                switch(request.Command)
                {
                    case ProtectedLifecycleCommand.Prepare:
                        Change(ProtectedLifecycleState.Preparing);
                        var gate=owner.PrepareAndVerifyHostGate();
                        if(!gate.PermanentClaudeFenceVerified || !gate.OwnedHostIpv6GateHeld || !gate.ExactKernelReadback || !gate.DurableRecoveryRecord)
                            throw new InvalidDataException("HostGateNotProven");
                        Change(ProtectedLifecycleState.WaitManualProxy);break;
                    case ProtectedLifecycleCommand.Check:
                        RevokeAdmission();Change(ProtectedLifecycleState.Checking);
                        var check=owner.CheckFreshAdmission();
                        if(check.Outcome!=ProtectedPreflightOutcome.Pass)
                        {check.Admission?.Dispose();Change(ProtectedLifecycleState.PreflightFailed);break;}
                        admission=check.Admission??throw new InvalidDataException("PreflightHasNoHeldOwnerAdmission");
                        observedAt=Now();Change(ProtectedLifecycleState.ReadyToLaunch);break;
                    case ProtectedLifecycleCommand.Launch:
                        if(!Fresh(Now()) || admission is null)throw new InvalidDataException("OwnerAdmissionExpired");
                        Change(ProtectedLifecycleState.Starting);
                        // The original owner MUST recheck live WFP/token/Job,
                        // privacy/exit/tool qualifications and the human grant.
                        var started=owner.RevalidateAndStartOfficialClaude(admission);
                        if(!started.OriginalOwnerHoldsLiveSession || !started.LpacAndOriginalJobVerified || !started.RequiredKernelRulesHeld || !started.AdmissionConsumed)
                            throw new InvalidDataException("ProtectedStartNotProven");
                        // Consumed admission/session lifetime now belongs to
                        // the original owner. Do not revoke it as a draft.
                        admission=null;observedAt=-1;Change(ProtectedLifecycleState.Running);break;
                    case ProtectedLifecycleCommand.Stop:
                        RevokeAdmission();Change(ProtectedLifecycleState.Stopping);
                        stopAttempted=true;closed=owner.RevokeIsolateStopAndDrain();
                        if(!Closed(closed))throw new InvalidDataException("SafeProxyCloseNotProven");
                        Change(ProtectedLifecycleState.SafeToCloseProxy);break;
                    case ProtectedLifecycleCommand.RestoreIpv6:
                        if(closed is null || !Closed(closed))throw new InvalidDataException("OriginalStopObservationMissing");
                        if(owner.ObserveManualProxyClosed()!=true){Change(ProtectedLifecycleState.RestorePending);break;}
                        Change(ProtectedLifecycleState.Restoring);
                        var restored=owner.RevalidateAndRestoreOwnedIpv6Gate(closed);
                        if(!restored.OwnedTemporaryRulesGone || !restored.PermanentClaudeFenceVerified)
                            throw new InvalidDataException("OwnedIpv6RestoreOrPermanentFenceUnproven");
                        closed=null;Change(ProtectedLifecycleState.Restored);break;
                }
                return Reply(true,"OWNER_STEP_FINISHED",Now());
            }
            catch(Exception error){LockDown(error);return Reply(true,"FAULT_LOCKDOWN",lastClock);}
        }
    }
    internal void FaultDetected()
    {
        lock(sync)
        {
            if(disposed || state==ProtectedLifecycleState.FaultLockdown)return;
            stopAttempted=false;
            try{owner.AssertHeld();}catch(Exception error){LockDown(error);return;}
            LockDown(new InvalidDataException("OwnerObservedProtectionOrProxyFault"));
        }
    }
    private void LockDown(Exception error)
    {
        if(state==ProtectedLifecycleState.FaultLockdown && stopAttempted)return;
        failureType=error.GetType().Name;failureCode=error.HResult;state=ProtectedLifecycleState.FaultLockdown;closed=null;
        // Never retry the failed Stop. Fault closure does not authorize manual
        // proxy-close guidance or an IPv6 restore, even if it reaches Job zero.
        try{RevokeAdmission();}catch{journalConfirmed=false;}
        if(!stopAttempted){stopAttempted=true;try{_=owner.RevokeIsolateStopAndDrain();}catch{journalConfirmed=false;}}
        if(journalConfirmed)try{
            if(revision>=512)throw new InvalidDataException("LifecycleTransitionLimit");
            revision++;owner.Persist(Snapshot(lastClock));
        }catch{journalConfirmed=false;}
    }
    private void Change(ProtectedLifecycleState next)
    {
        if(revision>=512)throw new InvalidDataException("LifecycleTransitionLimit");
        state=next;revision++;
        try{owner.Persist(Snapshot(Now()));journalConfirmed=true;}catch{journalConfirmed=false;throw;}
    }
    private void RevokeAdmission(){var previous=admission;admission=null;observedAt=-1;previous?.Dispose();}
    private long Now()
    {
        long value=elapsed();
        if(value<0 || value<lastClock)throw new InvalidDataException("LifecycleMonotonicClockRegressed");
        lastClock=value;return value;
    }
    private bool Fresh(long now)=>admission is not null && observedAt>=0 && now>=observedAt && now-observedAt<=FreshMilliseconds;
    private ProtectedLifecycleCommand[] Allowed(long now)
    {
        if(!owner.SupportsLifecycleV1 || !journalConfirmed || disposed)return Array.Empty<ProtectedLifecycleCommand>();
        return state switch {
            ProtectedLifecycleState.Idle or ProtectedLifecycleState.Restored=>new[]{ProtectedLifecycleCommand.Prepare},
            ProtectedLifecycleState.WaitManualProxy or ProtectedLifecycleState.PreflightFailed=>new[]{ProtectedLifecycleCommand.Check,ProtectedLifecycleCommand.Stop},
            ProtectedLifecycleState.ReadyToLaunch=>Fresh(now)?new[]{ProtectedLifecycleCommand.Check,ProtectedLifecycleCommand.Launch,ProtectedLifecycleCommand.Stop}
                :new[]{ProtectedLifecycleCommand.Check,ProtectedLifecycleCommand.Stop},
            ProtectedLifecycleState.Running or ProtectedLifecycleState.FaultLockdown=>new[]{ProtectedLifecycleCommand.Stop},
            ProtectedLifecycleState.SafeToCloseProxy or ProtectedLifecycleState.RestorePending=>new[]{ProtectedLifecycleCommand.Stop,ProtectedLifecycleCommand.RestoreIpv6},
            _=>Array.Empty<ProtectedLifecycleCommand>()};
    }
    private ProtectedLifecycleView Snapshot(long now)=>new(flowId,revision,state,Fresh(now),Allowed(now),failureType,failureCode,journalConfirmed);
    private ProtectedLifecycleReply Reply(bool accepted,string reason,long now)=>new(accepted,reason,Snapshot(now));
    private static bool Closed(ProtectedStopObservation value)=>value.AdmissionClosed && value.IsolationBeforeStop && value.AllOwnedJobsZero &&
        value.ConnectionsDrained && value.NoUnknownClaudeActors && value.PermanentClaudeFenceVerified && value.OwnedHostIpv6GateHeld;
    public void Dispose()
    {
        lock(sync)
        {
            if(disposed)return;
            if(state is not (ProtectedLifecycleState.Idle or ProtectedLifecycleState.Restored or ProtectedLifecycleState.SafeToCloseProxy or
                ProtectedLifecycleState.RestorePending or ProtectedLifecycleState.FaultLockdown))
            {stopAttempted=false;LockDown(new InvalidDataException("OriginalLifecycleControllerDisposed"));}
            // Disposal is never a human IPv6 restore request.
            try{RevokeAdmission();}finally{disposed=true;}
        }
    }
}
