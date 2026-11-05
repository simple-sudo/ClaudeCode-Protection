using System.Text.Json;
using ProtectionLifecycle;

if(args.Length!=0)return 125;
int passed=0;
void Check(bool value,string reason){if(!value)throw new InvalidDataException(reason);passed++;}
ProtectedLifecycleReply Step(ProtectedLifecycleCoordinator flow,ProtectedLifecycleCommand command)
{var view=flow.View();return flow.Execute(new(view.FlowId,view.Revision,command));}
void Prepare(ProtectedLifecycleCoordinator flow){Check(Step(flow,ProtectedLifecycleCommand.Prepare).View.State==ProtectedLifecycleState.WaitManualProxy,"prepare before manual proxy");}
void Ready(ProtectedLifecycleCoordinator flow){Prepare(flow);Check(Step(flow,ProtectedLifecycleCommand.Check).View.State==ProtectedLifecycleState.ReadyToLaunch,"fresh owner preflight");}
void Running(ProtectedLifecycleCoordinator flow){Ready(flow);Check(Step(flow,ProtectedLifecycleCommand.Launch).View.State==ProtectedLifecycleState.Running,"owner-bound launch result");}
void Safe(ProtectedLifecycleCoordinator flow){Prepare(flow);Check(Step(flow,ProtectedLifecycleCommand.Stop).View.State==ProtectedLifecycleState.SafeToCloseProxy,"stop before manual proxy close");}

{
    var owner=new FixtureOwner();using var flow=new ProtectedLifecycleCoordinator(owner);
    var initial=flow.View();Check(!initial.LaunchAuthority,"report is never authority");
    Check(!Step(flow,ProtectedLifecycleCommand.Launch).RequestAccepted && owner.Starts==0,"no launch before host gate");
    Check(!flow.Execute(new(new string('b',32),initial.Revision,ProtectedLifecycleCommand.Prepare)).RequestAccepted,"foreign flow rejected");
    Check(!flow.Execute(new(initial.FlowId,-1,ProtectedLifecycleCommand.Prepare)).RequestAccepted,"stale revision rejected");
    Check(!flow.Execute(new(initial.FlowId,initial.Revision,(ProtectedLifecycleCommand)999)).RequestAccepted,"unknown request rejected");
    Running(flow);Check(owner.LastAdmission is {Consumed:true,Disposals:0},"consumed admission transferred to original owner, not revoked as draft");
    Check(!Step(flow,ProtectedLifecycleCommand.RestoreIpv6).RequestAccepted && owner.Restores==0,"running session cannot restore IPv6");
    var stopped=Step(flow,ProtectedLifecycleCommand.Stop);Check(stopped.View.State==ProtectedLifecycleState.SafeToCloseProxy,"owned closure permits manual-close guidance");
    Check(!flow.Execute(new(stopped.View.FlowId,stopped.View.Revision-1,ProtectedLifecycleCommand.RestoreIpv6)).RequestAccepted,"old stop view cannot restore");
    owner.ProxyClosed=null;Check(Step(flow,ProtectedLifecycleCommand.RestoreIpv6).View.State==ProtectedLifecycleState.RestorePending && owner.Restores==0,"unknown manual proxy closure retains gate");
    owner.ProxyClosed=false;Check(Step(flow,ProtectedLifecycleCommand.RestoreIpv6).View.State==ProtectedLifecycleState.RestorePending && owner.Restores==0,"running proxy retains gate");
    owner.ProxyClosed=true;Check(Step(flow,ProtectedLifecycleCommand.RestoreIpv6).View.State==ProtectedLifecycleState.Restored && owner.Restores==1,"explicit restore after fresh owner checks");
    Check(!Step(flow,ProtectedLifecycleCommand.RestoreIpv6).RequestAccepted && owner.Restores==1,"restore does not replay");
}
{
    long now=100;var owner=new FixtureOwner();using var flow=new ProtectedLifecycleCoordinator(owner,()=>now);Ready(flow);
    now+=120001;Check(!flow.View().EvidenceFresh && !flow.View().AllowedRequests.Contains(ProtectedLifecycleCommand.Launch),"expired evidence disables launch request");
    Check(!Step(flow,ProtectedLifecycleCommand.Launch).RequestAccepted && owner.Starts==0,"expired admission never resumes");
    Step(flow,ProtectedLifecycleCommand.Check);Check(owner.LastDisposedAdmission?.Disposals==1,"recheck revokes old draft once");
}
foreach(var outcome in new[]{ProtectedPreflightOutcome.Fail,ProtectedPreflightOutcome.Unknown})
{
    var owner=new FixtureOwner{Outcome=outcome};using var flow=new ProtectedLifecycleCoordinator(owner);Prepare(flow);
    Check(Step(flow,ProtectedLifecycleCommand.Check).View.State==ProtectedLifecycleState.PreflightFailed,"FAIL/UNKNOWN retain failed preflight");
    Check(owner.Starts==0 && owner.Restores==0,"failed preflight cannot launch or restore");
}
foreach(int missing in Enumerable.Range(0,4))
{
    var owner=new FixtureOwner{Gate=new(missing!=0,missing!=1,missing!=2,missing!=3)};using var flow=new ProtectedLifecycleCoordinator(owner);
    Check(Step(flow,ProtectedLifecycleCommand.Prepare).View.State==ProtectedLifecycleState.FaultLockdown,"partial host gate locks down");
    Check(owner.Stops==1 && owner.Restores==0,"failed prepare closes once without restore");
}
foreach(int missing in Enumerable.Range(0,7))
{
    var owner=new FixtureOwner{Stop=new(missing!=0,missing!=1,missing!=2,missing!=3,missing!=4,missing!=5,missing!=6)};
    using var flow=new ProtectedLifecycleCoordinator(owner);Prepare(flow);
    Check(Step(flow,ProtectedLifecycleCommand.Stop).View.State==ProtectedLifecycleState.FaultLockdown,"partial closure never permits proxy-close guidance");
    Check(owner.Stops==1,"failed stop is not retried by fault handler");
}
{
    var owner=new FixtureOwner{ThrowStop=true};using var flow=new ProtectedLifecycleCoordinator(owner);Prepare(flow);
    Step(flow,ProtectedLifecycleCommand.Stop);flow.FaultDetected();flow.FaultDetected();Check(owner.Stops==1 && owner.Restores==0,"repeated fault never retries failed stop");
}
{
    var owner=new FixtureOwner();using var flow=new ProtectedLifecycleCoordinator(owner);Running(flow);
    flow.FaultDetected();flow.FaultDetected();Check(owner.Stops==1 && flow.View().State==ProtectedLifecycleState.FaultLockdown,"proxy/owner fault closes once and remains locked");
    Check(!Step(flow,ProtectedLifecycleCommand.RestoreIpv6).RequestAccepted && owner.Restores==0,"fault is not user proxy closure");
    Check(Step(flow,ProtectedLifecycleCommand.Stop).View.State==ProtectedLifecycleState.SafeToCloseProxy,"new explicit stop revalidates original objects");
}
foreach(int missing in Enumerable.Range(0,4))
{
    var owner=new FixtureOwner{Start=new(missing!=0,missing!=1,missing!=2,missing!=3)};using var flow=new ProtectedLifecycleCoordinator(owner);Ready(flow);
    Check(Step(flow,ProtectedLifecycleCommand.Launch).View.State==ProtectedLifecycleState.FaultLockdown && owner.Stops==1,"incomplete real-start observation cannot show running");
}
foreach(int missing in Enumerable.Range(0,2))
{
    var owner=new FixtureOwner{Restore=new(missing!=0,missing!=1),ProxyClosed=true};using var flow=new ProtectedLifecycleCoordinator(owner);Safe(flow);
    Check(Step(flow,ProtectedLifecycleCommand.RestoreIpv6).View.State==ProtectedLifecycleState.FaultLockdown && owner.Restores==1,"restore readback/permanent fence failure locks down without retry");
}
{
    var owner=new FixtureOwner{FailPersistAt=1};using var flow=new ProtectedLifecycleCoordinator(owner);
    var result=Step(flow,ProtectedLifecycleCommand.Prepare);
    Check(result.View.State==ProtectedLifecycleState.FaultLockdown && !result.View.JournalConfirmed,"failed durable intent stays unknown");
    Check(owner.Prepares==0 && owner.Persists==1 && owner.Stops==1,"do not mutate host gate or retry failed journal");
    Check(result.View.AllowedRequests.Length==0,"journal loss cannot grant followup mutation");
}
{
    var owner=new FixtureOwner{SupportsLifecycleV1=false};using var flow=new ProtectedLifecycleCoordinator(owner);
    Check(!Step(flow,ProtectedLifecycleCommand.Prepare).RequestAccepted && owner.Prepares==0 && owner.Stops==0,"unqualified backend never executes a system operation");
}
foreach(var recovery in new[]{ProtectedLifecycleRecovery.OwnedGateRequiresReconciliation,ProtectedLifecycleRecovery.Unknown})
{
    var owner=new FixtureOwner{Recovery=recovery};using var flow=new ProtectedLifecycleCoordinator(owner);
    Check(flow.View().State==ProtectedLifecycleState.FaultLockdown && owner.Restores==0,"restart or unknown gate cannot auto-restore/adopt");
    Check(!Step(flow,ProtectedLifecycleCommand.Prepare).RequestAccepted,"recovery uncertainty cannot prepare another gate");
}
{
    long now=100;var owner=new FixtureOwner();using var flow=new ProtectedLifecycleCoordinator(owner,()=>now);Running(flow);now=99;
    Check(flow.View().State==ProtectedLifecycleState.FaultLockdown && owner.Stops==1,"clock regression is a fault, not renewed evidence");
    Check(flow.View().State==ProtectedLifecycleState.FaultLockdown && owner.Stops==1,"clock fault does not retry closure");
}
{
    var owner=new FixtureOwner();var flow=new ProtectedLifecycleCoordinator(owner);Running(flow);flow.Dispose();flow.Dispose();
    Check(owner.Stops==1 && owner.Restores==0,"owner coordinator disposal closes active scope once and never restores IPv6");
}
{
    var owner=new FixtureOwner();using var flow=new ProtectedLifecycleCoordinator(owner);Ready(flow);owner.LostHeldIdentity=true;
    Check(flow.View().State==ProtectedLifecycleState.FaultLockdown && owner.Stops==1,"view cannot keep ready after original owner identity is lost");
    Check(!flow.View().AllowedRequests.Contains(ProtectedLifecycleCommand.Launch) && owner.Stops==1,"owner-loss observation neither renews admission nor repeats stop");
}
Console.WriteLine(JsonSerializer.Serialize(new {Scope="L1_FINITE_LIFECYCLE_FIXTURE_ONLY_NO_NATIVE_BACKEND",Passed=passed,
    NativeSystemActionsExecuted=false,OfficialClaudeStarted=false,HostIpv6Changed=false,ProductCapabilityDelivered=false}));return 0;

sealed class FixtureAdmission(FixtureOwner owner) : ProtectedLifecycleAdmission
{
    internal bool Consumed;internal int Disposals;
    public override void Dispose(){Disposals++;owner.LastDisposedAdmission=this;if(Consumed)throw new InvalidDataException("Consumed admission revoked as draft");}
}
sealed class FixtureOwner : IProtectedLifecycleOwner
{
    public bool SupportsLifecycleV1 {get;set;}=true;
    internal ProtectedLifecycleRecovery Recovery=ProtectedLifecycleRecovery.NoPendingOwnedGate;
    internal ProtectedHostGate Gate=new(true,true,true,true);
    internal ProtectedStopObservation Stop=new(true,true,true,true,true,true,true);
    internal ProtectedStartObservation Start=new(true,true,true,true);
    internal ProtectedRestoreObservation Restore=new(true,true);
    internal ProtectedPreflightOutcome Outcome=ProtectedPreflightOutcome.Pass;
    internal bool? ProxyClosed;internal bool ThrowStop,LostHeldIdentity;
    internal int FailPersistAt,Prepares,Starts,Stops,Restores,Persists;
    internal FixtureAdmission? LastAdmission,LastDisposedAdmission;
    public void AssertHeld(){if(LostHeldIdentity)throw new InvalidDataException("Fixture owner identity lost");}
    public ProtectedLifecycleRecovery ReadRecoveryState()=>Recovery;
    public void Persist(ProtectedLifecycleView view){Persists++;if(Persists==FailPersistAt)throw new IOException("Fixture journal failure");}
    public ProtectedHostGate PrepareAndVerifyHostGate(){Prepares++;return Gate;}
    public ProtectedLifecyclePreflight CheckFreshAdmission(){LastAdmission=Outcome==ProtectedPreflightOutcome.Pass?new(this):null;return new(Outcome,LastAdmission);}
    public ProtectedStartObservation RevalidateAndStartOfficialClaude(ProtectedLifecycleAdmission admission){Starts++;((FixtureAdmission)admission).Consumed=Start.AdmissionConsumed;return Start;}
    public ProtectedStopObservation RevokeIsolateStopAndDrain(){Stops++;if(ThrowStop)throw new IOException("Fixture stop failed");return Stop;}
    public bool? ObserveManualProxyClosed()=>ProxyClosed;
    public ProtectedRestoreObservation RevalidateAndRestoreOwnedIpv6Gate(ProtectedStopObservation closed){Restores++;return Restore;}
}
