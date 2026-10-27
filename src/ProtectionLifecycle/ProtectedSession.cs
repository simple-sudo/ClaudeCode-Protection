using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Security;

namespace ProtectionLifecycle;

// The installed Broker's session owner. Diagnostic JSON, supplied targets and
// serialized permits are deliberately absent from this API. Both request kinds
// use this owner; only its fixed installed synthetic workload is implemented.
internal sealed class ProtectedSession
{
    // Reviewed source hold, with no time/flag/environment/config override.
    internal static bool SystemTestingBlocked => true;
    internal static void AssertSystemTestingAllowed()
    {if(SystemTestingBlocked)throw new InvalidOperationException("SYSTEM_VALIDATION_BLOCKED: 0x1E investigation and artifact clearance required");}
    private const string ResourceScope = "INSTALLED_BROKER_CANARY_ONLY;workspace=none;tools=none;gpu=none;no-breakaway";
    private readonly FixedLayout layout;
    private readonly ProtectedState state;
    private readonly VerifiedVersion version;
    private readonly string id = Guid.NewGuid().ToString("N"), pointerSHA256;
    private readonly Stopwatch clock = Stopwatch.StartNew();
    private readonly DateTimeOffset startedUtc=DateTimeOffset.UtcNow;
    private readonly IReadOnlyList<EnvironmentEvidence> environment;
    private readonly IReadOnlyList<EnvironmentEvidence> systemSafety;
    private static readonly string[] SystemRequirements={"current-trusted-installation","current-gateway-kernel-enforcement",
        "host-sensitive-resource-denial","authorized-workspace-toolchain-device-grants"};
    private readonly List<PersistentFence> fences = new();
    private OwnedKernelJob? job;
    private SessionProxy? gateway;
    private string? sid;
    private Admission? admission;
    private ProtectedSession(FixedLayout layout,ProtectedState state,VerifiedVersion version)
    {
        this.layout=layout;this.state=state;this.version=version;
        pointerSHA256=state.Read("current.json",4096).SHA256;
        environment=CollectEnvironment();
        // Separate, mandatory security evidence. Environmental consistency
        // cannot stand in for any of these unqualified system properties.
        version.AssertHeld(state);
        systemSafety=Array.AsReadOnly(SystemRequirements.Select(name=>new EnvironmentEvidence(name,
            name=="current-trusted-installation"?"PASS":"UNKNOWN",
            name=="current-trusted-installation"?"HELD_CURRENT_INSTALLATION_ASSETS":
                "CURRENT_ARTIFACT_SECURITY_QUALIFICATION_OR_RESOURCE_GRANT_MISSING",clock.ElapsedMilliseconds,120000)).ToArray());
    }
    private sealed record EnvironmentEvidence(string Id,string Status,string Reason,long ObservedMs,long ValidForMs);
    private IReadOnlyList<EnvironmentEvidence> CollectEnvironment()
    {
        // This is the authoritative collector boundary, not a parser for daily
        // reports or old qualification receipts. No positive evidence is
        // fabricated while actual session-bound collectors are unavailable.
        return Array.AsReadOnly(StrictEnvironmentRequirements.Required.Select(def=>new EnvironmentEvidence(
            def.Id,"UNKNOWN","CURRENT_BROKER_COLLECTOR_OR_EXPLICIT_ENVIRONMENT_POLICY_MISSING",clock.ElapsedMilliseconds,120000)).ToArray());
    }
    internal static (int ExitCode,string Report) Request(FixedLayout layout,ProtectedState state,VerifiedVersion version,bool synthetic)
    {
        var owner=new ProtectedSession(layout,state,version);
        if(!synthetic || SystemTestingBlocked || !owner.EnvironmentEligible() || !owner.SystemSecurityEligible())
            return(125,owner.Report(!synthetic?"DEFERRED_BY_USER":SystemTestingBlocked?"SYSTEM_VALIDATION_BLOCKED":
                !owner.EnvironmentEligible()?"TRUSTED_ENVIRONMENT_ADMISSION_REFUSED":"TRUSTED_SYSTEM_SECURITY_ADMISSION_REFUSED",false,null,Array.Empty<WfpErrorEvidence>()));
        return owner.Execute();
    }
    private bool EnvironmentEligible()=>environment.Count==14 &&
        environment.Select(e=>e.Id).Distinct(StringComparer.Ordinal).Count()==14 &&
        StrictEnvironmentRequirements.Required.All(def=>environment.Any(e=>e.Id==def.Id)) &&
        environment.All(e=>e.Status=="PASS" && e.ValidForMs is >0 and <=120000 &&
            clock.ElapsedMilliseconds>=e.ObservedMs && clock.ElapsedMilliseconds-e.ObservedMs<e.ValidForMs);
    private bool SystemSecurityEligible()=>systemSafety.Select(e=>e.Id).SequenceEqual(SystemRequirements) &&
        systemSafety.All(e=>e.Status=="PASS" && e.ValidForMs is >0 and <=120000 &&
            clock.ElapsedMilliseconds>=e.ObservedMs && clock.ElapsedMilliseconds-e.ObservedMs<e.ValidForMs);
    private void AssertCurrent()
    {
        if(SystemTestingBlocked || !EnvironmentEligible() || !SystemSecurityEligible())throw WfpNative.Contract("SessionEvidenceExpiredUnknownOrBlocked");
        state.AssertHeld();version.AssertHeld(state);
        if(state.Read("current.json",4096).SHA256!=pointerSHA256 || job is null || gateway is null || sid is null ||
            gateway.SessionId!=id || fences.Count==0 || fences.Any(f=>!f.IsSessionChannel))
            throw WfpNative.Contract("SessionInstallationPolicyOrResourceBindingDrift");
        gateway.AssertHealthy();
    }
    // An in-memory, one-use capability tied to this owner and its live objects.
    // It has no JSON constructor, file reader, reusable token or caller evidence.
    internal sealed class Admission
    {
        private readonly ProtectedSession owner;
        private readonly string bindingSHA256;
        private AtomicChild? primary;
        private int phase; // 0 issued, 1 creation consumed, 2 resume consumed, 3 revoked
        internal string SessionId=>owner.id;
        internal SessionProxy Gateway=>owner.gateway??throw WfpNative.Contract("SessionGatewayMissing");
        internal Admission(ProtectedSession owner){this.owner=owner;owner.AssertCurrent();bindingSHA256=ComputeBinding();}
        internal void BeforeCreate(OwnedKernelJob exactJob,VerifiedVersion exactVersion)
        {
            AssertCurrent();
            if(!ReferenceEquals(exactJob,owner.job) || !ReferenceEquals(exactVersion,owner.version) ||
                Interlocked.CompareExchange(ref phase,1,0)!=0)throw WfpNative.Contract("SessionCreationPermitConsumedOrForeign");
        }
        internal void BeforeResume(AtomicChild child)
        {
            AssertCurrent();
            if(child.ExpectedPackageSid!=owner.sid || child.ExpectedImagePath!=WindowsPathSeal.Child(owner.layout.Version(owner.version.Package.Release),"bin/admin/ProtectionBroker.exe") ||
                Interlocked.CompareExchange(ref phase,2,1)!=1)throw WfpNative.Contract("SessionResumePermitConsumedOrForeign");
            primary=child;
        }
        internal void AssertCurrent()
        {
            if(Volatile.Read(ref phase)==3)throw WfpNative.Contract("SessionPermitRevoked");owner.AssertCurrent();
            if(bindingSHA256!=ComputeBinding())throw WfpNative.Contract("SessionPermitBindingDrift");
            // The first workload remains a fixed Broker canary. Reuse the
            // held-member rule from PR #1; never treat it as permission for an
            // arbitrary developer tool tree. General tool grants remain absent.
            if(Volatile.Read(ref phase)==2 && primary?.IsRunning==true)
            {
                var before=owner.job!.Observe();
                AtomicChild.InspectMembers(owner.job,before,members=>WatchdogMemberPolicy.Verify(before,members,owner.job.Observe(),
                    primary.Pid,primary.ExpectedCreatedFileTime,owner.sid!,primary.ExpectedImagePath,
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"conhost.exe")));
            }
        }
        internal void AssertRuntimeObjects(OwnedKernelJob exactJob,VerifiedVersion exactVersion,IReadOnlyList<PersistentFence> exactFences)
        {
            AssertCurrent();
            if(!ReferenceEquals(exactJob,owner.job) || !ReferenceEquals(exactVersion,owner.version) ||
                !exactFences.SequenceEqual(owner.fences))throw WfpNative.Contract("SessionRuntimeOwnerMismatch");
        }
        internal void Revoke()=>Interlocked.Exchange(ref phase,3);
        internal string BindingSHA256=>bindingSHA256;
        private string ComputeBinding()=>Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
            owner.state.InstallationId,owner.version.Package.Release,owner.version.Package.ManifestHash,owner.pointerSHA256,
            SessionId=owner.id,JobId=owner.job!.JobId,AppContainerSid=owner.sid,NetworkPolicySHA256=SessionProxy.PolicySHA256,
            Resources=ResourceScope,FenceIntents=owner.fences.Select(f=>f.IntentSHA256).ToArray(),
            RequiredEnvironmentIds=StrictEnvironmentRequirements.Required.Select(def=>def.Id).ToArray()
        })));
    }
    private (int ExitCode,string Report) Execute()
    {
        InstallationProfileLease? profile=null;InstallationLoopbackLease? loopback=null;ProxyChannelLease? upstream=null;
        AtomicChild? child=null;ProtectionRuntimeLease? runtime=null;JobSnapshot? zero=null;
        Task<uint>? exited=null;uint? childExitCode=null;
        RuntimeStop? stopObservation=null;
        var errors=new List<Exception>();bool resumed=false,completed=false;
        try
        {
            AssertPreparation();
            var plans=FencePlan.ReadAll(state);
            // Legacy 7890 barriers are retained for recovery, never silently
            // adopted as gateway policy or removed to make a launch succeed.
            if(plans.Any(plan=>plan.Data.PolicySHA256!=SessionProxy.PolicySHA256 || plan.Data.ProxyPort!=SessionProxy.Port))
                throw WfpNative.Contract("LegacyRawProxyFenceRequiresReviewedMigration");
            if(plans.Count==0)fences.Add(PersistentFence.CreateSessionQuarantined(state,version));
            else foreach(var plan in plans)fences.Add(PersistentFence.OpenExisting(state,plan.Data.FenceId));
            foreach(var fence in fences)if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("SessionInitialQuarantineMissing");
            profile=InstallationProfileLease.Create(state);job=OwnedKernelJob.CreateEmpty(state,version);
            using(var package=new InstallationPackageSid(state))sid=package.Value;
            upstream=ProxyChannelLease.Open(state);gateway=new SessionProxy(job,upstream,sid,id);
            loopback=InstallationLoopbackLease.Enable(state,false);
            admission=new Admission(this);
            state.WriteNew("protected-session-intent-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,SessionId=id,state.InstallationId,version.Package.Release,version.Package.ManifestHash,
                job.JobId,AppContainerSid=sid,admission.BindingSHA256,NetworkPolicySHA256=SessionProxy.PolicySHA256,
                Resources=ResourceScope,Reusable=false,Scope="FIXED_OWNED_SYNTHETIC_USING_PRODUCTION_SESSION_OWNER"
            }));
            child=AtomicChild.CreateSession(layout,state,version,job,profile,admission);
            foreach(var fence in fences)_=fence.OpenSessionGateway(gateway);
            runtime=new ProtectionRuntimeLease(state,version,job,fences,upstream,gateway,admission);
            _=child.ResumeQuarantined(upstream);resumed=true;runtime.Activate(15000);
            exited=Task.Run(child.WaitForCanaryExit);
            while(!exited.Wait(100))runtime.AssertHealthy();
            runtime.AssertHealthy();
            childExitCode=exited.GetAwaiter().GetResult();
            if(childExitCode!=42)throw WfpNative.Contract("SessionSyntheticWorkloadFailed");
            completed=true;
        }
        catch(Exception ex){errors.Add(ex);}
        finally
        {
            admission?.Revoke();
            try{gateway?.Revoke();}catch(Exception ex){errors.Add(ex);}
            if(runtime is not null)
            {
                try
                {
                    var stopped=runtime.Stop(completed?"SESSION_WORKLOAD_COMPLETE":"SESSION_FAILURE");stopObservation=stopped;zero=stopped.FinalJob;
                    if(stopped.Failures.Length!=0 || !stopped.QuarantineObservedBeforeStop || zero?.ObservedZero!=true)
                        throw WfpNative.Contract("SessionStopOrQuarantineNotConfirmed");
                }
                catch(Exception ex){errors.Add(ex);}
            }
            else
            {
                foreach(var fence in fences)try{_=fence.ReinstateQuarantine();}catch(Exception ex){errors.Add(ex);}
                if(job is not null)try{zero=job.AtomicAdmissionReserved?job.CloseAtomicAdmissionAndStop():job.StopAndVerifyZero();}catch(Exception ex){errors.Add(ex);}
            }
            if(profile?.ProcessCreationAttempted==true && zero is not null)try{profile.AfterOwnedJobZero(zero);}catch(Exception ex){errors.Add(ex);}
            if(exited is not null)
                try{childExitCode=exited.WaitAsync(TimeSpan.FromSeconds(3)).GetAwaiter().GetResult();}catch(Exception ex){errors.Add(ex);}
            // Stop/zero precedes profile and exact loopback removal. A failure
            // in one cleanup must not suppress the other owners' attempts.
            foreach(var resource in new IDisposable?[]{child,gateway,loopback,profile,job})
                try{resource?.Dispose();}catch(Exception ex){errors.Add(ex);}
            foreach(var fence in fences)try{fence.Dispose();}catch(Exception ex){errors.Add(ex);}
            try{upstream?.Dispose();}catch(Exception ex){errors.Add(ex);}
        }
        var success=completed && zero?.ObservedZero==true && errors.Count==0;
        var report=Report(success?"FIXED_SYNTHETIC_SESSION_CLOSED":"PROTECTED_SESSION_NOT_CONFIRMED",resumed,zero,
            errors.SelectMany(WfpNative.Describe).ToArray(),stopObservation,profile?.ProcessCreationAttempted==true,child is not null,childExitCode);
        state.WriteNew("protected-session-result-"+id+".json",Encoding.UTF8.GetBytes(report));
        return(success?0:3,report);
    }
    private void AssertPreparation()
    {
        if(SystemTestingBlocked || !EnvironmentEligible() || !SystemSecurityEligible())throw WfpNative.Contract("SessionPreparationNotAuthorized");
        state.AssertHeld();version.AssertHeld(state);LifecycleRecovery.AssertNoPending(state);InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var intent in OwnedJobIntent.ReadAll(state))
            if(AtomicJobCompletion.ReadClosed(state,intent) is null)throw WfpNative.Contract("SessionPriorAdmissionNotClosed");
    }
    private string Report(string status,bool resumed,JobSnapshot? final,WfpErrorEvidence[] failures,RuntimeStop? stopObservation=null,
        bool creationAttempted=false,bool created=false,uint? childExitCode=null)=>JsonSerializer.Serialize(new {
        SchemaVersion=1,Scope="INSTALLED_BROKER_PROTECTED_SESSION",state.InstallationId,version.Package.Release,
        version.Package.ManifestHash,SessionId=id,NetworkPolicySHA256=SessionProxy.PolicySHA256,Resources=ResourceScope,Status=status,
        Checks=environment.Select(e=>new {e.Id,e.Status,e.Reason,Required=true,
            EvidenceAtUtc=startedUtc.AddMilliseconds(e.ObservedMs).ToString("O"),e.ValidForMs,
            Source=e.Status=="UNKNOWN"?"BROKER_COLLECTOR_UNAVAILABLE":"CURRENT_BROKER_COLLECTOR_ONLY",
            Applicability="STRICT_POLICY_NO_IMPLICIT_EXEMPTIONS",DiagnosticReportAccepted=false,CachedPassAccepted=false}),
        SystemSecurityChecks=systemSafety.Select(e=>new {e.Id,e.Status,e.Reason,Required=true}),
        SystemSecurityGates=new[]{"INCIDENT_CLEARANCE","CONFINED_GATEWAY_AND_LITERAL_UPSTREAM","CURRENT_JOB_APPCONTAINER_WFP",
            "HOST_SENSITIVE_RESOURCE_DENIAL","AUTHORIZED_WORKSPACE_TOOLCHAIN_AND_GPU"},
        ProcessCreationAttempted=creationAttempted,ProcessCreatedConfirmed=created,ProcessCreationOutcomeUnknown=creationAttempted && !created,
        ProcessResumed=resumed,ChildExitCode=childExitCode,FinalJob=final,Failures=failures,StopObservation=stopObservation,LaunchAuthorized=false,ClaudeLaunched=false,
        ProductionSessionQualified=false,HostInformationConfidentialityQualified=false
    });
}
