using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Security;

namespace ProtectionLifecycle;

// The installed Broker's session owner. Diagnostic JSON, supplied targets and
// serialized permits are deliberately absent from this API. Both request kinds
// use this owner; only its fixed installed synthetic workload is implemented.
internal sealed class ProtectedSession
{
    // Current artifact still needs bounded runtime/install qualification.
    // Renewed human authorization permits that work, not a positive clearance.
    // There is no caller flag/environment/config override.
    internal static bool SystemTestingBlocked => true;
    internal static void AssertSystemTestingAllowed()
    {if(SystemTestingBlocked)throw new InvalidOperationException("SYSTEM_ARTIFACT_NOT_QUALIFIED: bounded artifact/runtime/install qualification required");}
    private const string ResourceScope = "INSTALLED_BROKER_CANARY_ONLY;workspace=none;tools=none;gpu=none;no-breakaway";
    private readonly FixedLayout layout;
    private readonly ProtectedState state;
    private readonly VerifiedVersion version;
    private readonly string id = Guid.NewGuid().ToString("N"), pointerSHA256;
    private readonly Stopwatch clock = Stopwatch.StartNew();
    private readonly DateTimeOffset startedUtc=DateTimeOffset.UtcNow;
    private IReadOnlyList<EnvironmentEvidence> environment;
    private readonly EnvironmentExpectations? expectations;
    private readonly string? expectationsSHA256;
    private readonly string expectationsReason;
    private long lastCollectionMs=-1;
    private readonly IReadOnlyList<EnvironmentEvidence> systemSafety;
    private static readonly string[] SystemRequirements={"current-trusted-installation","current-gateway-kernel-enforcement",
        "host-sensitive-resource-denial","authorized-workspace-toolchain-device-grants"};
    private readonly List<PersistentFence> fences = new();
    private OwnedKernelJob? job;
    private SessionProxy? gateway;
    private string? sid;
    private Admission? admission;
    private Preparation? preparation;
    private ProtectionRuntimeLease? runtime;
    private SessionResources? resources;
    private ProtectedSession(FixedLayout layout,ProtectedState state,VerifiedVersion version)
    {
        this.layout=layout;this.state=state;this.version=version;
        pointerSHA256=state.Read("current.json",4096).SHA256;
        (expectations,expectationsSHA256,expectationsReason)=ReadExpectations();
        environment=MissingEnvironment();
        // Separate, mandatory security evidence. Environmental consistency
        // cannot stand in for any of these unqualified system properties.
        version.AssertHeld(state);
        systemSafety=Array.AsReadOnly(SystemRequirements.Select(name=>new EnvironmentEvidence(name,
            name=="current-trusted-installation"?"PASS":"UNKNOWN",
            name=="current-trusted-installation"?"HELD_CURRENT_INSTALLATION_ASSETS":
                name=="current-gateway-kernel-enforcement"?"CURRENT_KERNEL_FUNCTIONALITY_AND_UPSTREAM_LITERAL_NON_DIRECT_ROUTE_NOT_QUALIFIED":
                "CURRENT_ARTIFACT_SECURITY_QUALIFICATION_OR_RESOURCE_GRANT_MISSING",clock.ElapsedMilliseconds,120000)).ToArray());
    }
    private sealed record EnvironmentEvidence(string Id,string Status,string Reason,long ObservedMs,long ValidForMs);
    // This capability authorizes one compiled offline resource experiment,
    // bound to this installed owner. It cannot attach Admission, open a
    // gateway, consume a formal Preparation, or select a caller workload.
    internal sealed class ResourceQualification
    {
        private readonly ProtectedSession owner;
        private AtomicChild? root;
        private int phase;
        internal ResourceQualification(ProtectedSession owner){this.owner=owner;AssertCurrent();}
        internal string SessionId=>owner.id;
        internal ResourceProbePlan Plan=>owner.resources!.Plan;
        internal string Workspace=>owner.resources!.Workspace;
        internal void AssertCurrent()
        {
            owner.state.AssertHeld();owner.version.AssertHeld(owner.state);
            if(Volatile.Read(ref phase)==3 || owner.clock.ElapsedMilliseconds>=30000 || owner.job is null || owner.resources is null ||
                owner.admission is not null || owner.preparation is not null || owner.gateway is not null || owner.sid is null ||
                owner.state.Read("current.json",4096).SHA256!=owner.pointerSHA256 || owner.fences.Count==0 ||
                owner.fences.Any(f=>!f.Observe().FullQuarantineObserved))throw WfpNative.Contract("OfflineResourceScopeExpiredChangedOrUnconfined");
            owner.resources.AssertHeld();
        }
        internal void BeforeCreate(OwnedKernelJob job,VerifiedVersion version)
        {
            AssertRuntimeObjects(job,version,owner.fences);
            if(Interlocked.CompareExchange(ref phase,1,0)!=0)throw WfpNative.Contract("ResourceCreationPermitConsumed");
        }
        internal void BindCreated(AtomicChild child)
        {
            if(Volatile.Read(ref phase)!=1 || root is not null || child.ExpectedPackageSid!=owner.sid)throw WfpNative.Contract("ResourceRootBindingRefused");
            child.AssertSuspendedResourceIdentity(this);root=child;
        }
        internal void BeforeResume(AtomicChild child)
        {
            AssertCurrent();
            if(!ReferenceEquals(root,child) || Interlocked.CompareExchange(ref phase,2,1)!=1)throw WfpNative.Contract("ResourceResumePermitConsumedOrForeign");
        }
        internal void AssertRuntimeObjects(OwnedKernelJob job,VerifiedVersion version,IReadOnlyList<PersistentFence> fences)
        {
            AssertCurrent();
            if(!ReferenceEquals(owner.job,job) || !ReferenceEquals(owner.version,version) || !fences.SequenceEqual(owner.fences))
                throw WfpNative.Contract("ResourceRuntimeOwnerMismatch");
        }
        internal void Revoke()=>Interlocked.Exchange(ref phase,3);
    }
    internal static (int ExitCode,string Report) QualifyResources(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>new ProtectedSession(layout,state,version).ExecuteResourceQualification();
    internal static (int ExitCode,string Report) QualifyResourceRecovery(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        // Deliberately EXIT this installed owner with a durable cleanup
        // checkpoint. The NEXT installed invocation performs real journal
        // recovery; no live in-memory profile object is transferred to it.
        =>new ProtectedSession(layout,state,version).ExecuteResourceQualification(true);
    private (int ExitCode,string Report) ExecuteResourceQualification(bool deferCleanup=false)
    {
        InstallationProfileLease? profile=null;AtomicChild? child=null;
        System.IO.Pipes.AnonymousPipeServerStream? pipe=null;StreamReader? reader=null;
        ResourceQualification? permit=null;ResourceChildReport? observed=null;Task<uint>? exited=null;Task<string>? text=null;
        JobSnapshot? zero=null;RuntimeStop? stopped=null;uint? exit=null;bool resumed=false,toolObserved=false,cleanupDeferred=false;
        var failures=new List<Exception>();
        try
        {
            LifecycleRecovery.AssertNoPending(state);InstallationLoopbackLease.AssertClosedHistory(state);
            foreach(var intent in OwnedJobIntent.ReadAll(state))
                if(AtomicJobCompletion.ReadClosed(state,intent) is null)throw WfpNative.Contract("ResourceQualificationPriorAdmissionNotClosed");
            var plans=FencePlan.ReadAll(state);if(plans.Count==0)throw WfpNative.Contract("ResourceQualificationNeedsExistingQuarantine");
            foreach(var plan in plans)fences.Add(PersistentFence.OpenExisting(state,plan.Data.FenceId));
            foreach(var fence in fences)if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("ResourceQualificationFullQuarantineRequired");
            state.WriteNew("resource-session-before-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,
                SessionId=id,version.Package.Release,version.Package.ManifestHash,Scope="FIXED_OFFLINE_RESOURCE_AND_POWERSHELL_QUALIFICATION",FormalAdmissionIssued=false}));
            profile=InstallationProfileLease.Create(state);resources=SessionResources.Create(state,version,profile,id);
            using(var package=new InstallationPackageSid(state))sid=package.Value;
            job=OwnedKernelJob.CreateEmpty(state,version);permit=new ResourceQualification(this);
            pipe=new(System.IO.Pipes.PipeDirection.In,HandleInheritability.Inheritable);reader=new StreamReader(pipe,Encoding.UTF8,false,4096,true);
            text=SessionResources.ReadBounded(reader);
            child=AtomicChild.CreateResourceQualification(layout,state,version,job,profile,permit,pipe.ClientSafePipeHandle.DangerousGetHandle());
            pipe.DisposeLocalCopyOfClientHandle();
            runtime=new ProtectionRuntimeLease(state,version,job,fences,null,resources:permit);
            _=child.ResumeQuarantined();resumed=true;runtime.Activate(20000);exited=Task.Run(child.WaitForCanaryExit);
            while(!exited.Wait(100))
            {
                runtime.AssertHealthy();
                // Fixed PowerShell waits before its workload until all held
                // members have been verified together. After release, its
                // planned exit is supervised by the runtime and exact Job
                // drain, not mistaken for a foreign process appearing.
                if(toolObserved || !resources.ToolReady())continue;
                var before=job.Observe();
                if(before.ActiveBefore==0 && before.ActiveAfter==0)continue;
                AtomicChild.InspectMembers(job,before,members=>
                {
                    var after=job.Observe();
                    if(!before.ExpectedLimits || !after.ExpectedLimits || before.ActiveBefore!=before.ActiveAfter || before.ActiveBefore is <1 or >4 ||
                        after.ActiveBefore!=after.ActiveAfter || before.ActiveBefore!=after.ActiveBefore ||
                        !before.ProcessIds.OrderBy(p=>p).SequenceEqual(after.ProcessIds.OrderBy(p=>p)) ||
                        before.ProcessIds.Length!=before.ActiveBefore || !before.ProcessIds.Contains(child.Pid) ||
                        members.Length!=before.ProcessIds.Length || members.Select(m=>m.Pid).Distinct().Count()!=members.Length)
                    {
                        state.WriteNew("resource-membership-failure-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {Before=before,Members=members,After=after}));
                        throw WfpNative.Contract("ResourceToolMembershipUnstable");
                    }
                    bool fixedTool=false;
                    foreach(var member in members)
                    {
                        var primary=member.Pid==child.Pid;
                        if(!member.MembershipConfirmed || member.Failures.Length!=0 || member.CreatedFileTime is null ||
                            member.CreatedFileTime<child.ExpectedCreatedFileTime || primary && member.CreatedFileTime!=child.ExpectedCreatedFileTime ||
                            member.Token is not {IsAppContainer:true,CapabilityCount:0,IntegritySid:"S-1-16-4096"} || member.Token.PackageSid!=sid ||
                            member.ImagePath is null)throw WfpNative.Contract("ResourceToolIdentityUnconfirmed");
                        var image=WindowsPathSeal.Canonical(member.ImagePath);
                        if(primary?!string.Equals(image,child.ExpectedImagePath,StringComparison.OrdinalIgnoreCase):
                            !string.Equals(image,SessionResources.ToolPath,StringComparison.OrdinalIgnoreCase) &&
                            !string.Equals(image,Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"conhost.exe"),StringComparison.OrdinalIgnoreCase))
                            throw WfpNative.Contract("ResourceUnexpectedToolImage");
                        if(!primary && string.Equals(image,SessionResources.ToolPath,StringComparison.OrdinalIgnoreCase))fixedTool=true;
                    }
                    if(!fixedTool)throw WfpNative.Contract("ReadyResourceToolNotInHeldJobSnapshot");
                    runtime.AssertHealthy();resources.ReleaseInspectedTool();toolObserved=true;
                });
            }
            exit=exited.GetAwaiter().GetResult();runtime.AssertHealthy();
            observed=JsonSerializer.Deserialize<ResourceChildReport>(text.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult())??throw WfpNative.Contract("ResourceChildReportMissing");
            if(exit!=0 || observed.Pid!=child.Pid || observed.Nonce!=id || !SessionResources.Qualified(observed) || !toolObserved)
                throw WfpNative.Contract("OfflineResourceOrInheritedToolBoundaryNotQualified");
            resources.AssertOutput();
        }
        catch(Exception ex){failures.Add(ex);}
        finally
        {
            permit?.Revoke();
            if(runtime is not null)
            {
                try{stopped=runtime.Stop("OFFLINE_RESOURCE_QUALIFICATION_TERMINAL");zero=stopped.FinalJob;
                    if(!stopped.QuarantineObservedBeforeStop || stopped.Failures.Length!=0 || zero?.ObservedZero!=true)throw WfpNative.Contract("ResourceQualificationStopUnconfirmed");}
                catch(Exception ex){failures.Add(ex);}
            }
            else if(job is not null)try{zero=job.AtomicAdmissionReserved?job.CloseAtomicAdmissionAndStop():job.StopAndVerifyZero();}catch(Exception ex){failures.Add(ex);}
            if(profile?.ProcessCreationAttempted==true && zero is not null)try{profile.AfterOwnedJobZero(zero);}catch(Exception ex){failures.Add(ex);}
            if(exited is not null)try{exit=exited.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();}catch(Exception ex){failures.Add(ex);}
            if(pipe is not null)try{pipe.DisposeLocalCopyOfClientHandle();}catch(Exception ex){failures.Add(ex);}
            foreach(var owned in new IDisposable?[]{child,reader,pipe,resources})try{owned?.Dispose();}catch(Exception ex){failures.Add(ex);}
            try
            {
                if(deferCleanup && failures.Count==0 && profile is not null && zero?.ObservedZero==true && observed is not null && SessionResources.Qualified(observed))
                {profile.DeferCleanupForRecovery();cleanupDeferred=true;}
                else profile?.Dispose();
            }
            catch(Exception ex){failures.Add(ex);}
            try{job?.Dispose();}catch(Exception ex){failures.Add(ex);}
            if(text is not null)try{_=text.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();}catch(Exception ex){failures.Add(ex);}
            foreach(var fence in fences)try{if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("ResourceFinalQuarantineMissing");}catch(Exception ex){failures.Add(ex);}
            foreach(var fence in fences)try{fence.Dispose();}catch(Exception ex){failures.Add(ex);}
        }
        var success=observed is not null && SessionResources.Qualified(observed) && toolObserved && zero?.ObservedZero==true && failures.Count==0;
        var report=JsonSerializer.Serialize(new {SchemaVersion=1,state.InstallationId,SessionId=id,version.Package.Release,version.Package.ManifestHash,
            Status=success?(cleanupDeferred?"OFFLINE_RESOURCE_CLOSED_JOB_CLEANUP_DEFERRED":"FIXED_OFFLINE_WORKSPACE_TOOL_AND_DENIAL_OBSERVED"):"OFFLINE_RESOURCE_SESSION_NOT_CONFIRMED",Scope="FIXED_PROFILE_WORKSPACE_WINDOWS_POWERSHELL_AND_NON_SECRET_DENIAL_FIXTURE_ONLY",
            Resumed=resumed,ChildExit=exit,Child=observed,InheritedPowerShellIdentityObserved=toolObserved,FinalJob=zero,Stop=stopped,
            CleanupDeferredForRecovery=cleanupDeferred,
            Failures=failures.SelectMany(WfpNative.Describe).ToArray(),FormalAdmissionIssued=false,LaunchAuthorized=false,NetworkOpened=false,ClaudeLaunched=false,
            AllHostResourceIsolationQualified=false,UserProjectToolchainQualified=false,FourteenEnvironmentRequirementsQualified=false,GpuQualified=false});
        state.WriteNew("resource-session-after-"+id+".json",Encoding.UTF8.GetBytes(report));return(success?0:3,report);
    }
    private (EnvironmentExpectations?,string?,string) ReadExpectations()
    {
        try
        {
            var raw=state.ReadOptional("session-environment-policy.json");
            return raw is null?(null,null,"EXPLICIT_ENVIRONMENT_EXPECTATIONS_MISSING"):
                (EnvironmentExpectations.Parse(raw.Bytes,state.InstallationId,SessionProxy.PolicySHA256),raw.SHA256,"EXPLICIT_PROTECTED_ENVIRONMENT_EXPECTATIONS");
        }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or JsonException or ArgumentException or
            InvalidOperationException or FormatException or OverflowException or System.ComponentModel.Win32Exception)
        {return(null,null,"PROTECTED_ENVIRONMENT_INTENT_INVALID_OR_UNREADABLE");}
    }
    private IReadOnlyList<EnvironmentEvidence> MissingEnvironment()=>Array.AsReadOnly(StrictEnvironmentRequirements.Required.Select(def=>new EnvironmentEvidence(
        def.Id,"UNKNOWN",SystemTestingBlocked?"NOT_RUN_SYSTEM_VALIDATION_BLOCKED":"CURRENT_BROKER_COLLECTOR_MISSING",clock.ElapsedMilliseconds,10000)).ToArray());
    private void RefreshEnvironment(bool force=false)
    {
        if(SystemTestingBlocked)return;
        var now=clock.ElapsedMilliseconds;
        if(!force && lastCollectionMs>=0 && now-lastCollectionMs<10000)return;
        var observed=MissingEnvironment().ToDictionary(e=>e.Id,StringComparer.Ordinal);
        void Set(string name,string status,string reason)=>observed[name]=new(name,status,reason,clock.ElapsedMilliseconds,10000);
        try
        {
            if(expectations is null)
            {Set("host-timezone","UNKNOWN",expectationsReason);Set("host-locale","UNKNOWN",expectationsReason);}
            else
            {
                if(state.ReadOptional("session-environment-policy.json")?.SHA256!=expectationsSHA256)
                    throw new InvalidDataException("EnvironmentIntentChanged");
                using var identity=WindowsIdentity.GetCurrent();
                if(identity.User?.Value!=expectations.OwnerSid)throw new InvalidDataException("EnvironmentIntentOwnerMismatch");
                try
                {
                // This cache belongs to this Broker process. Do not change the
                // host setting; do not retain Local across a cache refresh.
                TimeZoneInfo.ClearCachedData();
                var zone=TimeZoneInfo.Local.Id;
                _=TimeZoneInfo.FindSystemTimeZoneById(expectations.TimeZoneId);
                Set("host-timezone",zone==expectations.TimeZoneId?"PASS":"FAIL",zone==expectations.TimeZoneId?
                    "CURRENT_OS_TIMEZONE_MATCHES_EXPLICIT_INTENT_NOT_ISOLATION_PROOF":"CURRENT_OS_TIMEZONE_MISMATCH");
                }
                catch(Exception ex) when(ex is TimeZoneNotFoundException or InvalidTimeZoneException or System.Security.SecurityException or ArgumentException or InvalidOperationException)
                {Set("host-timezone","UNKNOWN","CURRENT_TIMEZONE_READ_NOT_CONFIRMED");}
                try
                {
                var user=new StringBuilder(85);var system=new StringBuilder(85);
                var userCount=GetUserDefaultLocaleName(user,user.Capacity);var systemCount=GetSystemDefaultLocaleName(system,system.Capacity);
                if(userCount is <2 or >85 || systemCount is <2 or >85 || user.Length!=userCount-1 || system.Length!=systemCount-1)
                    throw new InvalidDataException("CurrentLocaleReadUnavailable");
                var matches=user.ToString()==expectations.UserLocale && system.ToString()==expectations.SystemLocale;
                Set("host-locale",matches?"PASS":"FAIL",matches?
                    "CURRENT_OWNER_USER_AND_SYSTEM_LOCALE_MATCH_EXPLICIT_INTENT_NOT_ISOLATION_PROOF":"CURRENT_LOCALE_MISMATCH");
                }
                catch(Exception ex) when(ex is IOException or System.ComponentModel.Win32Exception or InvalidOperationException)
                {Set("host-locale","UNKNOWN","CURRENT_LOCALE_READ_NOT_CONFIRMED");}
            }
        }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or
            TimeZoneNotFoundException or InvalidTimeZoneException or ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {Set("host-timezone","UNKNOWN","CURRENT_ENVIRONMENT_INTENT_OR_OS_READ_NOT_CONFIRMED");Set("host-locale","UNKNOWN","CURRENT_ENVIRONMENT_INTENT_OR_OS_READ_NOT_CONFIRMED");}
        if(job is not null && gateway is not null && fences.Count>0)
        {
            try
            {
                gateway.AssertHealthy();
                var expected=admission is null?fences.All(f=>f.IsSessionChannel && f.Observe().FullQuarantineObserved):
                    fences.All(f=>f.IsSessionChannel && f.Observe().IPv4ProxyOnlyObserved);
                Set("owned-routing-policy",expected?"PASS":"FAIL",expected?
                    "CURRENT_SESSION_KERNEL_OBJECTS_MATCH_EXPECTED_STAGE_FUNCTIONAL_QUALIFICATION_SEPARATE":"CURRENT_SESSION_RULE_DRIFT");
                // Exact ownership alone is not end-to-end transport availability.
                Set("proxy-core","UNKNOWN","CURRENT_PROXY_IDENTITY_HELD_TRANSPORT_QUALIFICATION_MISSING");
                if(runtime?.StartupGuardObserved==true)Set("session-watchdog","PASS",
                    "CURRENT_BROKER_STARTUP_GUARD_BOUND_TO_JOB_FAULT_QUALIFICATION_SEPARATE");
            }
            catch(Exception){Set("owned-routing-policy","UNKNOWN","CURRENT_SESSION_KERNEL_READ_NOT_CONFIRMED");}
        }
        environment=Array.AsReadOnly(StrictEnvironmentRequirements.Required.Select(def=>observed[def.Id]).ToArray());
        lastCollectionMs=clock.ElapsedMilliseconds;
    }
    internal static (int ExitCode,string Report) Request(FixedLayout layout,ProtectedState state,VerifiedVersion version,bool synthetic)
    {
        var owner=new ProtectedSession(layout,state,version);
        if(!synthetic || SystemTestingBlocked)
            return(125,owner.Report(!synthetic?"DEFERRED_BY_USER":"SYSTEM_VALIDATION_BLOCKED",false,null,Array.Empty<WfpErrorEvidence>()));
        owner.RefreshEnvironment(true);
        if(!owner.PreparationEnvironmentEligible())
            return(125,owner.Report("EXPLICIT_ENVIRONMENT_PREPARATION_REFUSED",false,null,Array.Empty<WfpErrorEvidence>()));
        return owner.Execute();
    }
    private bool PreparationEnvironmentEligible()=>expectations is not null && environment.Where(e=>e.Id is "host-timezone" or "host-locale")
        .Count(e=>e.Status=="PASS" && clock.ElapsedMilliseconds-e.ObservedMs<e.ValidForMs)==2;
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
        RefreshEnvironment();
        if(SystemTestingBlocked || !EnvironmentEligible() || !SystemSecurityEligible())throw WfpNative.Contract("SessionEvidenceExpiredUnknownOrBlocked");
        state.AssertHeld();version.AssertHeld(state);
        if(state.Read("current.json",4096).SHA256!=pointerSHA256 || job is null || gateway is null || sid is null ||
            state.ReadOptional("session-environment-policy.json")?.SHA256!=expectationsSHA256 ||
            gateway.SessionId!=id || fences.Count==0 || fences.Any(f=>!f.IsSessionChannel))
            throw WfpNative.Contract("SessionInstallationPolicyOrResourceBindingDrift");
        gateway.AssertHealthy();
    }
    private void AssertPreparedCurrent(bool force=false)
    {
        AssertSystemTestingAllowed();RefreshEnvironment(force);
        state.AssertHeld();version.AssertHeld(state);
        if(!PreparationEnvironmentEligible() || state.Read("current.json",4096).SHA256!=pointerSHA256 ||
            state.ReadOptional("session-environment-policy.json")?.SHA256!=expectationsSHA256 ||
            job is null || gateway is null || sid is null || gateway.SessionId!=id || fences.Count==0 ||
            fences.Any(f=>!f.IsSessionChannel || !f.Observe().FullQuarantineObserved))
            throw WfpNative.Contract("SuspendedSessionPreparationBindingOrQuarantineDrift");
        gateway.AssertHealthy();
    }
    // Only an installed fixed canary may be CREATED SUSPENDED with this
    // capability. It cannot open forwarding or authorize ResumeThread.
    internal sealed class Preparation
    {
        private readonly ProtectedSession owner;
        private AtomicChild? child;
        private int phase;
        internal string SessionId=>owner.id;
        internal SessionProxy Gateway=>owner.gateway??throw WfpNative.Contract("SessionGatewayMissing");
        internal uint? RootPid=>child?.Pid;
        internal long? RootCreatedFileTime=>child?.ExpectedCreatedFileTime;
        internal Preparation(ProtectedSession owner){this.owner=owner;owner.AssertPreparedCurrent(true);}
        internal void BeforeCreate(OwnedKernelJob exactJob,VerifiedVersion exactVersion)
        {
            owner.AssertPreparedCurrent(true);
            if(!ReferenceEquals(exactJob,owner.job) || !ReferenceEquals(exactVersion,owner.version) ||
                Interlocked.CompareExchange(ref phase,1,0)!=0)throw WfpNative.Contract("SuspendedCreationPermitConsumedOrForeign");
        }
        internal void BindCreated(AtomicChild exactChild)
        {
            if(Volatile.Read(ref phase)!=1 || child is not null || exactChild.ExpectedPackageSid!=owner.sid)
                throw WfpNative.Contract("SuspendedCreationChildBindingRefused");
            exactChild.AssertSuspendedSessionIdentity(this);
            child=exactChild;
        }
        internal void AssertCurrent()
        {
            if(Volatile.Read(ref phase)==3)throw WfpNative.Contract("SuspendedPreparationRevoked");owner.AssertPreparedCurrent();
            child?.AssertSuspendedSessionIdentity(this);
        }
        internal void AssertRuntimeObjects(OwnedKernelJob exactJob,VerifiedVersion exactVersion,IReadOnlyList<PersistentFence> exactFences)
        {
            AssertCurrent();
            if(child is null || !ReferenceEquals(exactJob,owner.job) || !ReferenceEquals(exactVersion,owner.version) ||
                !exactFences.SequenceEqual(owner.fences))throw WfpNative.Contract("StartupGuardOwnerMismatch");
        }
        internal void ConsumeResume(AtomicChild exactChild)
        {
            if(!ReferenceEquals(child,exactChild) || Interlocked.CompareExchange(ref phase,2,1)!=1)
                throw WfpNative.Contract("SuspendedChildResumeBindingRefused");
        }
        internal void Revoke()=>Interlocked.Exchange(ref phase,3);
    }
    // An in-memory, one-use capability tied to this owner and its live objects.
    // It has no JSON constructor, file reader, reusable token or caller evidence.
    internal sealed class Admission
    {
        private readonly ProtectedSession owner;
        private readonly string bindingSHA256;
        private readonly SessionForwardingLease forwarding;
        private AtomicChild? primary;
        private int phase; // 0 issued, 2 resume consumed, 3 revoked; creation uses Preparation
        internal string SessionId=>owner.id;
        internal SessionProxy Gateway=>owner.gateway??throw WfpNative.Contract("SessionGatewayMissing");
        internal Admission(ProtectedSession owner)
        {this.owner=owner;owner.AssertCurrent();bindingSHA256=ComputeBinding();forwarding=new(()=>owner.clock.ElapsedMilliseconds);}
        internal void AssertGatewayOpening()
        {
            // Pure checks only: called inside the WFP write transaction too.
            // Do not reenter WFP reads or let an active/revoked permit reopen it.
            if(Volatile.Read(ref phase)!=0 || !owner.EnvironmentEligible() || !owner.SystemSecurityEligible())
                throw WfpNative.Contract("GatewayOpeningRequiresIssuedCurrentAdmission");
        }
        internal void AssertForwardingCurrent()
        {
            if(Volatile.Read(ref phase)!=2 || !owner.EnvironmentEligible() || !owner.SystemSecurityEligible())
                throw WfpNative.Contract("ForwardingRequiresResumedCurrentAdmission");
            forwarding.AssertCurrent();
        }
        internal void ObserveRuntimeHealthy(ProtectionRuntimeLease exactRuntime,long remainingMs)
        {
            if(!ReferenceEquals(owner.runtime,exactRuntime) || Volatile.Read(ref phase)==3)
                throw WfpNative.Contract("ForwardingHealthOwnerMismatch");
            forwarding.Renew(remainingMs);
        }
        internal void BeforeResume(AtomicChild child)
        {
            owner.RefreshEnvironment(true);
            AssertCurrent();
            forwarding.AssertCurrent();
            if(child.ExpectedPackageSid!=owner.sid || child.ExpectedImagePath!=WindowsPathSeal.Child(owner.layout.Version(owner.version.Package.Release),"bin/admin/ProtectionBroker.exe") ||
                Interlocked.CompareExchange(ref phase,2,0)!=0)throw WfpNative.Contract("SessionResumePermitConsumedOrForeign");
            (owner.preparation??throw WfpNative.Contract("SuspendedPreparationMissing")).ConsumeResume(child);
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
        internal void Revoke(){Interlocked.Exchange(ref phase,3);forwarding.Revoke();}
        internal bool Matches(Preparation prepared)=>ReferenceEquals(prepared,owner.preparation);
        internal string BindingSHA256=>bindingSHA256;
        private string ComputeBinding()=>Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
            owner.state.InstallationId,owner.version.Package.Release,owner.version.Package.ManifestHash,owner.pointerSHA256,
            SessionId=owner.id,JobId=owner.job!.JobId,AppContainerSid=owner.sid,NetworkPolicySHA256=SessionProxy.PolicySHA256,
            RootPid=owner.preparation?.RootPid,RootCreatedFileTime=owner.preparation?.RootCreatedFileTime,
            Resources=ResourceScope,EnvironmentIntentSHA256=owner.expectationsSHA256,FenceIntents=owner.fences.Select(f=>f.IntentSHA256).ToArray(),
            RequiredEnvironmentIds=StrictEnvironmentRequirements.Required.Select(def=>def.Id).ToArray()
        })));
    }
    private (int ExitCode,string Report) Execute()
    {
        InstallationProfileLease? profile=null;InstallationLoopbackLease? loopback=null;ProxyChannelLease? upstream=null;
        AtomicChild? child=null;JobSnapshot? zero=null;
        Task<uint>? exited=null;uint? childExitCode=null;
        RuntimeStop? stopObservation=null;
        var errors=new List<Exception>();bool resumed=false,completed=false;
        try
        {
            AssertPreparation();
            state.WriteNew("protected-session-preparation-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,state.InstallationId,SessionId=id,version.Package.Release,version.Package.ManifestHash,
                EnvironmentIntentSHA256=expectationsSHA256,NetworkPolicySHA256=SessionProxy.PolicySHA256,
                Scope="FIXED_INSTALLED_CANARY_CREATED_SUSPENDED_ONLY",ResumeAuthorized=false
            }));
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
            preparation=new Preparation(this);
            child=AtomicChild.CreateSession(layout,state,version,job,profile,preparation);
            runtime=new ProtectionRuntimeLease(state,version,job,fences,upstream,gateway,preparation:preparation);
            runtime.AssertHealthy();RefreshEnvironment(true);
            if(!EnvironmentEligible() || !SystemSecurityEligible())throw WfpNative.Contract("FullSessionAdmissionRefusedAfterSuspendedPreparation");
            admission=new Admission(this);
            gateway.BindAdmission(admission);
            state.WriteNew("protected-session-intent-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,SessionId=id,state.InstallationId,version.Package.Release,version.Package.ManifestHash,
                job.JobId,AppContainerSid=sid,admission.BindingSHA256,NetworkPolicySHA256=SessionProxy.PolicySHA256,
                Resources=ResourceScope,Reusable=false,Scope="FIXED_OWNED_SYNTHETIC_USING_PRODUCTION_SESSION_OWNER"
            }));
            foreach(var fence in fences)_=fence.OpenSessionGateway(gateway);
            runtime.AttachAdmission(admission);
            _=child.ResumeQuarantined(upstream,admission);resumed=true;runtime.Activate(15000);
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
            preparation?.Revoke();
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
            errors.SelectMany(WfpNative.Describe).ToArray(),stopObservation,profile?.ProcessCreationAttempted==true,child is not null,childExitCode,child?.ResumeAttempted==true);
        state.WriteNew("protected-session-result-"+id+".json",Encoding.UTF8.GetBytes(report));
        return(success?0:3,report);
    }
    private void AssertPreparation()
    {
        if(SystemTestingBlocked || !PreparationEnvironmentEligible())throw WfpNative.Contract("SessionPreparationNotAuthorized");
        state.AssertHeld();version.AssertHeld(state);LifecycleRecovery.AssertNoPending(state);InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var intent in OwnedJobIntent.ReadAll(state))
            if(AtomicJobCompletion.ReadClosed(state,intent) is null)throw WfpNative.Contract("SessionPriorAdmissionNotClosed");
    }
    private string Report(string status,bool resumed,JobSnapshot? final,WfpErrorEvidence[] failures,RuntimeStop? stopObservation=null,
        bool creationAttempted=false,bool created=false,uint? childExitCode=null,bool resumeAttempted=false)=>JsonSerializer.Serialize(new {
        SchemaVersion=1,Scope="INSTALLED_BROKER_PROTECTED_SESSION",state.InstallationId,version.Package.Release,
        version.Package.ManifestHash,SessionId=id,NetworkPolicySHA256=SessionProxy.PolicySHA256,
        EnvironmentIntentSHA256=expectationsSHA256,EnvironmentIntentStatus=expectationsReason,Resources=ResourceScope,Status=status,
        Checks=environment.Select(e=>new {e.Id,e.Status,e.Reason,Required=true,
            EvidenceAtUtc=startedUtc.AddMilliseconds(e.ObservedMs).ToString("O"),e.ValidForMs,
            Source=e.Status=="UNKNOWN"?"BROKER_COLLECTOR_UNAVAILABLE":"CURRENT_BROKER_COLLECTOR_ONLY",
            Applicability="STRICT_POLICY_NO_IMPLICIT_EXEMPTIONS",DiagnosticReportAccepted=false,CachedPassAccepted=false}),
        SystemSecurityChecks=systemSafety.Select(e=>new {e.Id,e.Status,e.Reason,Required=true}),
        SystemSecurityGates=new[]{"INCIDENT_CLEARANCE","CONFINED_GATEWAY_AND_LITERAL_UPSTREAM","CURRENT_JOB_APPCONTAINER_WFP",
            "HOST_SENSITIVE_RESOURCE_DENIAL","AUTHORIZED_WORKSPACE_TOOLCHAIN_AND_GPU"},
        ProcessCreationAttempted=creationAttempted,ProcessCreatedConfirmed=created,ProcessCreationOutcomeUnknown=creationAttempted && !created,
        ResumeAttempted=resumeAttempted,ResumeOutcomeUnknown=resumeAttempted && !resumed,
        ProcessResumed=resumed,ChildExitCode=childExitCode,FinalJob=final,Failures=failures,StopObservation=stopObservation,LaunchAuthorized=false,ClaudeLaunched=false,
        ProductionSessionQualified=false,HostInformationConfidentialityQualified=false
    });
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] private static extern int GetUserDefaultLocaleName(StringBuilder name,int capacity);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] private static extern int GetSystemDefaultLocaleName(StringBuilder name,int capacity);
}
