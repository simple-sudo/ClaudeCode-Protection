using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Security;
using ClaudeCodeProtection.Workspaces;

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
    // Chosen only by the compiled fixed gateway operation, never by data,
    // environment, persisted evidence or a formal-launch caller.
    private enum GatewayMode { None, Basic, Winsock, Transport, Provider, InternetClient, ZeroCapabilityComparison, NoContentHttps, OpenSslHead }
    private enum WinsockScope { None, Catalog, Transport, Provider }
    private sealed record GatewayQualification(WinsockScope Winsock,LpacCapabilityProfile Capabilities,bool CaptureContent,bool NoContentHttps,
        string ChildCommand,bool UsesFixedOpenSslHead=false)
    {
        internal static GatewayQualification? For(GatewayMode mode)=>mode switch {
            GatewayMode.None=>null,
            GatewayMode.Basic=>new(WinsockScope.None,LpacCapabilityProfile.None,false,false,"gateway-qualification-child"),
            GatewayMode.Winsock=>new(WinsockScope.Catalog,LpacCapabilityProfile.None,false,false,"gateway-qualification-child"),
            GatewayMode.Transport=>new(WinsockScope.Transport,LpacCapabilityProfile.None,false,false,"gateway-qualification-child"),
            GatewayMode.Provider=>new(WinsockScope.Provider,LpacCapabilityProfile.None,false,false,"gateway-qualification-child"),
            GatewayMode.InternetClient=>new(WinsockScope.Provider,LpacCapabilityProfile.InternetClientQualification,true,false,"internet-client-gateway-qualification-child"),
            GatewayMode.ZeroCapabilityComparison=>new(WinsockScope.Provider,LpacCapabilityProfile.None,true,false,"zero-capability-comparison-child"),
            GatewayMode.NoContentHttps=>new(WinsockScope.Provider,LpacCapabilityProfile.InternetClientQualification,true,true,"no-content-https-canary-child"),
            GatewayMode.OpenSslHead=>new(WinsockScope.Provider,LpacCapabilityProfile.InternetClientQualification,true,true,"fixed-openssl-head-child",true),
            _=>throw WfpNative.Contract("UnknownFixedGatewayMode")
        };
    }
    private readonly GatewayQualification? qualification;
    private bool IsGatewayQualification=>qualification is not null;
    private LpacCapabilityProfile CapabilityProfile=>qualification?.Capabilities??LpacCapabilityProfile.None;
    private bool CaptureCapabilityContent=>qualification?.CaptureContent==true;
    private bool FixedNoContentHttpsCanary=>qualification?.NoContentHttps==true;
    private bool UsesFixedOpenSslHead=>qualification?.UsesFixedOpenSslHead==true;
    private SessionWinsockReadAccess? winsockAccess;
    private const long GatewayQualificationLimitMs=30000;
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
    private GatewayChildReport? gatewayChildFeedback;
    private GatewayCapabilityChildReport? gatewayCapabilityFeedback;
    private ProtectionRuntimeLease? runtime;
    private SessionResources? resources;
    private ProtectedSession(FixedLayout layout,ProtectedState state,VerifiedVersion version,GatewayMode gatewayMode=GatewayMode.None)
    {
        qualification=GatewayQualification.For(gatewayMode);
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
    // This capability authorizes one compiled offline resource/Git program,
    // bound to this installed owner. It cannot attach Admission, open a
    // gateway or consume a formal Preparation. Caller code additionally needs
    // the explicit v6 manifest/byte binding and original-owner pre-code gate;
    // the v3 data operation never acquires that execution scope.
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
        internal void AssertExactToolJob(OwnedKernelJob job)
        {AssertCurrent();if(Volatile.Read(ref phase)!=2 || !ReferenceEquals(owner.job,job))throw WfpNative.Contract("OwnedToolExactActiveJobRequired");}
        internal void AuthorizeToolCreation(AtomicChild child,OwnedKernelJob job)
        {AssertExactToolJob(job);if(!ReferenceEquals(root,child) || !child.IsRunning)throw WfpNative.Contract("OwnedToolExactLiveRootRequired");}
        internal void RecordEtwTokenAccess(int toolPid,EtwTokenAccessCheck readback,EtwTokenAccessCheck hypothetical)
        {
            AssertCurrent();
            if(Volatile.Read(ref phase)!=2 || !Plan.RequiresPowerShell || toolPid<=0)throw WfpNative.Contract("EtwTokenComparisonScopeRefused");
            // Original owner evidence only. This is not an admission, grant,
            // tool reply or a claim to have observed ETW's kernel descriptor.
            owner.state.WriteNew("resource-tool-error-"+owner.id+"-etw-access.json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,owner.state.InstallationId,SessionId=owner.id,JobId=owner.job!.JobId,ToolPid=toolPid,PackageSid=owner.sid,
                Status="HELD_LPAC_TOKEN_ACCESSCHECK_ONLY_NO_ETW_GRANT",ProviderId=SessionEtwProviderAccess.ProviderId,
                DesiredAccess=SessionEtwProviderAccess.RegisterRight,DescriptorSource="WMI_READBACK_AND_HYPOTHETICAL_MEMORY_COPY_NOT_KERNEL_ETW_SD",
                Readback=readback,HypotheticalPackageAce=hypothetical,PermissionModified=false,AdmissionEvidence=false}));
        }
    }
    internal static (int ExitCode,string Report) QualifyResources(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>new ProtectedSession(layout,state,version).ExecuteResourceQualification();
    internal static (int ExitCode,string Report) QualifyToolchain(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>new ProtectedSession(layout,state,version).ExecuteResourceQualification(includeGit:true);
    internal static (int ExitCode,string Report) DevelopBundledProject(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>new ProtectedSession(layout,state,version).ExecuteResourceQualification(includeGit:true,workspaceInput:BundledProjectDevelopment.Baseline(),developProject:true);
    internal static (int ExitCode,string Report) DevelopBundledProjectForCaller(FixedLayout layout,ProtectedState state,VerifiedVersion version,Action assertCaller)
    {
        ArgumentNullException.ThrowIfNull(assertCaller);
        return new ProtectedSession(layout,state,version).ExecuteResourceQualification(includeGit:true,workspaceInput:BundledProjectDevelopment.Baseline(),developProject:true,assertCaller:assertCaller);
    }
    internal static (int ExitCode,string Report) BuildCallerProject(FixedLayout layout,ProtectedState state,VerifiedVersion version,byte[] bytes,Action assertCaller)
    {
        ArgumentNullException.ThrowIfNull(assertCaller);
        return new ProtectedSession(layout,state,version).ExecuteResourceQualification(includeGit:true,workspaceInput:bytes,developProject:true,callerProject:true,assertCaller:assertCaller);
    }
    // A data-only operation on the existing owner and fixed offline Git
    // program. Source/test/build files in the bundle are NEVER executed.
    internal static (int ExitCode,string Report) ProcessWorkspaceData(FixedLayout layout,ProtectedState state,VerifiedVersion version,byte[] bytes)
        =>new ProtectedSession(layout,state,version).ExecuteResourceQualification(includeGit:true,workspaceInput:bytes);
    internal static (int ExitCode,string Report) ProcessWorkspaceDataForCaller(FixedLayout layout,ProtectedState state,VerifiedVersion version,byte[] bytes,Action assertCaller)
    {
        ArgumentNullException.ThrowIfNull(assertCaller);
        return new ProtectedSession(layout,state,version).ExecuteResourceQualification(includeGit:true,workspaceInput:bytes,assertCaller:assertCaller);
    }
    internal static (int ExitCode,string Report) QualifyResourceRecovery(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        // Deliberately EXIT this installed owner with a durable cleanup
        // checkpoint. The NEXT installed invocation performs real journal
        // recovery; no live in-memory profile object is transferred to it.
        =>new ProtectedSession(layout,state,version).ExecuteResourceQualification(true);
    private (int ExitCode,string Report) ExecuteResourceQualification(bool deferCleanup=false,bool includeGit=false,byte[]? workspaceInput=null,bool developProject=false,bool callerProject=false,Action? assertCaller=null)
    {
        InstallationProfileLease? profile=null;AtomicChild? child=null;
        var (powerShellRequired,compilerRequired)=ResourceProbePlan.ToolRequirements(developProject,workspaceInput is not null);
        System.IO.Pipes.AnonymousPipeServerStream? pipe=null;StreamReader? reader=null;
        ResourceQualification? permit=null;ResourceChildReport? observed=null;Task<uint>? exited=null;Task<string>? text=null;
        ResourceBootstrapFailure? bootstrapFailure=null;
        JobSnapshot? zero=null;RuntimeStop? stopped=null;uint? exit=null;bool resumed=false,toolObserved=false,gitObserved=false,cleanupDeferred=false;
        var toolLaunch=new OwnedToolLaunch();
        var failures=new List<Exception>();
        string? workspaceResultSHA256=null;
        (int Pid,long CreatedFileTime)? projectActor=null,probeActor=null;bool probeObserved=false;HostPrivacySummary? hostPrivacy=null;
        try
        {
            assertCaller?.Invoke();
            LifecycleRecovery.AssertNoPending(state);InstallationLoopbackLease.AssertClosedHistory(state);
            foreach(var intent in OwnedJobIntent.ReadAll(state))
                if(AtomicJobCompletion.ReadClosed(state,intent) is null)throw WfpNative.Contract("ResourceQualificationPriorAdmissionNotClosed");
            var plans=FencePlan.ReadAll(state);if(plans.Count==0)throw WfpNative.Contract("ResourceQualificationNeedsExistingQuarantine");
            foreach(var plan in plans)fences.Add(PersistentFence.OpenExisting(state,plan.Data.FenceId));
            foreach(var fence in fences)if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("ResourceQualificationFullQuarantineRequired");
            state.WriteNew("resource-session-before-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,
                SessionId=id,version.Package.Release,version.Package.ManifestHash,Scope=callerProject?WorkspacePipe.CallerProjectScope:developProject?"EXPLICIT_BUNDLED_PROJECT_CODE_TASK":"FIXED_OFFLINE_RESOURCE_AND_POWERSHELL_QUALIFICATION",FormalAdmissionIssued=false}));
            assertCaller?.Invoke();
            profile=InstallationProfileLease.Create(state);resources=SessionResources.Create(state,version,profile,id,includeGit,workspaceInput,developProject,callerProject);
            using(var package=new InstallationPackageSid(state))sid=package.Value;
            job=OwnedKernelJob.CreateEmpty(state,version);permit=new ResourceQualification(this);
            pipe=new(System.IO.Pipes.PipeDirection.In,HandleInheritability.Inheritable);reader=new StreamReader(pipe,Encoding.UTF8,false,4096,true);
            text=toolLaunch.ReadMessages(reader);
            assertCaller?.Invoke();
            child=AtomicChild.CreateResourceQualification(layout,state,version,job,profile,permit,pipe.ClientSafePipeHandle.DangerousGetHandle());
            pipe.DisposeLocalCopyOfClientHandle();
            // The installed register-only ETW lease restored exactly but did
            // not repair EventRegister5. Retire that automatic permission
            // mutation; keep its journal inspection/recovery for old runs.
            runtime=new ProtectionRuntimeLease(state,version,job,fences,null,resources:permit,assertCaller:assertCaller);
            assertCaller?.Invoke();
            _=child.ResumeQuarantined();resumed=true;runtime.Activate(20000);exited=Task.Run(child.WaitForCanaryExit);
            while(!exited.Wait(100))
            {
                runtime.AssertHealthy();
                toolLaunch.ProcessPending(resources,child,job,permit);
                // Fixed PowerShell waits before its workload until all held
                // members have been verified together. After release, its
                // planned exit is supervised by the runtime and exact Job
                // drain, not mistaken for a foreign process appearing.
                var executionPhase=developProject && toolObserved;
                var probePhase=developProject && gitObserved && !resources.ProjectProbeSealed;
                if(probePhase && (probeObserved?!resources.ProjectProbePrivacyReady():!resources.ProjectProbeReady()))continue;
                if(!probePhase && executionPhase && (resources.ProjectExecutionReleased || !resources.ProjectPrivacyReady()))continue;
                var gitPhase=developProject?!gitObserved:!powerShellRequired || toolObserved;
                if(!probePhase && !executionPhase && (gitPhase?!includeGit || gitObserved || !resources.GitReady():!resources.ToolReady()))continue;
                var expectedTool=gitPhase?SessionGitToolchain.ToolPath:resources.Plan.PowerShellLaunchImage;
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
                    int fixedTools=0;
                    foreach(var member in members)
                    {
                        var primary=member.Pid==child.Pid;
                        if(!member.MembershipConfirmed || member.Failures.Length!=0 || member.CreatedFileTime is null ||
                            member.CreatedFileTime<child.ExpectedCreatedFileTime || primary && member.CreatedFileTime!=child.ExpectedCreatedFileTime ||
                            member.Token is not {IsAppContainer:true,LpacAccessCheckObserved:true,ApplicationPackageAccessMask:2,CapabilityCount:0,IntegritySid:"S-1-16-4096"} || member.Token.PackageSid!=sid ||
                            member.ImagePath is null)throw WfpNative.Contract("ResourceToolIdentityUnconfirmed");
                        var image=WindowsPathSeal.Canonical(member.ImagePath);
                        if(primary?!string.Equals(image,child.ExpectedImagePath,StringComparison.OrdinalIgnoreCase):
                            !string.Equals(image,expectedTool,StringComparison.OrdinalIgnoreCase) &&
                            !string.Equals(image,Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"conhost.exe"),StringComparison.OrdinalIgnoreCase))
                            throw WfpNative.Contract("ResourceUnexpectedToolImage");
                        if(!primary && string.Equals(image,expectedTool,StringComparison.OrdinalIgnoreCase))
                        {
                            fixedTools++;
                            if(developProject && !gitPhase)
                            {
                                var actor=(checked((int)member.Pid),member.CreatedFileTime.Value);
                                if(probePhase)
                                {
                                    if(probeObserved && probeActor!=actor)throw WfpNative.Contract("SealedPrivacyProbeIdentityChanged");
                                    probeActor=actor;
                                }
                                else if(executionPhase)
                                {
                                    if(projectActor!=actor)throw WfpNative.Contract("SealedProjectToolIdentityChanged");
                                }
                                else projectActor=actor;
                            }
                        }
                    }
                    if(fixedTools!=1)throw WfpNative.Contract("ReadyResourceToolNotUniqueInHeldJobSnapshot");
                    runtime.AssertHealthy();
                    if(probePhase)
                    {
                        if(probeObserved)resources.SealProjectProbeBeforeExit(probeActor?.Pid??throw WfpNative.Contract("PrivacyProbePidMissing"));
                        else{resources.ReleaseInspectedProbe();probeObserved=true;}
                    }
                    else if(executionPhase)resources.ReleaseProjectExecution(projectActor?.Pid??throw WfpNative.Contract("ProjectToolPidMissing"),runtime.AssertHealthy);
                    else if(gitPhase){if(developProject)resources.SealRootHostPrivacyBeforeGit(checked((int)child.Pid));resources.ReleaseInspectedGit();gitObserved=true;}
                    else{resources.ReleaseInspectedTool();toolObserved=true;}
                });
            }
            exit=exited.GetAwaiter().GetResult();runtime.AssertHealthy();
            var childText=text.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
            using(var doc=JsonDocument.Parse(childText))
                if(doc.RootElement.TryGetProperty("Scope",out var scope) && scope.GetString()=="RESOURCE_BOOTSTRAP_FAILURE")
                {
                    StrictJson.Fields(doc.RootElement,"SchemaVersion","Scope","Phase","Type","Code","NativeStage");
                    var failure=JsonSerializer.Deserialize<ResourceBootstrapFailure>(childText)??throw WfpNative.Contract("ChildBootstrapFailureMissing");
                    if(failure.SchemaVersion!=1 || failure.Phase is not ("self-token" or "resource-input") || failure.Type.Length is <1 or >80 ||
                        failure.Type.Any(c=>!char.IsAsciiLetterOrDigit(c)) || failure.NativeStage is not null && (failure.NativeStage.Length>80 || failure.NativeStage.Any(c=>!char.IsAsciiLetterOrDigit(c))))
                        throw WfpNative.Contract("ChildBootstrapFailureContractDiffers");
                    bootstrapFailure=failure;throw WfpNative.Contract("ResourceChildBootstrapFailed");
                }
            observed=JsonSerializer.Deserialize<ResourceChildReport>(childText)??throw WfpNative.Contract("ResourceChildReportMissing");
            if(exit!=0 || observed.Pid!=child.Pid || observed.Nonce!=id || !SessionResources.Qualified(observed,compilerRequired) || compilerRequired && !toolObserved ||
                includeGit && (!gitObserved || observed.Git is null) || !includeGit && observed.Git is not null || developProject && !resources.ProjectExecutionReleased)
                throw WfpNative.Contract("OfflineResourceOrInheritedToolBoundaryNotQualified");
        }
        catch(Exception ex){failures.Add(ex);}
        finally
        {
            permit?.Revoke();
            var closedResources=false;
            if(runtime is not null)
            {
                try
                {
                    stopped=runtime.Stop(RuntimeStop.ResourceTerminalReason);zero=stopped.FinalJob;
                    if(job is null || !stopped.ConfirmsClosedResources(id,job.JobId))throw WfpNative.Contract("ResourceQualificationStopUnconfirmed");
                    closedResources=true;
                }
                catch(Exception ex){failures.Add(ex);}
            }
            else if(job is not null)try{zero=job.AtomicAdmissionReserved?job.CloseAtomicAdmissionAndStop():job.StopAndVerifyZero();}catch(Exception ex){failures.Add(ex);}
            if(profile?.ProcessCreationAttempted==true && zero is not null)try{profile.AfterOwnedJobZero(zero);}catch(Exception ex){failures.Add(ex);}
            if(developProject && resources is not null && child is not null && closedResources)
                try
                {
                    hostPrivacy=resources.ReadClosedHostPrivacy(checked((int)child.Pid),projectActor?.Pid);
                    HostPrivacyContract.Validate(hostPrivacy,id,true);
                }
                catch(Exception ex){failures.Add(ex);}
            if(closedResources && failures.Count==0 && zero is not null && observed is not null && resources is not null)
                try
                {
                    assertCaller?.Invoke();
                    resources.AssertOutput(observed);
                    if(includeGit)workspaceResultSHA256=resources.PreserveClosedWorkspaceResult(zero,assertCaller);
                }
                catch(Exception ex){failures.Add(ex);}
            if(exited is not null)try{exit=exited.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();}catch(Exception ex){failures.Add(ex);}
            if(pipe is not null)try{pipe.DisposeLocalCopyOfClientHandle();}catch(Exception ex){failures.Add(ex);}
            if(closedResources && failures.Count!=0)try{resources?.PreserveGitFailure();}catch(Exception ex){failures.Add(ex);}
            foreach(var owned in new IDisposable?[]{child,reader,pipe,resources})try{owned?.Dispose();}catch(Exception ex){failures.Add(ex);}
            try
            {
                if(deferCleanup && failures.Count==0 && profile is not null && zero?.ObservedZero==true && observed is not null && SessionResources.Qualified(observed,powerShellRequired))
                {profile.DeferCleanupForRecovery();cleanupDeferred=true;}
                else profile?.Dispose();
            }
            catch(Exception ex){failures.Add(ex);}
            try{job?.Dispose();}catch(Exception ex){failures.Add(ex);}
            if(text is not null)try{_=text.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();}catch(Exception ex){failures.Add(ex);}
            foreach(var fence in fences)try{if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("ResourceFinalQuarantineMissing");}catch(Exception ex){failures.Add(ex);}
            foreach(var fence in fences)try{fence.Dispose();}catch(Exception ex){failures.Add(ex);}
        }
        // Cleanup is independent of the caller. A result written before a
        // late disconnect stays private and must not get a success receipt.
        if(workspaceResultSHA256 is not null && failures.Count==0)
            try{assertCaller?.Invoke();}catch(Exception ex){failures.Add(ex);}
        var success=observed is not null && SessionResources.Qualified(observed,compilerRequired) && (!compilerRequired || toolObserved) && (!includeGit || gitObserved && observed.Git is not null && workspaceResultSHA256 is not null) && zero?.ObservedZero==true && failures.Count==0;
        var report=JsonSerializer.Serialize(new {SchemaVersion=1,state.InstallationId,SessionId=id,version.Package.Release,version.Package.ManifestHash,
            Status=success?(callerProject?"CALLER_CSHARP_PROJECT_BUILT_AND_CLEANED":developProject?"BUNDLED_PROJECT_DEVELOPED_AND_CLEANED":workspaceInput is not null?"WORKSPACE_DATA_PROCESSED_AND_CLEANED":cleanupDeferred?"OFFLINE_RESOURCE_CLOSED_JOB_CLEANUP_DEFERRED":includeGit?"FIXED_OFFLINE_GIT_TOOLCHAIN_AND_DENIAL_OBSERVED":"FIXED_OFFLINE_WORKSPACE_TOOL_AND_DENIAL_OBSERVED"):"OFFLINE_RESOURCE_SESSION_NOT_CONFIRMED",
            Scope=callerProject?WorkspacePipe.CallerProjectScope:developProject?"EXPLICIT_TEXTSUMMARY_SOURCE_EDIT_BUILD_RUN_TEST":workspaceInput is not null?"CALLER_BYTE_PINNED_DATA_FIXED_OFFLINE_GIT_ONLY_NO_PROJECT_CODE_EXECUTION":includeGit?"FIXED_OFFLINE_GIT_INIT_ADD_COMMIT_AND_DENIAL_ONLY":"FIXED_PROFILE_WORKSPACE_WINDOWS_POWERSHELL_AND_NON_SECRET_DENIAL_FIXTURE_ONLY",
            Resumed=resumed,ChildExit=exit,Child=observed,ChildBootstrapFailure=bootstrapFailure,InheritedPowerShellIdentityObserved=powerShellRequired && toolObserved,FinalJob=zero,Stop=stopped,
            ProjectDevelopmentRequested=developProject,InheritedProjectToolIdentityObserved=developProject && toolObserved,
            ProjectExecutionPermitConsumedAfterOwnerSealedPrivacy=developProject && resources?.ProjectExecutionReleased==true,
            HostPrivacy=hostPrivacy,
            CleanupDeferredForRecovery=cleanupDeferred,ManifestReadAccessRequired=false,ManifestReadAccessRestored=false,
            PowerShellRequired=powerShellRequired,PowerShellVersion=powerShellRequired?SessionPowerShellToolchain.Version:null,PowerShellAssetSetSHA256=powerShellRequired?SessionPowerShellToolchain.AssetSetSHA256:null,
            EtwRegistrationAccessGranted=false,EtwRegistrationAccessRestored=false,
            EtwProvider=SessionEtwProviderAccess.ProviderId,EtwRegistrationRights=0,
            ToolCreationOwner="ORIGINAL_BROKER",ToolCreationBinding="ATOMIC_LPAC_PACKAGE_AND_ORIGINAL_JOB_NOT_PARENT_INHERITANCE",
            InheritedGitIdentityObserved=gitObserved,GitAssetSetSHA256=resources?.Plan.GitAssetSetSHA256,
            WorkspaceBaselineSHA256=includeGit && resources is not null?resources.Plan.WorkspaceInputSHA256??ClaudeCodeProtection.Workspaces.WorkspaceBundle.Hash(resources.Plan.FixedProjectBundle):null,
            ClosedWorkspaceResultSHA256=workspaceResultSHA256,
            Failures=failures.SelectMany(WfpNative.Describe).ToArray(),FormalAdmissionIssued=false,LaunchAuthorized=false,NetworkOpened=false,ClaudeLaunched=false,
            Boundary="LPAC_REQUIRED_NO_CAPABILITIES_NO_FALLBACK",AllHostResourceIsolationQualified=false,UserProjectToolchainQualified=false,FourteenEnvironmentRequirementsQualified=false,GpuQualified=false});
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
    // A finite installed canary obtains no formal environment/security PASS and
    // cannot accept projects, tools, targets or serialized permits. It uses the
    // same suspended creation, admission, forwarding and stop owners.
    internal static (int ExitCode,string Report) QualifySessionGateway(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>QualifyGateway(layout,state,version,GatewayMode.Basic);
    internal static (int ExitCode,string Report) QualifyWinsockSessionGateway(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>QualifyGateway(layout,state,version,GatewayMode.Winsock);
    internal static (int ExitCode,string Report) QualifyWinsockTransportSessionGateway(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>QualifyGateway(layout,state,version,GatewayMode.Transport);
    internal static (int ExitCode,string Report) QualifyWinsockProviderSessionGateway(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>QualifyGateway(layout,state,version,GatewayMode.Provider);
    internal static (int ExitCode,string Report) QualifyInternetClientSessionGateway(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>QualifyGateway(layout,state,version,GatewayMode.InternetClient);
    internal static (int ExitCode,string Report) QualifyNoContentHttpsCanary(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>QualifyGateway(layout,state,version,GatewayMode.NoContentHttps);
    internal static (int ExitCode,string Report) QualifyFixedOpenSslHead(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>QualifyGateway(layout,state,version,GatewayMode.OpenSslHead);
    internal static (int ExitCode,string Report) QualifyZeroCapabilityComparisonGateway(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>QualifyGateway(layout,state,version,GatewayMode.ZeroCapabilityComparison);
    private static (int ExitCode,string Report) QualifyGateway(FixedLayout layout,ProtectedState state,VerifiedVersion version,GatewayMode mode)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);
        var owner=new ProtectedSession(layout,state,version,mode);
        if(owner.qualification is null)throw WfpNative.Contract("FixedGatewayQualificationRequired");
        var resolverTrust=owner.UsesFixedOpenSslHead?FixedResolverTrust.ReadOwned(version.Package):null;
        if(owner.qualification.Winsock!=WinsockScope.None)SessionWinsockReadAccess.RequireCurrentRootControl();
        return owner.Execute(resolverTrust);
    }
    private bool CurrentWorkloadEvidenceEligible()=>IsGatewayQualification?
        clock.ElapsedMilliseconds>=0 && clock.ElapsedMilliseconds<GatewayQualificationLimitMs:
        !SystemTestingBlocked && EnvironmentEligible() && SystemSecurityEligible();
    private void AssertQualificationBinding(bool quarantine)
    {
        state.AssertHeld();version.AssertHeld(state);
        if(!IsGatewayQualification || !CurrentWorkloadEvidenceEligible() || resources is not null ||
            state.Read("current.json",4096).SHA256!=pointerSHA256 || job is null || gateway is null || sid is null ||
            gateway.SessionId!=id || fences.Count==0 || fences.Any(f=>!f.IsSessionChannel || quarantine && !f.Observe().FullQuarantineObserved))
            throw WfpNative.Contract("FixedGatewayQualificationExpiredOrBindingDrift");
        if(preparation?.RootPid is not null)
            (preparation.PublicTimeZone??throw WfpNative.Contract("TimeZoneResourceNotPrepared")).AssertCurrent();
        if(UsesFixedOpenSslHead)
        {
            FixedOpenSslHeadTrust.RequireCurrent(DateTimeOffset.UtcNow);
            FixedResolverTrust.RequireCurrent(DateTimeOffset.UtcNow);
        }
        winsockAccess?.AssertHeld();
        gateway.AssertHealthy();
    }
    private bool PreparationEnvironmentEligible()=>expectations is not null && environment.Where(e=>e.Id is "host-timezone" or "host-locale")
        .Count(e=>e.Status=="PASS" && clock.ElapsedMilliseconds-e.ObservedMs<e.ValidForMs)==2;
    private bool EnvironmentEligible()=>environment.Count==StrictEnvironmentRequirements.Required.Count &&
        environment.Select(e=>e.Id).Distinct(StringComparer.Ordinal).Count()==environment.Count &&
        StrictEnvironmentRequirements.Required.All(def=>environment.Any(e=>e.Id==def.Id)) &&
        environment.All(e=>e.Status=="PASS" && e.ValidForMs is >0 and <=120000 &&
            clock.ElapsedMilliseconds>=e.ObservedMs && clock.ElapsedMilliseconds-e.ObservedMs<e.ValidForMs);
    private bool SystemSecurityEligible()=>systemSafety.Select(e=>e.Id).SequenceEqual(SystemRequirements) &&
        systemSafety.All(e=>e.Status=="PASS" && e.ValidForMs is >0 and <=120000 &&
            clock.ElapsedMilliseconds>=e.ObservedMs && clock.ElapsedMilliseconds-e.ObservedMs<e.ValidForMs);
    private void AssertCurrent()
    {
        if(IsGatewayQualification){AssertQualificationBinding(quarantine:false);return;}
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
        if(IsGatewayQualification){AssertQualificationBinding(quarantine:true);return;}
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
        internal bool IsGatewayQualification=>owner.IsGatewayQualification;
        internal LpacCapabilityProfile CapabilityProfile=>owner.CapabilityProfile;
        internal string ChildCommand=>owner.qualification?.ChildCommand??"admission-child";
        internal bool FixedNoContentHttpsCanary=>owner.FixedNoContentHttpsCanary;
        internal bool UsesFixedOpenSslHead=>owner.UsesFixedOpenSslHead;
        internal string? PublicTimeZoneId {get;}
        internal PublicTimeZoneSnapshot? PublicTimeZone {get;}
        internal SessionProxy Gateway=>owner.gateway??throw WfpNative.Contract("SessionGatewayMissing");
        internal uint? RootPid=>child?.Pid;
        internal long? RootCreatedFileTime=>child?.ExpectedCreatedFileTime;
        internal Preparation(ProtectedSession owner)
        {
            this.owner=owner;owner.AssertPreparedCurrent(true);
            if(owner.IsGatewayQualification)
            {
                PublicTimeZone=PublicTimeZoneSnapshot.Capture(owner.id);
                PublicTimeZoneId=PublicTimeZone.TimeZoneId;
            }
        }
        internal void BeforeCreate(OwnedKernelJob exactJob,VerifiedVersion exactVersion)
        {
            owner.AssertPreparedCurrent(true);
            PublicTimeZone?.AssertCurrent();
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
        internal bool IsFixedGatewayQualification=>owner.IsGatewayQualification;
        internal bool FixedNoContentHttpsCanary=>owner.FixedNoContentHttpsCanary;
        internal bool UsesFixedOpenSslHead=>owner.UsesFixedOpenSslHead;
        internal LpacCapabilityProfile CapabilityProfile=>owner.CapabilityProfile;
        internal void AssertFixedGatewayRoot((uint Pid,long CreatedFileTime) peer)
        {
            var root=primary;
            if(!IsFixedGatewayQualification || root is null || !MatchesFixedGatewayRoot(peer,root.Pid,root.ExpectedCreatedFileTime))
                throw WfpNative.Contract("FixedGatewayPeerIsNotPreparedRoot");
        }
        internal static bool MatchesFixedGatewayRoot((uint Pid,long CreatedFileTime) peer,uint rootPid,long rootCreatedFileTime)
            =>rootPid!=0 && rootCreatedFileTime>0 && peer==(rootPid,rootCreatedFileTime);
        internal Admission(ProtectedSession owner)
        {this.owner=owner;owner.AssertCurrent();bindingSHA256=ComputeBinding();forwarding=new(()=>owner.clock.ElapsedMilliseconds);}
        internal void AssertGatewayOpening()
        {
            // Pure checks only: called inside the WFP write transaction too.
            // Do not reenter WFP reads or let an active/revoked permit reopen it.
            if(Volatile.Read(ref phase)!=0 || !owner.CurrentWorkloadEvidenceEligible())
                throw WfpNative.Contract("GatewayOpeningRequiresIssuedCurrentAdmission");
        }
        internal void AssertForwardingCurrent()
        {
            if(Volatile.Read(ref phase)!=2 || !owner.CurrentWorkloadEvidenceEligible())
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
                AtomicChild.InspectMembers(owner.job,before,members=>WatchdogMemberPolicy.VerifyWithCapabilities(before,members,owner.job.Observe(),
                    primary.Pid,primary.ExpectedCreatedFileTime,owner.sid!,primary.ExpectedImagePath,
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"conhost.exe"),requireLpac:true,capabilities:owner.CapabilityProfile));
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
            Resources=ResourceScope,FixedGatewayQualification=owner.IsGatewayQualification,TimeZoneReadIntentSHA256=(string?)null,
            ExpectedCapabilitiesSHA256=owner.CapabilityProfile.SHA256,
            CaptureCapabilityContent=owner.CaptureCapabilityContent,
            FixedNoContentHttpsCanary=owner.FixedNoContentHttpsCanary,
            FixedOpenSslHead=owner.UsesFixedOpenSslHead,
            WinsockReadIntentSHA256=owner.winsockAccess?.IntentSHA256,
            PublicTimeZoneSnapshotSHA256=owner.preparation?.PublicTimeZone?.SHA256,EnvironmentIntentSHA256=owner.expectationsSHA256,FenceIntents=owner.fences.Select(f=>f.IntentSHA256).ToArray(),
            RequiredEnvironmentIds=StrictEnvironmentRequirements.Required.Select(def=>def.Id).ToArray()
        })));
    }
    private (int ExitCode,string Report) Execute(FixedResolverTrust? resolverTrust=null)
    {
        InstallationProfileLease? profile=null;InstallationLoopbackLease? loopback=null;ProxyChannelLease? upstream=null;
        AtomicChild? child=null;JobSnapshot? zero=null;
        Task<uint>? exited=null;uint? childExitCode=null;
        System.IO.Pipes.AnonymousPipeServerStream? feedbackPipe=null;StreamReader? feedbackReader=null;Task<string>? feedbackText=null;bool feedbackReadAttempted=false;
        void ReadFixedFeedback()
        {
            if(!IsGatewayQualification || feedbackReadAttempted || child is null || childExitCode is null || feedbackText is null)return;
            feedbackReadAttempted=true;
            var raw=feedbackText.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult();
            if(CaptureCapabilityContent)
            {
                state.WriteNew("gateway-capability-content-"+id+".json",Encoding.UTF8.GetBytes(raw));
                gatewayCapabilityFeedback=GatewayCapabilityChildReport.ParseForPurpose(raw,id,child.Pid,childExitCode.Value,child.ExpectedCreatedFileTime,FixedNoContentHttpsCanary);
                gatewayChildFeedback=gatewayCapabilityFeedback.Gateway;
            }
            else gatewayChildFeedback=GatewayChildReport.Parse(raw,id,child.Pid,childExitCode.Value);
        }
        RuntimeStop? stopObservation=null;
        var errors=new List<Exception>();bool resumed=false,completed=false;var fixedExchangeObserved=false;
        try
        {
            AssertPreparation();
            state.WriteNew("protected-session-preparation-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,state.InstallationId,SessionId=id,version.Package.Release,version.Package.ManifestHash,
                EnvironmentIntentSHA256=expectationsSHA256,NetworkPolicySHA256=SessionProxy.PolicySHA256,
                Scope="FIXED_INSTALLED_CANARY_CREATED_SUSPENDED_ONLY",ResumeAuthorized=false
            }));
            if(IsGatewayQualification)PrepareQualificationGatewayPolicy();
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
            upstream=ProxyChannelLease.Open(state);
            gateway=new SessionProxy(job,upstream,sid,id,CapabilityProfile,FixedNoContentHttpsCanary,resolverTrust);
            loopback=InstallationLoopbackLease.Enable(state,false);
            preparation=new Preparation(this);
            if(IsGatewayQualification)
            {
                feedbackPipe=new(System.IO.Pipes.PipeDirection.In,HandleInheritability.Inheritable);
                feedbackReader=new StreamReader(feedbackPipe,new UTF8Encoding(false,true),false,1024,true);
                feedbackText=CaptureCapabilityContent?GatewayCapabilityChildReport.ReadBounded(feedbackReader):GatewayChildReport.ReadBounded(feedbackReader);
            }
            child=AtomicChild.CreateSession(layout,state,version,job,profile,preparation,feedbackPipe?.ClientSafePipeHandle.DangerousGetHandle()??IntPtr.Zero);
            feedbackPipe?.DisposeLocalCopyOfClientHandle();
            if(qualification is {Winsock: not WinsockScope.None} fixedGateway)
            {
                var scope=fixedGateway.Winsock;
                winsockAccess=SessionWinsockReadAccess.Prepare(state,version,job,id,
                    scope is WinsockScope.Transport or WinsockScope.Provider,scope==WinsockScope.Provider);
                winsockAccess.Apply();
            }
            // Calendar compatibility remains process-local. Only the distinct
            // compiled Winsock qualification requests the exact registry lease.
            runtime=new ProtectionRuntimeLease(state,version,job,fences,upstream,gateway,preparation:preparation);
            runtime.AssertHealthy();RefreshEnvironment(true);
            if(!CurrentWorkloadEvidenceEligible())throw WfpNative.Contract("FullSessionAdmissionRefusedAfterSuspendedPreparation");
            admission=new Admission(this);
            gateway.BindAdmission(admission);
            state.WriteNew("protected-session-intent-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,SessionId=id,state.InstallationId,version.Package.Release,version.Package.ManifestHash,
                job.JobId,AppContainerSid=sid,admission.BindingSHA256,NetworkPolicySHA256=SessionProxy.PolicySHA256,
                ExpectedCapabilityProfile=CapabilityProfile.Id,ExpectedCapabilitiesSHA256=CapabilityProfile.SHA256,
                Resources=ResourceScope,Reusable=false,FixedWorkloadPermitIssued=true,FormalAdmissionIssued=false,
                Scope=IsGatewayQualification?"FIXED_GATEWAY_QUALIFICATION_NO_FORMAL_LAUNCH":"FIXED_OWNED_SYNTHETIC_USING_PRODUCTION_SESSION_OWNER"
            }));
            foreach(var fence in fences)_=fence.OpenSessionGateway(gateway);
            runtime.AttachAdmission(admission);
            _=child.ResumeQuarantined(upstream,admission);resumed=true;runtime.Activate(15000);
            exited=Task.Run(child.WaitForCanaryExit);
            while(!exited.Wait(100))runtime.AssertHealthy();
            runtime.AssertHealthy();
            childExitCode=exited.GetAwaiter().GetResult();
            ReadFixedFeedback();
            if(childExitCode!=42)throw WfpNative.Contract("SessionSyntheticWorkloadFailed");
            if(IsGatewayQualification)
            {
                if(gatewayChildFeedback is not {Phase:"COMPLETE",HttpStatus:>=200 and <400})throw WfpNative.Contract("FixedGatewayTerminalFeedbackMissing");
                gateway.RequireFixedExchange(child.Pid,child.ExpectedCreatedFileTime);
                runtime.AssertHealthy();fixedExchangeObserved=true;
            }
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
            if(winsockAccess is not null && zero is not null)try{winsockAccess.RestoreAfterClosedJob(zero);}catch(Exception ex){errors.Add(ex);}
            if(profile?.ProcessCreationAttempted==true && zero is not null)try{profile.AfterOwnedJobZero(zero);}catch(Exception ex){errors.Add(ex);}
            if(exited is not null)
                try{childExitCode=exited.WaitAsync(TimeSpan.FromSeconds(3)).GetAwaiter().GetResult();}catch(Exception ex){errors.Add(ex);}
            try{feedbackPipe?.DisposeLocalCopyOfClientHandle();}catch(Exception ex){errors.Add(ex);}
            try{ReadFixedFeedback();}catch(Exception ex){errors.Add(ex);}
            // Stop/zero precedes profile and exact loopback removal. A failure
            // in one cleanup must not suppress the other owners' attempts.
            foreach(var resource in new IDisposable?[]{winsockAccess,child,gateway,loopback,profile,job,feedbackReader,feedbackPipe})
                try{resource?.Dispose();}catch(Exception ex){errors.Add(ex);}
            foreach(var fence in fences)try{fence.Dispose();}catch(Exception ex){errors.Add(ex);}
            try{upstream?.Dispose();}catch(Exception ex){errors.Add(ex);}
            if(feedbackText is not null)try{_=feedbackText.WaitAsync(TimeSpan.FromSeconds(3)).GetAwaiter().GetResult();}
                catch(Exception ex){if(resumed && !feedbackReadAttempted)errors.Add(ex);}
        }
        var success=completed && zero?.ObservedZero==true && errors.Count==0;
        var report=Report(success?(IsGatewayQualification?"FIXED_GATEWAY_QUALIFICATION_CLOSED":"FIXED_SYNTHETIC_SESSION_CLOSED"):"PROTECTED_SESSION_NOT_CONFIRMED",resumed,zero,
            errors.SelectMany(WfpNative.Describe).ToArray(),stopObservation,profile?.ProcessCreationAttempted==true,child is not null,childExitCode,child?.ResumeAttempted==true,fixedExchangeObserved);
        state.WriteNew("protected-session-result-"+id+".json",Encoding.UTF8.GetBytes(report));
        return(success?0:3,report);
    }
    private void PrepareQualificationGatewayPolicy()
    {
        // Only the original known raw-proxy policy may move to the current
        // gateway. Unknown/older gateway policies and pending migrations fail.
        FencePlan.AssertNoPendingMigration(state);
        var plans=FencePlan.ReadAll(state);
        if(plans.Any(p=>!(p.Data.PolicySHA256==CompiledFencePolicy.SHA256 && p.Data.ProxyPort==CompiledFencePolicy.ProxyPort) &&
            !(p.Data.PolicySHA256==SessionProxy.PolicySHA256 && p.Data.ProxyPort==SessionProxy.Port)))
            throw WfpNative.Contract("UnrecognizedGatewayQualificationPolicyRequiresReview");
        using var jobs=RegisteredJobSet.OpenForMaintenance(state);jobs.AssertClosedAdmissionsForNetworkMaintenance();
        foreach(var plan in plans)
        {
            using(var fence=PersistentFence.OpenExisting(state,plan.Data.FenceId))
                if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("GatewayQualificationRequiresInitialQuarantine");
            if(plan.Data.PolicySHA256==CompiledFencePolicy.SHA256)
                _=PersistentFence.MigrateRawProxyToSession(state,version,plan.Data.FenceId,jobs);
        }
        FencePlan.AssertNoPendingMigration(state);
    }
    private void AssertPreparation()
    {
        if(IsGatewayQualification?!CurrentWorkloadEvidenceEligible():SystemTestingBlocked || !PreparationEnvironmentEligible())
            throw WfpNative.Contract("SessionPreparationNotAuthorized");
        state.AssertHeld();version.AssertHeld(state);LifecycleRecovery.AssertNoPending(state);InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var intent in OwnedJobIntent.ReadAll(state))
            if(AtomicJobCompletion.ReadClosed(state,intent) is null)throw WfpNative.Contract("SessionPriorAdmissionNotClosed");
    }
    private string Report(string status,bool resumed,JobSnapshot? final,WfpErrorEvidence[] failures,RuntimeStop? stopObservation=null,
        bool creationAttempted=false,bool created=false,uint? childExitCode=null,bool resumeAttempted=false,bool fixedExchangeObserved=false)=>JsonSerializer.Serialize(new {
        SchemaVersion=1,Scope=IsGatewayQualification?"INSTALLED_FIXED_GATEWAY_QUALIFICATION":"INSTALLED_BROKER_PROTECTED_SESSION",state.InstallationId,version.Package.Release,
        version.Package.ManifestHash,SessionId=id,NetworkPolicySHA256=SessionProxy.PolicySHA256,
        ExpectedCapabilityProfile=CapabilityProfile.Id,ExpectedCapabilitiesSHA256=CapabilityProfile.SHA256,
        CapabilityContentComparison=CaptureCapabilityContent,
        FixedNoContentHttpsCanary=FixedNoContentHttpsCanary,
        FixedOpenSslHead=UsesFixedOpenSslHead,
        CapabilityContentPrivacyQualified=false,
        EffectiveGatewayPolicySHA256=gateway?.EffectivePolicySHA256,
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
        FixedGatewayQualification=IsGatewayQualification,FormalAdmissionIssued=false,
        GatewayChildFeedback=gatewayChildFeedback,GatewayFailure=gateway?.FailureFeedback,GatewayChildFeedbackUsedForAdmission=false,
        ResolverTls=gateway?.ResolverTls,
        TargetTunnel=gateway?.TargetTunnel,
        CapabilityContentEvidence=gatewayCapabilityFeedback,
        FixedGatewayRootBidirectionalWriteObserved=fixedExchangeObserved,
        PublicTimeZoneReadResource=(object?)null,
        WinsockReadResource=winsockAccess is null?(object?)null:new{winsockAccess.KeyCount,winsockAccess.Restored,winsockAccess.IntentSHA256},
        PublicTimeZoneProjection=preparation?.PublicTimeZone is not PublicTimeZoneSnapshot zone?null:new {
            Source="ORIGINAL_OWNER_PUBLIC_CALENDAR",SnapshotSHA256=zone.SHA256,CoreLibModule=PublicTimeZoneSnapshot.CoreLibModule,
            HostRegistryAclModified=false,RegistryCapabilityAdded=false,CompatibilityOnly=true,RequiredBeforeHttps=true},
        ProductionSessionQualified=false,HostInformationConfidentialityQualified=false
    });
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] private static extern int GetUserDefaultLocaleName(StringBuilder name,int capacity);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] private static extern int GetSystemDefaultLocaleName(StringBuilder name,int capacity);
}
