using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Security;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal sealed partial class ProtectedSession
{
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
    internal static (int ExitCode,string Report) QualifyReviewedProxyRoute(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>QualifyGateway(layout,state,version,GatewayMode.ReviewedRouteOpenSslHead);
    internal static (int ExitCode,string Report) QualifyLocalManagementBoundary(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>QualifyGateway(layout,state,version,GatewayMode.LocalManagement);
    internal static (int ExitCode,string Report) QualifyZeroCapabilityComparisonGateway(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>QualifyGateway(layout,state,version,GatewayMode.ZeroCapabilityComparison);
    private static (int ExitCode,string Report) QualifyGateway(FixedLayout layout,ProtectedState state,VerifiedVersion version,GatewayMode mode)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);
        if(mode==GatewayMode.ReviewedRouteOpenSslHead && version.Package.SchemaVersion is not
            (PackageAssetCatalog.ReviewedProxyRouteSchema or PackageAssetCatalog.SessionZeroGitInitSchema or PackageAssetCatalog.SessionZeroCudaSchema or PackageAssetCatalog.SessionZeroCudaSplitInitSchema or PackageAssetCatalog.SessionZeroCudaAccessTraceSchema or PackageAssetCatalog.SessionZeroCudaMappedFaultSchema or PackageAssetCatalog.SessionZeroCudaWddmSchema or PackageAssetCatalog.SessionZeroCudaWddmSelfHandleSchema or PackageAssetCatalog.SessionZeroCudaDeferredPreloadSchema or PackageAssetCatalog.SessionZeroCudaInitializationTraceSchema or PackageAssetCatalog.SessionZeroCudaHelperPathSchema or PackageAssetCatalog.SessionZeroCudaRegistryCallsSchema or PackageAssetCatalog.SessionZeroCudaGraphicsReadSchema or PackageAssetCatalog.SessionZeroCudaGraphicsRootSchema or PackageAssetCatalog.SessionZeroCudaDeviceIdentitySchema or PackageAssetCatalog.SessionZeroGitTrackedCommitSchema))
            throw WfpNative.Contract("ReviewedRouteRequiresFixedPackageSchema");
        var owner=new ProtectedSession(layout,state,version,mode);
        if(owner.qualification is null)throw WfpNative.Contract("FixedGatewayQualificationRequired");
        var resolverTrust=owner.UsesFixedOpenSslHead?FixedResolverTrust.ReadOwned(version.Package):null;
        if(owner.qualification.Winsock!=WinsockScope.None)SessionWinsockReadAccess.RequireCurrentRootControl();
        return owner.Execute(resolverTrust);
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
            if(IsLocalManagementBoundary)
            {
                localManagementFeedback=LocalManagementBoundaryReport.Parse(raw,id,child.Pid,childExitCode.Value);
                if(localManagementFeedback.Attempts.Any(attempt=>attempt.Received.Length>0))
                    state.WriteNew("local-management-restricted-"+id+".json",Encoding.UTF8.GetBytes(raw));
            }
            else if(CaptureCapabilityContent)
            {
                state.WriteNew("gateway-capability-content-"+id+".json",Encoding.UTF8.GetBytes(raw));
                gatewayCapabilityFeedback=GatewayCapabilityChildReport.ParseForPurpose(raw,id,child.Pid,childExitCode.Value,child.ExpectedCreatedFileTime,FixedNoContentHttpsCanary);
                gatewayChildFeedback=gatewayCapabilityFeedback.Gateway;
            }
            else gatewayChildFeedback=GatewayChildReport.Parse(raw,id,child.Pid,childExitCode.Value);
        }
        RuntimeStop? stopObservation=null;
        var errors=new List<Exception>();bool resumed=false,completed=false;
        (uint Pid,long CreatedFileTime)? fixedRootIdentity=null;
        try
        {
            AssertPreparation();
            if(RequiresReviewedProxyRoute)
            {
                // A route refusal must not leave a Job intent without an admission receipt.
                upstream=ProxyChannelLease.Open(state);
                proxyRoute=ProxyRouteObservation.Capture(upstream).GetAwaiter().GetResult();
                proxyRoute.RequireAllowed("UpstreamRouteSnapshotRefused");
            }
            state.WriteNew("protected-session-preparation-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,state.InstallationId,SessionId=id,version.Package.Release,version.Package.ManifestHash,
                EnvironmentIntentSHA256=expectationsSHA256,NetworkPolicySHA256=SessionProxy.PolicySHA256,
                Scope="FIXED_INSTALLED_CANARY_CREATED_SUSPENDED_ONLY",ResumeAuthorized=false
            }));
            if(IsGatewayQualification && !RequiresReviewedProxyRoute)PrepareQualificationGatewayPolicy();
            var plans=FencePlan.ReadAll(state);
            // Legacy 7890 barriers are retained for recovery, never silently
            // adopted as gateway policy or removed to make a launch succeed.
            if(plans.Any(plan=>plan.Data.PolicySHA256!=SessionProxy.PolicySHA256 || plan.Data.ProxyPort!=SessionProxy.Port))
                throw WfpNative.Contract("LegacyRawProxyFenceRequiresReviewedMigration");
            if(IsGatewayQualification && RequiresReviewedProxyRoute && plans.Count==0)
                throw WfpNative.Contract("ReviewedRouteRequiresExistingSessionFence");
            if(plans.Count==0)fences.Add(PersistentFence.CreateSessionQuarantined(state,version));
            else foreach(var plan in plans)fences.Add(PersistentFence.OpenExisting(state,plan.Data.FenceId));
            foreach(var fence in fences)if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("SessionInitialQuarantineMissing");
            upstream??=ProxyChannelLease.Open(state);
            profile=InstallationProfileLease.Create(state);job=OwnedKernelJob.CreateEmpty(state,version);
            using(var package=new InstallationPackageSid(state))sid=package.Value;
            if(IsLocalManagementBoundary)
            {
                proxyRoute=ProxyRouteObservation.Capture(upstream).GetAwaiter().GetResult();
                var bytes=LocalManagementBoundary.CaptureTrustedController(upstream).GetAwaiter().GetResult();
                try
                {
                    var sha=Convert.ToHexString(SHA256.HashData(bytes));
                    state.WriteNew("local-management-reference-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                        SchemaVersion=1,SessionId=id,Status=200,ReceivedBytes=bytes.Length,SHA256=sha,Content=bytes
                    }));
                    localManagementReference=new {Status=200,ReceivedBytes=bytes.Length,SHA256=sha};
                }
                finally{CryptographicOperations.ZeroMemory(bytes);}
            }
            gateway=new SessionProxy(job,upstream,sid,id,CapabilityProfile,FixedNoContentHttpsCanary,resolverTrust,IsLocalManagementBoundary,
                requireFreshProxyRoute:RequiresReviewedProxyRoute);
            loopback=InstallationLoopbackLease.Enable(state,false);
            preparation=new Preparation(this);
            if(IsGatewayQualification)
            {
                feedbackPipe=new(System.IO.Pipes.PipeDirection.In,HandleInheritability.Inheritable);
                feedbackReader=new StreamReader(feedbackPipe,new UTF8Encoding(false,true),false,1024,true);
                feedbackText=IsLocalManagementBoundary?LocalManagementBoundaryReport.ReadBounded(feedbackReader):
                    CaptureCapabilityContent?GatewayCapabilityChildReport.ReadBounded(feedbackReader):GatewayChildReport.ReadBounded(feedbackReader);
            }
            child=AtomicChild.CreateSession(layout,state,version,job,profile,preparation,feedbackPipe?.ClientSafePipeHandle.DangerousGetHandle()??IntPtr.Zero);
            if(IsGatewayQualification)fixedRootIdentity=(child.Pid,child.ExpectedCreatedFileTime);
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
            if(IsLocalManagementBoundary && fixedRootIdentity is { } localRoot)
            {
                upstream.AssertControllerListener();
                if(localManagementFeedback?.Attempts.FirstOrDefault() is {Role:"OWNED_GATEWAY",Phase:"ACKNOWLEDGED"})
                {
                    gateway.RequireLocalAcknowledgement(localRoot.Pid,localRoot.CreatedFileTime);
                    localManagementPositiveControl=true;
                }
            }
            if(childExitCode!=42)throw WfpNative.Contract("SessionSyntheticWorkloadFailed");
            if(fixedRootIdentity is { } root)
            {
                if(IsLocalManagementBoundary)
                {
                    if(localManagementFeedback?.BoundaryObserved!=true || localManagementReference is null || !localManagementPositiveControl)
                        throw WfpNative.Contract("LocalManagementBoundaryNotConfirmed");
                }
                else
                {
                    if(gatewayChildFeedback is not {Phase:"COMPLETE",HttpStatus:>=200 and <400})throw WfpNative.Contract("FixedGatewayTerminalFeedbackMissing");
                    gateway.RequireFixedExchange(root.Pid,root.CreatedFileTime);
                    if(RequiresReviewedProxyRoute && gateway.ReviewedRouteEvidence?.FixedExchangeCovered!=true)
                        throw WfpNative.Contract("FixedGatewayReviewedRouteEvidenceMissing");
                }
                runtime.AssertHealthy();
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
                if(job is not null)try{zero=job.AtomicAdmissionReserved?job.CloseAtomicAdmissionAndStop():job.StopAndRetireUnadmitted();}catch(Exception ex){errors.Add(ex);}
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
        var fixedExchangeObserved=resumed && fixedRootIdentity is { } observedRoot &&
            gateway?.FixedExchangeObserved(observedRoot.Pid,observedRoot.CreatedFileTime)==true;
        var completedStatus=IsLocalManagementBoundary?"FIXED_LOCAL_MANAGEMENT_BOUNDARY_CLOSED":
            IsGatewayQualification?"FIXED_GATEWAY_QUALIFICATION_CLOSED":"FIXED_SYNTHETIC_SESSION_CLOSED";
        var report=Report(success?completedStatus:"PROTECTED_SESSION_NOT_CONFIRMED",resumed,zero,
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
            if(!SessionZeroCreatorRecovery.IsAdmissionResolved(state,intent))throw WfpNative.Contract("SessionPriorAdmissionNotClosed");
    }
}
