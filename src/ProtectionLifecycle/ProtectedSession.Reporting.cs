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
    private string Report(string status,bool resumed,JobSnapshot? final,WfpErrorEvidence[] failures,RuntimeStop? stopObservation=null,
        bool creationAttempted=false,bool created=false,uint? childExitCode=null,bool resumeAttempted=false,bool fixedExchangeObserved=false)=>JsonSerializer.Serialize(new {
        SchemaVersion=1,Scope=qualification?.ReviewedProxyRoute==true?"INSTALLED_FIXED_REVIEWED_PROXY_ROUTE":
            IsLocalManagementBoundary?"INSTALLED_FIXED_LOCAL_MANAGEMENT_BOUNDARY":
            IsGatewayQualification?"INSTALLED_FIXED_GATEWAY_QUALIFICATION":"INSTALLED_BROKER_PROTECTED_SESSION",state.InstallationId,version.Package.Release,
        version.Package.ManifestHash,SessionId=id,NetworkPolicySHA256=SessionProxy.PolicySHA256,
        ExpectedCapabilityProfile=CapabilityProfile.Id,ExpectedCapabilitiesSHA256=CapabilityProfile.SHA256,
        CapabilityContentComparison=CaptureCapabilityContent,
        FixedNoContentHttpsCanary=FixedNoContentHttpsCanary,
        FixedOpenSslHead=UsesFixedOpenSslHead,
        LocalManagementBoundary=IsLocalManagementBoundary,
        LocalManagementTrustedReference=localManagementReference,
        ProxyRouteObservation=proxyRoute,
        ReviewedProxyRouteRequired=RequiresReviewedProxyRoute,
        ReviewedProxyRouteEvidence=gateway?.ReviewedRouteEvidence,
        LocalManagementGatewayAcknowledged=localManagementPositiveControl,
        LocalManagementFeedback=localManagementFeedback is null?null:new {localManagementFeedback.Phase,localManagementFeedback.ExitCode,
            localManagementFeedback.SetupError,Attempts=localManagementFeedback.Attempts.Select(attempt=>attempt.Summary()).ToArray()},
        FixedOpenSslHeadRequestPath=UsesFixedOpenSslHead?FixedOpenSslHead.RequestPath:null,
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
        CapabilityContentEvidence=qualification?.ReviewedProxyRoute==true?null:gatewayCapabilityFeedback,
        ReviewedRouteNoContentGate=qualification?.ReviewedProxyRoute==true?gatewayCapabilityFeedback?.Network?.FixedNoContentHttpsCanaryEligible:null,
        FixedGatewayRootBidirectionalWriteObserved=fixedExchangeObserved,
        PublicTimeZoneReadResource=(object?)null,
        WinsockReadResource=winsockAccess is null?(object?)null:new{winsockAccess.KeyCount,winsockAccess.Restored,winsockAccess.IntentSHA256},
        PublicTimeZoneProjection=preparation?.PublicTimeZone is not PublicTimeZoneSnapshot zone?null:new {
            Source="ORIGINAL_OWNER_PUBLIC_CALENDAR",SnapshotSHA256=zone.SHA256,CoreLibModule=PublicTimeZoneSnapshot.CoreLibModule,
            HostRegistryAclModified=false,RegistryCapabilityAdded=false,CompatibilityOnly=true,RequiredBeforeHttps=true},
        ProductionSessionQualified=false,HostInformationConfidentialityQualified=false
    });
}
