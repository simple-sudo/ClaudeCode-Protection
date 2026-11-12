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
        internal bool IsLocalManagementBoundary=>owner.IsLocalManagementBoundary;
        internal bool RequiresReviewedProxyRoute=>owner.RequiresReviewedProxyRoute;
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
            ReviewedProxyRoute=owner.RequiresReviewedProxyRoute,
            LocalManagementBoundary=owner.IsLocalManagementBoundary,
            WinsockReadIntentSHA256=owner.winsockAccess?.IntentSHA256,
            PublicTimeZoneSnapshotSHA256=owner.preparation?.PublicTimeZone?.SHA256,EnvironmentIntentSHA256=owner.expectationsSHA256,FenceIntents=owner.fences.Select(f=>f.IntentSHA256).ToArray(),
            RequiredEnvironmentIds=StrictEnvironmentRequirements.Required.Select(def=>def.Id).ToArray()
        })));
    }
}
