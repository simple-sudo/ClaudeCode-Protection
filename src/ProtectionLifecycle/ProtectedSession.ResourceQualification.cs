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
            if(Volatile.Read(ref phase)==3 || owner.clock.ElapsedMilliseconds>=owner.resourceDurationMs || owner.job is null || owner.resources is null ||
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
}
