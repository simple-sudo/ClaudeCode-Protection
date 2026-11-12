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
}
