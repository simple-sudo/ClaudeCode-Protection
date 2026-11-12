using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

// Owns the active one-shot Job's health/deadline and stop ordering. This is not
// the whole-installation update/uninstall authority or a generic launch API.
internal sealed class ProtectionRuntimeLease
{
    private readonly ProtectedState state;
    private readonly VerifiedVersion version;
    private readonly OwnedKernelJob job;
    private readonly IReadOnlyList<PersistentFence> fences;
    private readonly ProxyChannelLease? proxy;
    private readonly ProtectedSession.ResourceQualification? resources;
    private readonly SessionProxy? gateway;
    private enum FixedOffline { None, Gpu, HostGpuReference, Schannel, OpenSsl, Console }
    private readonly FixedOffline fixedOffline;
    private ProtectedSession.Admission? admission;
    private readonly ProtectedSession.Preparation? preparation;
    private bool startupObserved;
    internal bool StartupGuardObserved=>preparation is not null && startupObserved && !closed && clock.ElapsedMilliseconds<deadlineMs;
    private readonly Action? assertCaller;
    private readonly Stopwatch clock=Stopwatch.StartNew();
    private readonly string pointerSHA256,id=Guid.NewGuid().ToString("N");
    private long deadlineMs=25000;
    private bool activated,closed;
    private RuntimeStop? stopped;
    internal static ProtectionRuntimeLease ForFixedGpu(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,
        IReadOnlyList<PersistentFence> fences,AtomicChild child,string sessionId)
    {
        child.AssertGpuRuntimeOwner(state,version,job);
        return new(state,version,job,fences,null,null,null,null,null,Identifiers.Hex32(sessionId),FixedOffline.Gpu);
    }
    internal static ProtectionRuntimeLease ForHostGpuReference(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,
        IReadOnlyList<PersistentFence> fences,AtomicChild.HostGpuReferenceChild child,string sessionId,Action? assertCaller=null)
    {
        child.AssertOwner(state,version,job);
        return new(state,version,job,fences,null,null,null,null,assertCaller,Identifiers.Hex32(sessionId),FixedOffline.HostGpuReference);
    }
    internal static ProtectionRuntimeLease ForFixedOfflineTls(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,
        IReadOnlyList<PersistentFence> fences,AtomicChild child,string sessionId,OfflineTlsProbe probe)
    {
        child.AssertOfflineTlsRuntimeOwner(state,version,job,probe);
        var mode=probe switch {
            OfflineTlsProbe.Schannel=>FixedOffline.Schannel,OfflineTlsProbe.OpenSsl=>FixedOffline.OpenSsl,
            _=>throw WfpNative.Contract("UnknownOfflineTlsProbe")
        };
        return new(state,version,job,fences,null,null,null,null,null,Identifiers.Hex32(sessionId),mode);
    }
    internal static ProtectionRuntimeLease ForFixedOfflineConsole(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,
        IReadOnlyList<PersistentFence> fences,AtomicChild child,string sessionId)
    {
        child.AssertOfflineConsoleRuntimeOwner(state,version,job);
        return new(state,version,job,fences,null,null,null,null,null,Identifiers.Hex32(sessionId),FixedOffline.Console);
    }
    internal ProtectionRuntimeLease(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,IReadOnlyList<PersistentFence> fences,ProxyChannelLease? proxy,
        SessionProxy? gateway=null,ProtectedSession.Preparation? preparation=null,ProtectedSession.ResourceQualification? resources=null,Action? assertCaller=null)
        :this(state,version,job,fences,proxy,gateway,preparation,resources,assertCaller,null,FixedOffline.None){}

    private ProtectionRuntimeLease(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,IReadOnlyList<PersistentFence> fences,ProxyChannelLease? proxy,
        SessionProxy? gateway,ProtectedSession.Preparation? preparation,ProtectedSession.ResourceQualification? resources,Action? assertCaller,
        string? offlineSessionId,FixedOffline fixedOffline)
    {
        this.state=state;this.version=version;this.job=job;this.fences=fences;this.proxy=proxy;
        this.fixedOffline=fixedOffline;
        var offline=resources is not null || fixedOffline!=FixedOffline.None;
        if(offline?(proxy is not null || gateway is not null || preparation is not null):proxy is null)
            throw WfpNative.Contract("RuntimeScopeRequiresEitherOfflineResourcesOrLiveProxy");
        if(assertCaller is not null && resources is null && fixedOffline!=FixedOffline.HostGpuReference)throw WfpNative.Contract("WorkspaceCallerGuardRequiresOfflineResources");
        this.assertCaller=assertCaller;
        this.resources=resources;resources?.AssertRuntimeObjects(job,version,fences);
        if((gateway is null)!=(preparation is null))throw WfpNative.Contract("SessionGatewayAndPreparationRequiredTogether");
        if(preparation is not null && !ReferenceEquals(gateway,preparation.Gateway))throw WfpNative.Contract("StartupGatewayMismatch");
        preparation?.AssertRuntimeObjects(job,version,fences);
        this.gateway=gateway;this.preparation=preparation;
        if(gateway is not null)id=gateway.SessionId;
        if(resources is not null)id=resources.SessionId;
        if(offlineSessionId is not null)id=offlineSessionId;
        pointerSHA256=state.Read("current.json",4096).SHA256;
        if(fences.Count==0 || !job.AtomicAdmissionReserved)throw WfpNative.Contract("RuntimeRequiresAtomicAdmissionAndFence");
        job.AssertCreatorSealedBeforeResume();
        AssertHealthy();
        state.WriteNew("session-open-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,SessionId=id,job.JobId,
            version.Package.Release,version.Package.ManifestHash,CurrentPointerSHA256=pointerSHA256,StartupDeadlineMs=deadlineMs,
            Scope=fixedOffline switch {
                FixedOffline.Gpu=>"FIXED_OFFLINE_GPU_NO_FORWARDING_NO_FORMAL_PERMIT",
                FixedOffline.HostGpuReference=>"FIXED_ORDINARY_HOST_GPU_REFERENCE_NO_FORMAL_PERMIT",
                FixedOffline.Schannel=>"FIXED_OFFLINE_SCHANNEL_NO_FORWARDING_NO_FORMAL_PERMIT",
                FixedOffline.OpenSsl=>"FIXED_OFFLINE_OPENSSL_NO_FORWARDING_NO_FORMAL_PERMIT",
                FixedOffline.Console=>"FIXED_OFFLINE_CONSOLE_NO_FORWARDING_NO_FORMAL_PERMIT",
                _=>resources is not null?"FIXED_OFFLINE_RESOURCES_NO_FORWARDING_NO_FORMAL_PERMIT":gateway is null?"SINGLE_ATOMIC_JOB_COMPILED_PROXY":"QUARANTINED_SUSPENDED_SESSION_STARTUP"
            },
            FormalSessionResumeAuthorized=false,AdmissionReusable=false,
            SessionBindingSHA256=(string?)null,AtUtc=DateTime.UtcNow.ToString("o")}));
    }
    internal void AssertHealthy()
    {
        if(closed)throw WfpNative.Contract("RuntimeAdmissionClosed");
        assertCaller?.Invoke();
        state.AssertHeld();version.AssertHeld(state);
        if(state.Read("current.json",4096).SHA256!=pointerSHA256)throw WfpNative.Contract("RuntimeInstalledSelectionDrift");
        if(clock.ElapsedMilliseconds>=deadlineMs)throw WfpNative.Contract("RuntimeLeaseExpired");
        proxy?.AssertHealthy();resources?.AssertCurrent();
        if(admission is not null)admission.AssertCurrent();else preparation?.AssertCurrent();
        gateway?.AssertRuntimeHealthy(activated);
        foreach(var fence in fences)
        {
            var observed=fence.Observe();
            if(fixedOffline!=FixedOffline.None || resources is not null || preparation is not null && admission is null?!observed.FullQuarantineObserved:!observed.IPv4ProxyOnlyObserved)
                throw WfpNative.Contract("RuntimeFenceDrift");
        }
        if(gateway is not null && fences.Any(f=>!f.IsSessionChannel))throw WfpNative.Contract("SessionRawProxyPolicyDrift");
        if(!job.Observe().ExpectedLimits)throw WfpNative.Contract("RuntimeJobLimitsDrift");
        if(fixedOffline==FixedOffline.Console)job.AssertSingleProcessEverAdmitted();
        // Renew only after every check succeeded. A delayed/dead owner cannot
        // let an existing socket retain its old forwarding permission forever.
        admission?.ObserveRuntimeHealthy(this,deadlineMs-clock.ElapsedMilliseconds);
        startupObserved=true;
    }
    internal void AttachAdmission(ProtectedSession.Admission permit)
    {
        if(preparation is null || admission is not null || activated || closed || !permit.Matches(preparation))
            throw WfpNative.Contract("StartupGuardAdmissionTransitionRefused");
        permit.AssertRuntimeObjects(job,version,fences);admission=permit;AssertHealthy();
    }
    // One transition from bounded startup to a bounded active lease. A later
    // authenticated controller heartbeat/renewal path is not implemented here.
    internal void Activate(int durationMs)
    {
        if(activated || durationMs is <250 or >60000 || preparation is not null && admission is null)throw WfpNative.Contract("RuntimeActivationRefused");
        AssertHealthy();activated=true;deadlineMs=checked(clock.ElapsedMilliseconds+durationMs);
        admission?.ObserveRuntimeHealthy(this,deadlineMs-clock.ElapsedMilliseconds);
        state.WriteNew("session-active-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,SessionId=id,job.JobId,
            ActiveDurationMs=durationMs,DeadlineMs=deadlineMs,Renewable=false,AtUtc=DateTime.UtcNow.ToString("o")}));
    }
    internal RuntimeStop Stop(string reason)
    {
        if(stopped is not null)return stopped;
        closed=true;var errors=new List<Exception>();var quarantined=true;long quarantineAt=-1,jobAt=-1;JobSnapshot? zero=null;
        admission?.Revoke();
        resources?.Revoke();
        preparation?.Revoke();
        try{gateway?.Revoke();}catch(Exception ex){errors.Add(ex);}
        try{state.WriteNew("session-stop-intent-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,SessionId=id,job.JobId,
            Reason=reason,AdmissionClosed=true,AtMs=clock.ElapsedMilliseconds}));}catch(Exception ex){errors.Add(ex);}
        foreach(var fence in fences)
        {
            try
            {
                if(!fence.Observe().FullQuarantineObserved)_=fence.ReinstateQuarantine();
                if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("RuntimeQuarantineReadbackFailed");
            }
            catch(Exception ex){quarantined=false;errors.Add(ex);}
        }
        if(quarantined)quarantineAt=clock.ElapsedMilliseconds;
        // A failed barrier restore still must not prevent exact Job termination.
        // It remains a failure, never a successful ordered-quarantine claim.
        try{jobAt=clock.ElapsedMilliseconds;zero=job.CloseAtomicAdmissionAndStop();}catch(Exception ex){errors.Add(ex);}
        RuntimeStop Snapshot()=>new(id,reason,true,quarantined,quarantineAt,jobAt,zero,errors.SelectMany(WfpNative.Describe).ToArray());
        try{state.WriteNew("session-stopped-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(Snapshot()));}catch(Exception ex){errors.Add(ex);}
        stopped=Snapshot();return stopped;
    }
}
