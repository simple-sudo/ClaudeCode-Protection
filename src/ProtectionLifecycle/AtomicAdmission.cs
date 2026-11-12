using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

// No supplied executable/arguments/PID/token. First consumer is the installed
// broker's own finite canary. Production Claude admission remains deferred.
internal sealed partial class AtomicChild : IDisposable
{
    private readonly ProtectedState state;
    private readonly VerifiedVersion version;
    private readonly OwnedKernelJob job;
    private readonly SafeProcessHandle process;
    private readonly SafeWaitHandle thread;
    private readonly uint initialThreadId;
    private readonly string image,packageSid;
    private readonly NetworkProbePlan? network;
    private readonly bool gpuWorkload;
    private readonly OfflineTlsProbe? offlineTls;
    private readonly bool offlineConsole;
    private readonly bool independentOfflineConsole;
    private readonly bool independentCuda;
    private readonly SessionGitToolchain.Operation independentGit;
    private readonly bool startupWitness;
    private readonly SessionZeroCreatorChannel.TokenProof creatorTokenProof;
    private readonly ProtectedSession.Preparation? sessionPreparation;
    private readonly ProtectedSession.ResourceQualification? resourceQualification;
    private ProtectedSession.Admission? sessionAdmission;
    private bool resumed,disposed;
    internal bool ResumeAttempted {get;private set;}
    internal uint Pid {get;}
    internal string ExpectedPackageSid=>packageSid;
    internal string ExpectedImagePath=>image;
    internal bool RequiresLpac=>sessionPreparation is not null || resourceQualification is not null || gpuWorkload || offlineTls is not null || offlineConsole;
    private LpacCapabilityProfile CapabilityProfile=>sessionPreparation?.CapabilityProfile??FixedCapabilities(offlineTls is not null);
    private static LpacCapabilityProfile FixedCapabilities(bool offlineTls)=>offlineTls?
        LpacCapabilityProfile.InternetClientQualification:LpacCapabilityProfile.None;
    internal long ExpectedCreatedFileTime
    {
        get
        {
            if(disposed || !GetProcessTimes(process,out var created,out _,out _,out _))throw Error("ReadHeldPrimaryCreationTime");
            return created;
        }
    }
    internal bool IsRunning=>!disposed && WaitForSingleObject(process,0)==0x102;
    // Candidate primitive only; no current creation/qualification path calls
    // it. A separately reviewed fixed owner operation must select it before
    // resume. It can alter only this held child's future-object default ACL.
    internal void AssertSuspendedSessionIdentity(ProtectedSession.Preparation exactPreparation)
    {
        if(!ReferenceEquals(sessionPreparation,exactPreparation))throw WfpNative.Contract("ForeignSuspendedSessionRoot");
        AssertSuspendedIdentity();
        var localService=!exactPreparation.IsGatewayQualification;
        KernelJobSeal.SessionObjectDescriptor.AssertSeal(process,localService);
        KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread,localService);
    }
    internal void AssertSuspendedResourceIdentity(ProtectedSession.ResourceQualification permit)
    {
        if(!ReferenceEquals(resourceQualification,permit))throw WfpNative.Contract("ForeignResourceQualificationRoot");
        AssertSuspendedIdentity();
    }
    private void AssertSuspendedIdentity()
    {
        if(disposed || resumed || !IsRunning)throw WfpNative.Contract("LiveSuspendedSessionRootRequired");
        var snapshot=job.Observe();
        if(!snapshot.ExpectedLimits || snapshot.ActiveBefore!=1 || snapshot.ActiveAfter!=1 || snapshot.ProcessIds.Length!=1 || snapshot.ProcessIds[0]!=Pid ||
            !job.ContainsProcess(process) || GetProcessId(process)!=Pid)throw WfpNative.Contract("SuspendedSessionRootJobMismatch");
        var path=new StringBuilder(32768);uint length=(uint)path.Capacity;
        if(!QueryFullProcessImageName(process,0,path,ref length))throw Error("ReadSuspendedSessionImage");
        var requireIndependentUser=sessionPreparation is {IsGatewayQualification:false};
        var token=ReadTokenSnapshot(process,true,requireIndependentUser,out var actualUser);
        if(!string.Equals(WindowsPathSeal.Canonical(path.ToString()),image,StringComparison.OrdinalIgnoreCase) ||
            !token.IsAppContainer || !token.LpacAccessCheckObserved || token.PackageSid!=packageSid || !CapabilityProfile.Matches(token.CapabilityCount,token.Capabilities) || token.IntegritySid!="S-1-16-4096")
            throw WfpNative.Contract("SuspendedSessionRootImageOrTokenMismatch");
        if(requireIndependentUser)
        {
            using var host=WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            AssertIndependentSessionUser(actualUser,host.User);
        }
    }
    private AtomicChild(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,ProcessInfo info,string image,string sid,NetworkProbePlan? network,bool gpuWorkload,ProtectedSession.Preparation? preparation,ProtectedSession.ResourceQualification? resources,OfflineTlsProbe? offlineTls,bool offlineConsole)
    {
        this.state=state;this.version=version;this.job=job;this.image=image;packageSid=sid;Pid=info.ProcessId;this.network=network;this.gpuWorkload=gpuWorkload;
        process=new(info.Process,true);thread=new(info.Thread,true);initialThreadId=info.ThreadId;
        sessionPreparation=preparation;resourceQualification=resources;this.offlineTls=offlineTls;this.offlineConsole=offlineConsole;
    }
    private AtomicChild(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,SessionZeroCreatorChannel.SuspendedRoot root,
        string image,string sid,bool startupWitness,SessionGitToolchain.Operation gitOperation,bool cuda)
    {
        this.state=state;this.version=version;this.job=job;this.image=image;packageSid=sid;
        Pid=root.Identity.Pid;initialThreadId=root.Identity.Tid;
        (process,thread)=root.TransferTo(job);
        offlineConsole=true;independentOfflineConsole=true;
        independentGit=gitOperation;
        independentCuda=cuda;
        this.startupWitness=startupWitness;
        creatorTokenProof=root.LpacProof;
    }
    internal object ResumeQuarantined(ProxyChannelLease? proxy=null,ProtectedSession.Admission? sessionPermit=null)
    {
        if(disposed || ResumeAttempted)throw new InvalidOperationException("Canary resume is one-shot");
        if(sessionPreparation is not null)
        {
            if(sessionPermit is null || !sessionPermit.Matches(sessionPreparation))throw WfpNative.Contract("FullSessionPermitRequiredBeforeFirstInstruction");
            AssertSuspendedSessionIdentity(sessionPreparation);
            sessionAdmission=sessionPermit;
        }
        else if(sessionPermit is not null)throw WfpNative.Contract("SessionPermitCannotAuthorizeLegacyCanary");
        if(resourceQualification is not null)
        {
            if(proxy is not null || sessionPermit is not null)throw WfpNative.Contract("OfflineResourceQualificationCannotUseNetworkPermit");
            AssertSuspendedResourceIdentity(resourceQualification);
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(process);KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread);
            resourceQualification.AssertCurrent();
        }
        if(gpuWorkload)
        {
            if(proxy is not null)throw WfpNative.Contract("GpuQualificationRequiresOfflineQuarantine");
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(process);
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread);
        }
        if(offlineTls is not null)
        {
            if(proxy is not null || sessionPermit is not null)throw WfpNative.Contract("TlsQualificationRequiresOfflineQuarantine");
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(process);
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread);
        }
        if(offlineConsole)
        {
            if(proxy is not null || sessionPermit is not null)throw WfpNative.Contract("OfflineConsoleRequiresFullQuarantine");
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(process,independentOfflineConsole);
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread,independentOfflineConsole);
            AssertNoChildCreation(process);
            job.AssertSingleProcessEverAdmitted();
        }
        state.AssertHeld();version.AssertHeld(state);
        sessionAdmission?.AssertCurrent();
        var snapshot=job.Observe();
        if(!snapshot.ExpectedLimits || snapshot.ActiveBefore!=1 || snapshot.ActiveAfter!=1 || snapshot.ProcessIds.Length!=1 || snapshot.ProcessIds[0]!=Pid)
            throw WfpNative.Contract("AtomicJobMembershipBeforeResumeMismatch");
        if(!GetProcessTimes(process,out var created,out _,out _,out _))throw Error("AtomicReadCreationTime");
        var path=new StringBuilder(32768);uint length=(uint)path.Capacity;
        if(!QueryFullProcessImageName(process,0,path,ref length))throw Error("AtomicReadCreatedImage");
        if(!string.Equals(WindowsPathSeal.Canonical(path.ToString()),image,StringComparison.OrdinalIgnoreCase))throw WfpNative.Contract("AtomicCreatedImageMismatch");
        SecurityIdentifier? tokenUser;
        var token=independentOfflineConsole?ReadIndependentOfflineToken(process,creatorTokenProof,out tokenUser):
            ReadTokenSnapshot(process,true,offlineConsole,out tokenUser);
        if(!token.IsAppContainer || RequiresLpac && !token.LpacAccessCheckObserved || token.PackageSid!=packageSid || !CapabilityProfile.Matches(token.CapabilityCount,token.Capabilities) || token.IntegritySid!="S-1-16-4096")throw WfpNative.Contract("AtomicTokenBeforeResumeMismatch");
        if(independentOfflineConsole)
        {
            using var host=WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            AssertIndependentSessionUser(tokenUser,host.User);
        }
        var plans=FencePlan.ReadAll(state);if(plans.Count==0)throw WfpNative.Contract("AtomicResumeRequiresRegisteredFence");
        var observations=new List<FenceObservation>();
        var proxyOnly=network?.RequiresProxy==true;
        if(proxyOnly){if(proxy is null)throw WfpNative.Contract("NetworkProxyAdmissionNeedsLiveIdentityLease");proxy.AssertHealthy();}
        foreach(var plan in plans)
        {
            using var fence=PersistentFence.OpenExisting(state,plan.Data.FenceId);var observed=fence.Observe();
            if(sessionAdmission is not null)
            {
                sessionAdmission.Gateway.AssertHealthy();
                if(!fence.IsSessionChannel || !observed.IPv4ProxyOnlyObserved)throw WfpNative.Contract("SessionResumeRequiresGatewayFenceOnly");
            }
            else if(proxyOnly?!observed.IPv4ProxyOnlyObserved:!observed.FullQuarantineObserved)throw WfpNative.Contract("AtomicResumeRequiresCommittedExpectedFence");
            observations.Add(observed);
        }
        AssertHeldInitialThread(process,thread,Pid,initialThreadId);
        var proof=new {SchemaVersion=1,state.InstallationId,job.JobId,Pid,CreatedFileTime=created.ToString("X16"),Token=token,
            ExpectedCapabilitiesSHA256=CapabilityProfile.SHA256,ObservedCapabilities=token.Capabilities?.CopyEntries(),
            ImageSHA256=independentGit!=SessionGitToolchain.Operation.None?SessionGitToolchain.ImageSHA256:
                version.Package.Files.Single(f=>f.Asset.Id==(startupWitness?PackageAssetCatalog.SessionZeroStartupWitnessId:"broker-exe")).SHA256,
            Job=snapshot,Fences=observations,
            CreatorLpacAccessCheckBoundToPrimaryToken=independentOfflineConsole?(bool?)true:null,
            Binding="SECURITY_CAPABILITIES_AND_JOB_LIST_AT_CREATION",Status="BEFORE_FIRST_RESUME",NetworkBehaviorQualified=false,
            SessionBindingSHA256=sessionAdmission?.BindingSHA256,
            Scope=sessionAdmission is not null?"AUTHENTICATED_SESSION_GATEWAY":network?.Kind==NetworkProbeKind.Control?"UNFENCED_OWNED_LOOPBACK_CONTROL":proxyOnly?"COMPILED_IPV4_PROXY_ONLY":gpuWorkload?"FIXED_CUDA_FULL_QUARANTINE":startupWitness?SessionZeroStartupWitness.Scope:
                independentGit!=SessionGitToolchain.Operation.None?SessionGitToolchain.Scope(independentGit):independentCuda?IndependentGpuWorkload.Scope:independentOfflineConsole?"FIXED_INDEPENDENT_CONSOLE_FULL_QUARANTINE":offlineConsole?"FIXED_CONSOLE_FULL_QUARANTINE":
                offlineTls switch {OfflineTlsProbe.Schannel=>"FIXED_SCHANNEL_FULL_QUARANTINE",OfflineTlsProbe.OpenSsl=>"FIXED_OPENSSL_FULL_QUARANTINE",_=>"FULL_QUARANTINE"}};
        state.WriteNew("admission-before-resume-"+job.JobId+".json",JsonSerializer.SerializeToUtf8Bytes(proof));
        OfflineConsoleUserSid=tokenUser;
        sessionAdmission?.BeforeResume(this);
        resourceQualification?.BeforeResume(this);
        job.AssertCreatorSealedBeforeResume();
        if(independentOfflineConsole)
        {
            using var held=OpenCreatorQueryToken(process);
            AssertCreatorLpacBinding(creatorTokenProof,WindowsTokenInformation.ReadPrimaryBinding(held));
        }
        var branchTrace=startupWitness && SessionZeroStartupWitness.UsesBranchTrace(version.Package.SchemaVersion);
        if(branchTrace || startupWitness && version.Package.SchemaVersion==PackageAssetCatalog.SessionZeroStartupDiagnosticsSchema)
        {
            const int processSystemCallDisablePolicy=4;
            BeforeResumeWin32k=GetProcessMitigationPolicy(process,processSystemCallDisablePolicy,out var flags,sizeof(uint))
                ?new(0,(flags&1)!=0):new(unchecked((uint)Marshal.GetLastWin32Error()),null);
        }
        if(branchTrace)
        {
            const int processSystemCallFilterPolicy=11;
            BeforeResumeSystemCallFilter=GetProcessMitigationPolicy(process,processSystemCallFilterPolicy,out var flags,sizeof(uint))
                ?new(0,flags&15):new(unchecked((uint)Marshal.GetLastWin32Error()),null);
        }
        ResumeAttempted=true;
        var previous=ResumeThread(thread);if(previous==uint.MaxValue)throw Error("AtomicResumePrimaryThread");
        if(previous!=1)throw WfpNative.Contract("AtomicInitialSuspendCountMismatch");
        resumed=true;return proof;
    }
    private static void AssertNoChildCreation(SafeProcessHandle process)
    {
        if(!GetProcessMitigationPolicy(process,13,out var flags,sizeof(uint)))throw Error("OfflineConsoleReadChildPolicy");
        if(flags!=1)throw WfpNative.Contract("OfflineConsoleChildPolicyNotEnforced");
    }
    public void Dispose(){if(disposed)return;disposed=true;thread.Dispose();process.Dispose();}
    private static Win32Exception Error(string stage){var e=new Win32Exception(Marshal.GetLastWin32Error());e.Data["Stage"]=stage;return e;}

}
