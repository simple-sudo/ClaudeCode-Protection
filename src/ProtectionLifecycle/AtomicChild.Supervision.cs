using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Runtime supervision of the exact AtomicChild admitted by the owner.
// This partial holds no independent process/thread handle and cannot resume or replace it.
internal sealed partial class AtomicChild
{
    internal SecurityIdentifier? OfflineConsoleUserSid { get;private set; }
    internal SessionZeroStartupWitness.Win32kObservation? BeforeResumeWin32k {get;private set;}
    internal SessionZeroStartupWitness.SystemCallFilterObservation? BeforeResumeSystemCallFilter {get;private set;}

    internal uint WaitForCanaryExit()=>WaitForCanaryExit(null);
    internal uint WaitForCanaryExit(int? timeoutMs)
    {
        var defaultTimeoutMs=network?.Kind==NetworkProbeKind.ProxySession?90000u:network is not null || gpuWorkload?30000u:15000u;
        return ObserveCanaryExit(ResolveCanaryTimeoutMs(timeoutMs,defaultTimeoutMs))
            ??throw new TimeoutException("Finite atomic canary did not exit");
    }
    internal static uint ResolveCanaryTimeoutMs(int? timeoutMs,uint defaultTimeoutMs)
    {
        if(defaultTimeoutMs is 0 or >120000 || timeoutMs is <1 or >120000)
            throw new ArgumentOutOfRangeException(nameof(timeoutMs));
        return timeoutMs.HasValue?checked((uint)timeoutMs.Value):defaultTimeoutMs;
    }
    internal static void AssertHeldInitialThread(SafeProcessHandle process,SafeWaitHandle thread,uint pid,uint tid)
    {
        if(pid==0 || tid==0 || process.IsClosed || process.IsInvalid || thread.IsClosed || thread.IsInvalid ||
            GetProcessId(process)!=pid || GetThreadId(thread)!=tid || GetProcessIdOfThread(thread)!=pid ||
            WaitForSingleObject(process,0)!=0x102 || WaitForInitialThread(thread,0)!=0x102)
            throw WfpNative.Contract("HeldInitialThreadIdentityOrLifetimeMismatch");
    }
    internal void AssertGpuRuntimeOwner(ProtectedState exactState,VerifiedVersion exactVersion,OwnedKernelJob exactJob)
    {
        if(!gpuWorkload || disposed || resumed || !IsRunning || !ReferenceEquals(state,exactState) ||
            !ReferenceEquals(version,exactVersion) || !ReferenceEquals(job,exactJob) || !job.ContainsProcess(process))
            throw WfpNative.Contract("GpuRuntimeRequiresExactSuspendedChild");
    }
    internal uint? ObserveFixedGpuExit()
    {
        if(!gpuWorkload)throw WfpNative.Contract("FixedGpuWorkloadRequired");
        return ObserveCanaryExit(100);
    }
    internal void AssertOfflineTlsRuntimeOwner(ProtectedState exactState,VerifiedVersion exactVersion,OwnedKernelJob exactJob,OfflineTlsProbe probe)
    {
        if(offlineTls!=probe || disposed || resumed || !IsRunning || !ReferenceEquals(state,exactState) ||
            !ReferenceEquals(version,exactVersion) || !ReferenceEquals(job,exactJob) || !job.ContainsProcess(process))
            throw WfpNative.Contract("OfflineTlsRuntimeRequiresExactSuspendedChild");
    }
    internal uint? ObserveFixedOfflineTlsExit()
    {
        if(offlineTls is null)throw WfpNative.Contract("FixedOfflineTlsWorkloadRequired");
        return ObserveCanaryExit(100);
    }
    internal void AssertOfflineConsoleRuntimeOwner(ProtectedState exactState,VerifiedVersion exactVersion,OwnedKernelJob exactJob)
    {
        if(!offlineConsole || disposed || ResumeAttempted || !IsRunning || !ReferenceEquals(state,exactState) ||
            !ReferenceEquals(version,exactVersion) || !ReferenceEquals(job,exactJob) || !job.ContainsProcess(process))
            throw WfpNative.Contract("OfflineConsoleRuntimeRequiresExactSuspendedChild");
    }
    internal SecurityIdentifier? OfflineConsoleUserSid { get;private set; }
    internal SessionZeroStartupWitness.Win32kObservation? BeforeResumeWin32k {get;private set;}
    internal SessionZeroStartupWitness.SystemCallFilterObservation? BeforeResumeSystemCallFilter {get;private set;}
    internal void ObserveStartupBranch(SessionZeroStartupBranchTrace trace,Action assertHealthy)
    {
        if(!startupWitness || !SessionZeroStartupWitness.UsesBranchTrace(version.Package.SchemaVersion) ||
            disposed || !resumed || !job.ContainsProcess(process))
            throw WfpNative.Contract("StartupTraceRequiresResumedReviewedWitness");
        trace.Observe(process,Pid,initialThreadId,assertHealthy);
    }
    internal void ObserveCudaAccess(SessionZeroStartupBranchTrace.CudaAccessTrace trace,Action assertHealthy)
    {
        if(!independentCuda || version.Package.SchemaVersion is not (PackageAssetCatalog.SessionZeroCudaDeferredPreloadSchema or PackageAssetCatalog.SessionZeroCudaInitializationTraceSchema or PackageAssetCatalog.SessionZeroCudaHelperPathSchema or PackageAssetCatalog.SessionZeroCudaRegistryCallsSchema or PackageAssetCatalog.SessionZeroCudaGraphicsReadSchema or PackageAssetCatalog.SessionZeroCudaGraphicsRootSchema or PackageAssetCatalog.SessionZeroCudaDeviceIdentitySchema or PackageAssetCatalog.SessionZeroGitTrackedCommitSchema) ||
            disposed || !resumed || !job.ContainsProcess(process))
            throw WfpNative.Contract("CudaTraceRequiresResumedReviewedRoot");
        trace.Observe(process,Pid,initialThreadId,assertHealthy);
    }
    internal uint? ObserveOfflineConsoleExit()
    {
        if(!offlineConsole)throw WfpNative.Contract("OfflineConsoleWorkloadRequired");
        return ObserveCanaryExit(100);
    }

    private uint? ObserveCanaryExit(uint milliseconds)
    {
        if(!resumed || disposed)throw new InvalidOperationException("Canary has not resumed");
        var status=WaitForSingleObject(process,milliseconds);
        if(status==0x102)return null;
        if(status!=0)throw Error("AtomicCanaryWait");
        if(!GetExitCodeProcess(process,out var code))throw Error("AtomicCanaryExitCode");return code;
    }
}
