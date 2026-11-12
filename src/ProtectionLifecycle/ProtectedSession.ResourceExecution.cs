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
    internal static (int ExitCode,string Report) QualifyResources(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>new ProtectedSession(layout,state,version).ExecuteResourceQualification(ResourceExecutionIntent.ForWorkspaceQualification());
    internal static (int ExitCode,string Report) QualifyToolchain(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>new ProtectedSession(layout,state,version).ExecuteResourceQualification(ResourceExecutionIntent.ForGitToolchainQualification());
    internal static (int ExitCode,string Report) DevelopBundledProject(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        =>new ProtectedSession(layout,state,version).ExecuteResourceQualification(
            ResourceExecutionIntent.ForBundledProjectDevelopment(),BundledProjectDevelopment.Baseline());
    internal static (int ExitCode,string Report) DevelopBundledProjectForCaller(FixedLayout layout,ProtectedState state,VerifiedVersion version,Action assertCaller)
    {
        ArgumentNullException.ThrowIfNull(assertCaller);
        return new ProtectedSession(layout,state,version).ExecuteResourceQualification(
            ResourceExecutionIntent.ForBundledProjectDevelopment(assertCaller),BundledProjectDevelopment.Baseline());
    }
    internal static (int ExitCode,string Report) BuildCallerProject(FixedLayout layout,ProtectedState state,VerifiedVersion version,byte[] bytes,Action assertCaller)
    {
        ArgumentNullException.ThrowIfNull(assertCaller);
        return new ProtectedSession(layout,state,version).ExecuteResourceQualification(
            ResourceExecutionIntent.ForCallerProjectBuild(assertCaller),bytes);
    }
    // A data-only operation on the existing owner and fixed offline Git
    // program. Source/test/build files in the bundle are NEVER executed.
    internal static (int ExitCode,string Report) ProcessWorkspaceData(FixedLayout layout,ProtectedState state,VerifiedVersion version,byte[] bytes)
        =>new ProtectedSession(layout,state,version).ExecuteResourceQualification(
            ResourceExecutionIntent.ForWorkspaceDataProcessing(),bytes);
    internal static (int ExitCode,string Report) ProcessWorkspaceDataForCaller(FixedLayout layout,ProtectedState state,VerifiedVersion version,byte[] bytes,Action assertCaller)
    {
        ArgumentNullException.ThrowIfNull(assertCaller);
        return new ProtectedSession(layout,state,version).ExecuteResourceQualification(
            ResourceExecutionIntent.ForWorkspaceDataProcessing(assertCaller),bytes);
    }
    internal static (int ExitCode,string Report) QualifyResourceRecovery(FixedLayout layout,ProtectedState state,VerifiedVersion version)
        // Deliberately EXIT this installed owner with a durable cleanup
        // checkpoint. The NEXT installed invocation performs real journal
        // recovery; no live in-memory profile object is transferred to it.
        =>new ProtectedSession(layout,state,version).ExecuteResourceQualification(ResourceExecutionIntent.ForRecoveryQualification());
    private (int ExitCode,string Report) ExecuteResourceQualification(ResourceExecutionIntent intent,byte[]? workspaceInput=null)
    {
        ArgumentNullException.ThrowIfNull(intent);intent.AssertInput(workspaceInput);
        InstallationProfileLease? profile=null;AtomicChild? child=null;
        var gitWorkflow=workspaceInput is not null && WorkspaceBundle.Parse(workspaceInput).GitPlan is not null;
        resourceDurationMs=gitWorkflow?GitWorkflowTimeoutMs:30000;
        var (powerShellRequired,compilerRequired)=ResourceProbePlan.ToolRequirementsForIntent(intent);
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
            intent.AssertCaller?.Invoke();
            LifecycleRecovery.AssertNoPending(state);InstallationLoopbackLease.AssertClosedHistory(state);
            foreach(var ownedJobIntent in OwnedJobIntent.ReadAll(state))
                if(!SessionZeroCreatorRecovery.IsAdmissionResolved(state,ownedJobIntent))throw WfpNative.Contract("ResourceQualificationPriorAdmissionNotClosed");
            var plans=FencePlan.ReadAll(state);if(plans.Count==0)throw WfpNative.Contract("ResourceQualificationNeedsExistingQuarantine");
            foreach(var plan in plans)fences.Add(PersistentFence.OpenExisting(state,plan.Data.FenceId));
            foreach(var fence in fences)if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("ResourceQualificationFullQuarantineRequired");
            state.WriteNew("resource-session-before-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,
                SessionId=id,version.Package.Release,version.Package.ManifestHash,Scope=intent.CallerProject?WorkspacePipe.CallerProjectScope:intent.DevelopProject?"EXPLICIT_BUNDLED_PROJECT_CODE_TASK":"FIXED_OFFLINE_RESOURCE_AND_POWERSHELL_QUALIFICATION",FormalAdmissionIssued=false}));
            intent.AssertCaller?.Invoke();
            profile=InstallationProfileLease.Create(state);resources=SessionResources.Create(state,version,profile,id,intent,workspaceInput);
            using(var package=new InstallationPackageSid(state))sid=package.Value;
            job=OwnedKernelJob.CreateEmpty(state,version);permit=new ResourceQualification(this);
            pipe=new(System.IO.Pipes.PipeDirection.In,HandleInheritability.Inheritable);reader=new StreamReader(pipe,Encoding.UTF8,false,4096,true);
            text=toolLaunch.ReadMessages(reader);
            intent.AssertCaller?.Invoke();
            child=AtomicChild.CreateResourceQualification(layout,state,version,job,profile,permit,pipe.ClientSafePipeHandle.DangerousGetHandle());
            pipe.DisposeLocalCopyOfClientHandle();
            // The installed register-only ETW lease restored exactly but did
            // not repair EventRegister5. Retire that automatic permission
            // mutation; keep its journal inspection/recovery for old runs.
            runtime=new ProtectionRuntimeLease(state,version,job,fences,null,resources:permit,assertCaller:intent.AssertCaller);
            intent.AssertCaller?.Invoke();
            _=child.ResumeQuarantined();resumed=true;runtime.Activate(gitWorkflow?GitWorkflowTimeoutMs:20000);
            // Eleven owner-brokered Git processes need the same bounded window
            // as the resource permit and runtime watchdog, not the generic
            // atomic canary's 15-second default.
            exited=Task.Run(()=>child!.WaitForCanaryExit(gitWorkflow?GitWorkflowTimeoutMs:null));
            while(!exited.Wait(100))
            {
                runtime.AssertHealthy();
                toolLaunch.ProcessPending(resources,child,job,permit);
                // Fixed PowerShell waits before its workload until all held
                // members have been verified together. After release, its
                // planned exit is supervised by the runtime and exact Job
                // drain, not mistaken for a foreign process appearing.
                var executionPhase=intent.DevelopProject && toolObserved;
                var probePhase=intent.DevelopProject && gitObserved && !resources.ProjectProbeSealed;
                if(probePhase && (probeObserved?!resources.ProjectProbePrivacyReady():!resources.ProjectProbeReady()))continue;
                if(!probePhase && executionPhase && (resources.ProjectExecutionReleased || !resources.ProjectPrivacyReady()))continue;
                var gitPhase=intent.DevelopProject?!gitObserved:!powerShellRequired || toolObserved;
                if(!probePhase && !executionPhase && (gitPhase?!intent.IncludeGit || gitObserved || !resources.GitReady():!resources.ToolReady()))continue;
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
                            if(intent.DevelopProject && !gitPhase)
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
                    else if(gitPhase){if(intent.DevelopProject)resources.SealRootHostPrivacyBeforeGit(checked((int)child.Pid));resources.ReleaseInspectedGit();gitObserved=true;}
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
                intent.IncludeGit && (!gitObserved || observed.Git is null) || !intent.IncludeGit && observed.Git is not null || intent.DevelopProject && !resources.ProjectExecutionReleased)
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
            else if(job is not null)try{zero=job.AtomicAdmissionReserved?job.CloseAtomicAdmissionAndStop():job.StopAndRetireUnadmitted();}catch(Exception ex){failures.Add(ex);}
            if(profile?.ProcessCreationAttempted==true && zero is not null)try{profile.AfterOwnedJobZero(zero);}catch(Exception ex){failures.Add(ex);}
            if(intent.DevelopProject && resources is not null && child is not null && closedResources)
                try
                {
                    hostPrivacy=resources.ReadClosedHostPrivacy(checked((int)child.Pid),projectActor?.Pid);
                    HostPrivacyContract.Validate(hostPrivacy,id,true);
                }
                catch(Exception ex){failures.Add(ex);}
            if(closedResources && failures.Count==0 && zero is not null && observed is not null && resources is not null)
                try
                {
                    intent.AssertCaller?.Invoke();
                    resources.AssertOutput(observed);
                    if(intent.IncludeGit)workspaceResultSHA256=resources.PreserveClosedWorkspaceResult(zero,intent.AssertCaller);
                }
                catch(Exception ex){failures.Add(ex);}
            if(exited is not null)try{exit=exited.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();}catch(Exception ex){failures.Add(ex);}
            if(pipe is not null)try{pipe.DisposeLocalCopyOfClientHandle();}catch(Exception ex){failures.Add(ex);}
            if(closedResources && failures.Count!=0)try{resources?.PreserveGitFailure();}catch(Exception ex){failures.Add(ex);}
            foreach(var owned in new IDisposable?[]{child,reader,pipe,resources})try{owned?.Dispose();}catch(Exception ex){failures.Add(ex);}
            try
            {
                if(intent.DeferCleanup && failures.Count==0 && profile is not null && zero?.ObservedZero==true && observed is not null && SessionResources.Qualified(observed,powerShellRequired))
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
            try{intent.AssertCaller?.Invoke();}catch(Exception ex){failures.Add(ex);}
        var success=observed is not null && SessionResources.Qualified(observed,compilerRequired) && (!compilerRequired || toolObserved) && (!intent.IncludeGit || gitObserved && observed.Git is not null && workspaceResultSHA256 is not null) && zero?.ObservedZero==true && failures.Count==0;
        var report=JsonSerializer.Serialize(new {SchemaVersion=1,state.InstallationId,SessionId=id,version.Package.Release,version.Package.ManifestHash,
            Status=success?(intent.CallerProject?"CALLER_CSHARP_PROJECT_BUILT_AND_CLEANED":intent.DevelopProject?"BUNDLED_PROJECT_DEVELOPED_AND_CLEANED":workspaceInput is not null?"WORKSPACE_DATA_PROCESSED_AND_CLEANED":cleanupDeferred?"OFFLINE_RESOURCE_CLOSED_JOB_CLEANUP_DEFERRED":intent.IncludeGit?"FIXED_OFFLINE_GIT_TOOLCHAIN_AND_DENIAL_OBSERVED":"FIXED_OFFLINE_WORKSPACE_TOOL_AND_DENIAL_OBSERVED"):"OFFLINE_RESOURCE_SESSION_NOT_CONFIRMED",
            Scope=intent.CallerProject?WorkspacePipe.CallerProjectScope:intent.DevelopProject?"EXPLICIT_TEXTSUMMARY_SOURCE_EDIT_BUILD_RUN_TEST":workspaceInput is not null?"CALLER_BYTE_PINNED_DATA_FIXED_OFFLINE_GIT_ONLY_NO_PROJECT_CODE_EXECUTION":intent.IncludeGit?"FIXED_OFFLINE_GIT_INIT_ADD_COMMIT_AND_DENIAL_ONLY":"FIXED_PROFILE_WORKSPACE_WINDOWS_POWERSHELL_AND_NON_SECRET_DENIAL_FIXTURE_ONLY",
            Resumed=resumed,ChildExit=exit,Child=observed,ChildBootstrapFailure=bootstrapFailure,InheritedPowerShellIdentityObserved=powerShellRequired && toolObserved,FinalJob=zero,Stop=stopped,
            ProjectDevelopmentRequested=intent.DevelopProject,InheritedProjectToolIdentityObserved=intent.DevelopProject && toolObserved,
            ProjectExecutionPermitConsumedAfterOwnerSealedPrivacy=intent.DevelopProject && resources?.ProjectExecutionReleased==true,
            HostPrivacy=hostPrivacy,
            CleanupDeferredForRecovery=cleanupDeferred,ManifestReadAccessRequired=false,ManifestReadAccessRestored=false,
            PowerShellRequired=powerShellRequired,PowerShellVersion=powerShellRequired?SessionPowerShellToolchain.Version:null,PowerShellAssetSetSHA256=powerShellRequired?SessionPowerShellToolchain.AssetSetSHA256:null,
            EtwRegistrationAccessGranted=false,EtwRegistrationAccessRestored=false,
            EtwProvider=SessionEtwProviderAccess.ProviderId,EtwRegistrationRights=0,
            ToolCreationOwner="ORIGINAL_BROKER",ToolCreationBinding="ATOMIC_LPAC_PACKAGE_AND_ORIGINAL_JOB_NOT_PARENT_INHERITANCE",
            InheritedGitIdentityObserved=gitObserved,GitAssetSetSHA256=resources?.Plan.GitAssetSetSHA256,
            WorkspaceBaselineSHA256=intent.IncludeGit && resources is not null?resources.Plan.WorkspaceInputSHA256??ClaudeCodeProtection.Workspaces.WorkspaceBundle.Hash(resources.Plan.FixedProjectBundle):null,
            ClosedWorkspaceResultSHA256=workspaceResultSHA256,
            Failures=failures.SelectMany(WfpNative.Describe).ToArray(),FormalAdmissionIssued=false,LaunchAuthorized=false,NetworkOpened=false,ClaudeLaunched=false,
            Boundary="LPAC_REQUIRED_NO_CAPABILITIES_NO_FALLBACK",AllHostResourceIsolationQualified=false,UserProjectToolchainQualified=false,FourteenEnvironmentRequirementsQualified=false,GpuQualified=false});
        state.WriteNew("resource-session-after-"+id+".json",Encoding.UTF8.GetBytes(report));return(success?0:3,report);
    }
}
