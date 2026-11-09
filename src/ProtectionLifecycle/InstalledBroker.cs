using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace ProtectionLifecycle;

// The production command surface is deliberately smaller than the internal
// owners: no supplied host path, SID, script or activation option. The data
// pipe accepts only its ordinary installed caller PID, nonce and input digest.
// Workspace bytes are untrusted data, never a package/code-execution permit.
// Mutations require the installed verified broker and elevation. The two
// explicit diagnostics are read-only and can be separately qualified from a
// development build. Neither diagnostic opens the installed mutation path.
public static partial class InstalledBroker
{
    public static int RunSessionZeroOfflineCreatorService()=>SessionZeroCreatorService.Dispatch();
    public static int RunHostGpuReferenceChild()=>GpuHostReferenceQualification.RunChild();
    public static (int ExitCode,string Report) QualifyHostGpuReference()=>WithCurrentInstallation(GpuHostReferenceQualification.RunInstalled);
    public static int RunRestrictedPowerShell(string[] arguments)=>RestrictedPowerShellHost.Run(arguments);
    public static int RunRestrictedProject(string[] arguments)=>BundledProjectDevelopment.Run(arguments);
    public static int RunRestrictedProjectProbe(string[] arguments)=>BundledProjectDevelopment.RunProbe(arguments);
    public static (int ExitCode,string Report) DevelopBundledProject()=>WithCurrentInstallation(ProtectedSession.DevelopBundledProject);
    public static (int ExitCode,string Report) InspectFailedCallerProject(string sessionId,string expectedInputSHA256)
        =>WithCurrentInstallation((_,state,_)=>
    {
        var id=Identifiers.Hex32(sessionId);var input=Identifiers.Hash(expectedInputSHA256);
        // Fixed protected leaf only. Never read tool-error, Job/Stop files,
        // workspace results or caller paths, and never modify session state.
        var record=state.Read("resource-session-after-"+id+".json",FailedProjectInspection.MaximumBytes);
        var summary=FailedProjectInspection.Parse(record.Bytes,state.InstallationId,id,input);
        state.AssertHeld();return(0,JsonSerializer.Serialize(summary));
    });
    public static (int ExitCode,string Report) ProcessWorkspaceData(string expectedSHA256)
        =>WithCurrentInstallation((layout,state,version)=>
    {
        var expected=Identifiers.Hash(expectedSHA256);
        if(!Console.IsInputRedirected)throw new InvalidDataException("Byte-pinned redirected workspace data required");
        var bytes=ClaudeCodeProtection.Workspaces.WorkspaceFiles.ReadInput(Console.OpenStandardInput(),ClaudeCodeProtection.Workspaces.WorkspaceBundle.MaxBundleBytes);
        return ProcessWorkspaceBytes(layout,state,version,expected,bytes);
    });
    private static (int ExitCode,string Report) ProcessWorkspaceBytes(FixedLayout layout,ProtectedState state,VerifiedVersion version,string expected,byte[] bytes,Action? assertCaller=null)
    {
        if(ClaudeCodeProtection.Workspaces.WorkspaceBundle.Hash(bytes)!=expected)throw new InvalidDataException("Workspace input digest differs");
        var bundle=ClaudeCodeProtection.Workspaces.WorkspaceBundle.Parse(bytes);
        if(bundle.BaseSHA256 is not null || bundle.Files.Length==0)throw new InvalidDataException("Nonempty baseline workspace required");
        return assertCaller is null?ProtectedSession.ProcessWorkspaceData(layout,state,version,bytes):
            ProtectedSession.ProcessWorkspaceDataForCaller(layout,state,version,bytes,assertCaller);
    }
    public static byte[] ExportWorkspaceData(string sessionId,string expectedResultSHA256)
        =>ExportWorkspaceResult(sessionId,expectedResultSHA256,false);
    public static byte[] ExportDevelopedProject(string sessionId,string expectedResultSHA256)
        =>ExportWorkspaceResult(sessionId,expectedResultSHA256,true);
    private static byte[] ExportCallerCSharpProject(string sessionId,string expectedResultSHA256)
        =>ExportWorkspaceResult(sessionId,expectedResultSHA256,true,true);
    private static byte[] ExportWorkspaceResult(string sessionId,string expectedResultSHA256,bool developedProject,bool callerProject=false)
    {
        byte[]? result=null;
        _=WithCurrentInstallation((_,state,_)=>
        {
            var id=Identifiers.Hex32(sessionId);var expected=Identifiers.Hash(expectedResultSHA256);
            // Data publication alone is insufficient: only a successful
            // terminal record after exact cleanup can release this result.
            using var doc=JsonDocument.Parse(state.Read("resource-session-after-"+id+".json").Bytes);var r=doc.RootElement;
            if(r.GetProperty("InstallationId").GetString()!=state.InstallationId || r.GetProperty("SessionId").GetString()!=id ||
                r.GetProperty("Status").GetString()!=(callerProject?"CALLER_CSHARP_PROJECT_BUILT_AND_CLEANED":developedProject?"BUNDLED_PROJECT_DEVELOPED_AND_CLEANED":"WORKSPACE_DATA_PROCESSED_AND_CLEANED") ||
                r.GetProperty("ClosedWorkspaceResultSHA256").GetString()!=expected || r.GetProperty("Failures").GetArrayLength()!=0 ||
                r.GetProperty("FormalAdmissionIssued").GetBoolean() || r.GetProperty("NetworkOpened").GetBoolean() || r.GetProperty("ClaudeLaunched").GetBoolean())
                throw new InvalidDataException("Workspace success/cleanup receipt required");
            AssertWorkspaceExportClosure(state,r,id);
            var baseline=state.ReadWorkspaceData(id,false);var data=state.ReadWorkspaceData(id,true);
            if(data.SHA256!=expected || baseline.SHA256!=r.GetProperty("WorkspaceBaselineSHA256").GetString())throw new InvalidDataException("Workspace export digest differs");
            _=ClaudeCodeProtection.Workspaces.WorkspaceBundle.Compare(baseline.Bytes,data.Bytes);
            if(developedProject)
            {
                if(!r.GetProperty("ProjectDevelopmentRequested").GetBoolean() || !r.GetProperty("InheritedProjectToolIdentityObserved").GetBoolean() ||
                    (!callerProject && baseline.SHA256!=BundledProjectDevelopment.BaselineHash))throw new InvalidDataException("Explicit development receipt required");
                if(callerProject)
                {
                    if(r.GetProperty("Scope").GetString()!=ClaudeCodeProtection.Workspaces.WorkspacePipe.CallerProjectScope ||
                        !r.GetProperty("ProjectExecutionPermitConsumedAfterOwnerSealedPrivacy").GetBoolean())throw new InvalidDataException("Caller code execution receipt required");
                    _=ClaudeCodeProtection.Workspaces.HostPrivacyContract.Parse(r.GetProperty("HostPrivacy"),id,true);
                    ClaudeCodeProtection.Workspaces.CSharpProjectTask.Parse(baseline.Bytes).VerifyResult(data.Bytes);
                }
                else BundledProjectDevelopment.VerifyResult(data.Bytes);
            }
            result=data.Bytes;return(0,"WORKSPACE_DATA_EXPORT_READY");
        });
        return result??throw new InvalidDataException("Workspace export missing");
    }
    private static void AssertWorkspaceExportClosure(ProtectedState state,JsonElement terminal,string id)
    {
        // Reopen only this result's recorded owner evidence. A current upgrade
        // must not replace the historical release/manifest in its bindings.
        using var open=JsonDocument.Parse(state.Read("session-open-"+id+".json",8192).Bytes);
        var original=open.RootElement;
        var release=Identifiers.Hex32(StrictJson.Text(terminal,"Release"));
        var manifest=Identifiers.Hash(StrictJson.Text(terminal,"ManifestHash"));
        if(original.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(original,"InstallationId")!=state.InstallationId ||
            StrictJson.Text(original,"SessionId")!=id || StrictJson.Text(original,"Release")!=release || StrictJson.Text(original,"ManifestHash")!=manifest ||
            StrictJson.Text(original,"Scope")!="FIXED_OFFLINE_RESOURCES_NO_FORWARDING_NO_FORMAL_PERMIT" ||
            original.GetProperty("FormalSessionResumeAuthorized").GetBoolean() || original.GetProperty("AdmissionReusable").GetBoolean())
            throw WfpNative.Contract("WorkspaceExportOriginalSessionMismatch");
        var jobId=Identifiers.Hex32(StrictJson.Text(original,"JobId"));
        var intent=OwnedJobIntent.Read(state,jobId);
        if(intent.Release!=release || intent.ManifestSHA256!=manifest)throw WfpNative.Contract("WorkspaceExportJobReleaseMismatch");
        var completion=AtomicJobCompletion.ReadClosed(state,intent)??throw WfpNative.Contract("WorkspaceExportDurableJobClosureMissing");
        var persisted=JsonSerializer.Deserialize<RuntimeStop>(state.Read("session-stopped-"+id+".json",8192).Bytes);
        var reported=terminal.GetProperty("Stop").Deserialize<RuntimeStop>();
        var final=terminal.GetProperty("FinalJob").Deserialize<JobSnapshot>();
        if(persisted is null || reported is null || final is null || !persisted.MatchesResourceExport(reported,final,completion.Snapshot,id,jobId))
            throw WfpNative.Contract("WorkspaceExportClosureRecordsDiffer");
    }
    public static (int ExitCode,string Report) MigrateSessionNetwork()
    {
        ProtectedSession.AssertSystemTestingAllowed();
        return WithCurrentInstallation((_,state,version)=>
        {
            var plans=FencePlan.ReadAll(state,forNetworkMigration:true);
            if(plans.Any(p=>!(p.Data.PolicySHA256==CompiledFencePolicy.SHA256 && p.Data.ProxyPort==CompiledFencePolicy.ProxyPort) &&
                !(p.Data.PolicySHA256==SessionProxy.PolicySHA256 && p.Data.ProxyPort==SessionProxy.Port)))
                throw WfpNative.Contract("UnrecognizedNetworkPolicyRequiresSeparateReview");
            InstallationLoopbackLease.AssertClosedHistory(state);
            using var jobs=RegisteredJobSet.OpenForMaintenance(state);jobs.AssertClosedAdmissionsForNetworkMaintenance();
            var observations=new List<FenceObservation>();
            foreach(var plan in plans)
                if(plan.Data.PolicySHA256==CompiledFencePolicy.SHA256 || FencePlan.HasMigration(state,plan.Data.FenceId))
                    observations.Add(PersistentFence.MigrateRawProxyToSession(state,version,plan.Data.FenceId,jobs));
                else
                {
                    using var fence=PersistentFence.OpenExisting(state,plan.Data.FenceId);var observed=fence.Observe();
                    if(!observed.FullQuarantineObserved)throw WfpNative.Contract("ExistingSessionFenceNotQuarantined");
                }
            FencePlan.AssertNoPendingMigration(state);
            return(0,JsonSerializer.Serialize(new {SchemaVersion=1,Scope="INSTALLATION_NETWORK_MAINTENANCE_ONLY",state.InstallationId,
                Status=plans.Count==0?"NO_EXISTING_FENCES_TO_MIGRATE":"OWNED_GATEWAY_POLICY_SELECTED_IN_QUARANTINE",Migrated=observations.ToArray(),LaunchAuthorized=false,
                NetworkFunctionalityQualified=false,JobsTerminated=false}));
        },forNetworkMigration:true);
    }
    public static (int ExitCode,string Report) InspectEnvironmentExpectations()=>WithCurrentInstallation((_,state,_)=>
    {
        var raw=state.ReadOptional("session-environment-policy.json");
        var selected=raw is null?null:ClaudeCodeProtection.Security.EnvironmentExpectations.ReadForMaintenance(raw.Bytes,state.InstallationId);
        return(raw is null?2:0,JsonSerializer.Serialize(new {SchemaVersion=1,Scope="PROTECTED_ENVIRONMENT_INTENT_ONLY",state.InstallationId,
            NetworkPolicySHA256=SessionProxy.PolicySHA256,ConfiguredNetworkPolicySHA256=selected?.NetworkPolicySHA256,
            ExpectedPreviousSHA256=raw?.SHA256??"none",Status=raw is null?"MISSING":selected?.NetworkPolicySHA256==SessionProxy.PolicySHA256?"CONFIGURED":"REQUIRES_EXPLICIT_RECONFIGURATION",
            selected?.TimeZoneId,selected?.UserLocale,selected?.SystemLocale,LaunchAuthorized=false,ObservedEnvironmentVerified=false,SystemSettingsModified=false}));
    });
    public static (int ExitCode,string Report) ConfigureEnvironmentExpectations(string expectedPreviousSHA256,string zone,string userLocale,string systemLocale)
        =>WithCurrentInstallation((_,state,_)=>
    {
        var expected=expectedPreviousSHA256=="none"?null:Identifiers.Hash(expectedPreviousSHA256);
        var old=state.ReadOptional("session-environment-policy.json");
        if((old?.SHA256)!=expected)throw new InvalidOperationException("Environment intent changed; inspect before retrying");
        using var identity=System.Security.Principal.WindowsIdentity.GetCurrent();
        var ownerSid=identity.User?.Value??throw new InvalidOperationException("Explicit human policy owner required");
        if(old is not null && ClaudeCodeProtection.Security.EnvironmentExpectations.ReadForMaintenance(old.Bytes,state.InstallationId).OwnerSid!=ownerSid)
            throw new InvalidOperationException("Environment intent belongs to another human owner");
        var bytes=JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,NetworkPolicySHA256=SessionProxy.PolicySHA256,
            OwnerSid=ownerSid,TimeZoneId=zone,UserLocale=userLocale,SystemLocale=systemLocale});
        var selected=ClaudeCodeProtection.Security.EnvironmentExpectations.Parse(bytes,state.InstallationId,SessionProxy.PolicySHA256);
        _=TimeZoneInfo.FindSystemTimeZoneById(selected.TimeZoneId); // validate intent, never set the OS
        var request=Guid.NewGuid().ToString("N");
        state.WriteNew("environment-policy-before-"+request+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,
            ExpectedPreviousSHA256=expected,NextSHA256=selected.SHA256,PreviousBytesBase64=old is null?null:Convert.ToBase64String(old.Bytes),
            Scope="ENVIRONMENT_EXPECTATIONS_ONLY_NOT_EVIDENCE",SystemSettingsModified=false}));
        var hash=state.ReplacePointer("session-environment-policy.json",expected,bytes);
        if(hash!=selected.SHA256)throw new IOException("Environment intent readback differs");
        state.WriteNew("environment-policy-after-"+request+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,
            Status="CONFIGURED",PolicySHA256=hash,SystemSettingsModified=false,LaunchAuthorized=false}));
        return(0,JsonSerializer.Serialize(new {SchemaVersion=1,Status="CONFIGURED",PolicySHA256=hash,SystemSettingsModified=false,
            LaunchAuthorized=false,ObservedEnvironmentVerified=false}));
    });
    private static (int ExitCode,string Report) WithCurrentInstallation(Func<FixedLayout,ProtectedState,VerifiedVersion,(int ExitCode,string Report)> operation,bool forNetworkMigration=false,bool forManifestAccessRecovery=false)
    {
        ProtectedState.RequireAdministrator();var layout=FixedLayout.FromWindows();using var state=ProtectedState.OpenExisting(layout);
        using var version=OpenVerifiedCurrentInstallation(layout,state,out _);
        LifecycleRecovery.AssertNoPending(state,forNetworkMigration:forNetworkMigration,forManifestAccessRecovery:forManifestAccessRecovery);
        return operation(layout,state,version);
    }
    // Authentication of the current installation is common to maintenance and
    // execution. Pending-operation checks remain with each operation.
    private static VerifiedVersion OpenVerifiedCurrentInstallation(FixedLayout layout,ProtectedState state,out CurrentPointer current)
    {
        current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
        var version=VerifiedVersion.Open(layout,state,current.Release);
        try
        {
            if(version.Package.ManifestHash!=current.ManifestSHA256)throw WfpNative.Contract("InstalledPointerManifestMismatch");
            AssertInstalledHost(layout,state,version);
            return version;
        }
        catch{version.Dispose();throw;}
    }
    // The sole production development-session entry. It deliberately has no
    // target/script/report input and no fallback to a qualification command.
    // There is no positive issuer until current trusted collectors, a confined
    // forwarding channel and the remaining system-security gates exist.
    public static (int ExitCode,string Report) LaunchDevelopmentSession()
    {
        ProtectedState.RequireAdministrator();var layout=FixedLayout.FromWindows();
        using var state=ProtectedState.OpenExisting(layout);
        using var version=OpenVerifiedCurrentInstallation(layout,state,out _);
        return ProtectedSession.Request(layout,state,version,false);
    }

    public static (int ExitCode,string Report) RunSyntheticSession()
    {
        ProtectedSession.AssertSystemTestingAllowed();
        ProtectedState.RequireAdministrator();var layout=FixedLayout.FromWindows();using var state=ProtectedState.OpenExisting(layout);
        using var version=OpenVerifiedCurrentInstallation(layout,state,out _);
        return ProtectedSession.Request(layout,state,version,true);
    }

    public static (int ExitCode,string Report) QualifySessionGateway()=>WithCurrentInstallation(ProtectedSession.QualifySessionGateway);
    public static (int ExitCode,string Report) QualifyWinsockSessionGateway()=>WithCurrentInstallation(ProtectedSession.QualifyWinsockSessionGateway);
    public static (int ExitCode,string Report) QualifyWinsockTransportSessionGateway()=>WithCurrentInstallation(ProtectedSession.QualifyWinsockTransportSessionGateway);
    public static (int ExitCode,string Report) QualifyWinsockProviderSessionGateway()=>WithCurrentInstallation(ProtectedSession.QualifyWinsockProviderSessionGateway);
    public static (int ExitCode,string Report) QualifyInternetClientSessionGateway()=>WithCurrentInstallation(ProtectedSession.QualifyInternetClientSessionGateway);
    public static (int ExitCode,string Report) QualifyZeroCapabilityComparisonGateway()=>WithCurrentInstallation(ProtectedSession.QualifyZeroCapabilityComparisonGateway);
    public static (int ExitCode,string Report) QualifyNoContentHttpsCanary()=>WithCurrentInstallation(ProtectedSession.QualifyNoContentHttpsCanary);
    public static (int ExitCode,string Report) QualifyFixedOpenSslHead()=>WithCurrentInstallation(ProtectedSession.QualifyFixedOpenSslHead);
    public static (int ExitCode,string Report) QualifyLocalManagementBoundary()=>WithCurrentInstallation(ProtectedSession.QualifyLocalManagementBoundary);
    public static (int ExitCode,string Report) QualifySchannelAcquisition()
        =>WithCurrentInstallation((layout,state,version)=>OfflineTlsQualification.Run(layout,state,version,OfflineTlsProbe.Schannel));
    public static (int ExitCode,string Report) QualifyOpenSslOffline()
        =>WithCurrentInstallation((layout,state,version)=>OfflineTlsQualification.Run(layout,state,version,OfflineTlsProbe.OpenSsl));
    public static (int ExitCode,string Report) QualifyOfflineConsole()
        =>WithCurrentInstallation(OfflineConsoleQualification.Run);
    public static (int ExitCode,string Report) QualifyIndependentOfflineConsole()
        =>WithCurrentInstallation(OfflineConsoleQualification.RunIndependent);
    public static (int ExitCode,string Report) InspectWinsockReadAccess()=>WithCurrentInstallation((_,state,_)=>SessionWinsockReadAccess.Inspect(state),forManifestAccessRecovery:true);
    public static (int ExitCode,string Report) RecoverWinsockReadAccess()=>WithCurrentInstallation((_,state,_)=>SessionWinsockReadAccess.Recover(state),forManifestAccessRecovery:true);
    public static int RunGatewayQualificationCanary()=>AtomicChild.RunGatewayQualificationCanary();
    public static int RunInternetClientGatewayQualificationCanary()=>AtomicChild.RunInternetClientGatewayQualificationCanary();
    public static int RunZeroCapabilityComparisonCanary()=>AtomicChild.RunZeroCapabilityComparisonCanary();
    public static int RunNoContentHttpsCanary()=>AtomicChild.RunNoContentHttpsCanary();
    public static int RunFixedOpenSslHeadCanary()=>AtomicChild.RunFixedOpenSslHeadCanary();
    public static int RunLocalManagementBoundaryCanary()=>AtomicChild.RunLocalManagementBoundaryCanary();
    public static int RunSchannelAcquisitionChild()=>AtomicChild.RunOfflineTlsChild(OfflineTlsProbe.Schannel);
    public static int RunOpenSslOfflineChild()=>AtomicChild.RunOfflineTlsChild(OfflineTlsProbe.OpenSsl);
    public static int RunOfflineConsoleChild()=>OfflineConsoleQualification.RunChild();
    public static int RunAdmissionCanary()
    {
        if(Environment.GetEnvironmentVariable("CPC_RESOURCE_PLAN") is not null)return AtomicChild.RunResourceCanary();
        ProtectedSession.AssertSystemTestingAllowed();return AtomicChild.RunCanary();
    }
    public static (int ExitCode,string Report) QualifyResources()=>WithCurrentInstallation(ProtectedSession.QualifyResources);
    public static (int ExitCode,string Report) QualifyToolchain()=>WithCurrentInstallation(ProtectedSession.QualifyToolchain);
    public static (int ExitCode,string Report) QualifyResourceRecovery()=>WithCurrentInstallation(ProtectedSession.QualifyResourceRecovery);
    public static (int ExitCode,string Report) RecoverSessionResources()=>WithCurrentInstallation((_,state,_)=>SessionProfileRecovery.RecoverClosed(state));
    public static (int ExitCode,string Report) InspectResourceRecovery()=>WithCurrentInstallation((_,state,_)=>SessionProfileRecovery.InspectRecovery(state));
    public static (int ExitCode,string Report) RecoverUnstartedSessionResources()=>WithCurrentInstallation((_,state,_)=>SessionProfileRecovery.RecoverNeverStarted(state));
    public static (int ExitCode,string Report) InspectTimeZoneReadAccess()=>WithCurrentInstallation((_,state,_)=>SessionTimeZoneReadAccess.Inspect(state),forManifestAccessRecovery:true);
    public static (int ExitCode,string Report) RecoverTimeZoneReadAccess()=>WithCurrentInstallation((_,state,_)=>SessionTimeZoneReadAccess.Recover(state),forManifestAccessRecovery:true);
    public static (int ExitCode,string Report) InspectManifestReadAccess()=>WithCurrentInstallation((_,state,_)=>SessionManifestReadAccess.Inspect(state),forManifestAccessRecovery:true);
    public static (int ExitCode,string Report) RecoverManifestReadAccess()=>WithCurrentInstallation((_,state,_)=>SessionManifestReadAccess.Recover(state),forManifestAccessRecovery:true);
    public static (int ExitCode,string Report) InspectEtwProviderAccess()=>WithCurrentInstallation((_,state,_)=>SessionEtwProviderAccess.Inspect(state),forManifestAccessRecovery:true);
    public static (int ExitCode,string Report) RecoverEtwProviderAccess()=>WithCurrentInstallation((_,state,_)=>SessionEtwProviderAccess.Recover(state),forManifestAccessRecovery:true);
    public static (int ExitCode,string Report) QualifyWatchdog()
    {
        ProtectedSession.AssertSystemTestingAllowed();
        ProtectedState.RequireAdministrator();var layout=FixedLayout.FromWindows();using var state=ProtectedState.OpenExisting(layout);
        using var version=OpenVerifiedCurrentInstallation(layout,state,out _);
        return WatchdogQualification.Run(layout,state,version);
    }
    public static (int ExitCode,string Report) QualifyGpu()
    {
        ProtectedSession.AssertSystemTestingAllowed();
        ProtectedState.RequireAdministrator();var layout=FixedLayout.FromWindows();using var state=ProtectedState.OpenExisting(layout);
        using var version=OpenVerifiedCurrentInstallation(layout,state,out _);
        return GpuQualification.Run(layout,state,version);
    }
    public static (int ExitCode,string Report) QualifyNetwork()
    {
        ProtectedSession.AssertSystemTestingAllowed();
        ProtectedState.RequireAdministrator();var layout=FixedLayout.FromWindows();
        using var state=ProtectedState.OpenExisting(layout);
        using var version=OpenVerifiedCurrentInstallation(layout,state,out _);
        return NetworkQualification.Run(layout,state,version);
    }

    public static (int ExitCode,string Report) InspectInstalledFence()
    {
        ProtectedState.RequireAdministrator();var layout=FixedLayout.FromWindows();
        using var state=ProtectedState.OpenExisting(layout);
        using var version=OpenVerifiedCurrentInstallation(layout,state,out _);
        var observations=new List<FenceObservation>();
        foreach(var plan in FencePlan.ReadAll(state))
        {using var owner=PersistentFence.OpenExisting(state,plan.Data.FenceId);observations.Add(owner.Observe());}
        var complete=observations.Count>0 && observations.All(o=>o.FullQuarantineObserved);
        return(complete?0:3,JsonSerializer.Serialize(new {SchemaVersion=1,Scope="INSTALLED_FENCE_READ_ONLY",state.InstallationId,
            QuarantineObjectsObserved=complete,Observations=observations,PolicyModified=false,JobApiCalled=false,NetworkBehaviorQualified=false}));
    }

    public static (int ExitCode,string Report) QualifyAtomicAdmission()
    {
        ProtectedSession.AssertSystemTestingAllowed();
        ProtectedState.RequireAdministrator();var layout=FixedLayout.FromWindows();
        using var state=ProtectedState.OpenExisting(layout);
        using var version=OpenVerifiedCurrentInstallation(layout,state,out var current);
        LifecycleRecovery.AssertNoPending(state);
        var plans=FencePlan.ReadAll(state);if(plans.Count==0)throw WfpNative.Contract("AtomicQualificationRequiresQuarantine");
        foreach(var plan in plans)
        {using var fence=PersistentFence.OpenExisting(state,plan.Data.FenceId);if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("AtomicQualificationRequiresCompleteQuarantine");}
        var request=Guid.NewGuid().ToString("N");
        state.WriteNew("atomic-before-"+request+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,
            current.Release,current.ManifestSHA256,Scope="FIXED_INSTALLED_NO_NETWORK_CANARY",AtUtc=DateTime.UtcNow.ToString("o")}));
        using var profile=InstallationProfileLease.Create(state);
        using var job=OwnedKernelJob.CreateEmpty(state,version);
        Exception? failure=null;uint? childExit=null;bool resumed=false;JobSnapshot? final=null;
        try
        {
            using var child=AtomicChild.CreateCanary(layout,state,version,job,profile);
            _=child.ResumeQuarantined();resumed=true;childExit=child.WaitForCanaryExit();
            if(childExit!=42)throw WfpNative.Contract("AtomicCanaryExitMismatch");
        }
        catch(Exception ex){failure=ex;}
        finally
        {
            try
            {
                if(job.AtomicAdmissionReserved){final=job.CloseAtomicAdmissionAndStop();profile.AfterOwnedJobZero(final);}
                else
                {
                    _=job.StopAndVerifyZero();
                    throw WfpNative.Contract("AtomicAdmissionWasNotReservedCompletionUnknown");
                }
            }
            catch(Exception ex){failure=failure is null?ex:new AggregateException(failure,ex);}
        }
        var complete=resumed && childExit==42 && final is not null && final.ObservedZero && failure is null;
        var report=JsonSerializer.Serialize(new {SchemaVersion=1,state.InstallationId,RequestId=request,job.JobId,ChildExitCode=childExit,
            Status=complete?"ATOMIC_CANARY_ADMISSION_AND_CLOSED_JOB_OBSERVED":"ATOMIC_CANARY_NOT_CONFIRMED",
            ResumedAfterIdentityJobAndQuarantineChecks=resumed,OneShotAdmissionClosedAndMembersZero=final?.ObservedZero??false,
            Failures=failure is null?Array.Empty<WfpErrorEvidence>():WfpNative.Describe(failure),NetworkBehaviorQualified=false,
            ClaudeLaunched=false,ProxyQualified=false,ControllerCrashQualified=false});
        state.WriteNew("atomic-after-"+request+".json",System.Text.Encoding.UTF8.GetBytes(report));
        return(complete?0:3,report);
    }
    public static (int ExitCode, string Report) InspectRuntime()
    {
        var layout=WfpNative.LayoutSnapshot();
        try
        {
            WfpNative.AssertLayout();
            return (0,JsonSerializer.Serialize(new {SchemaVersion=1,Scope="CURRENT_PROCESS_MARSHALLING_LAYOUT_ONLY",Status="LAYOUT_MATCHES_DECLARED_X64_CONTRACT",
                Runtime=Environment.Version.ToString(),Is64BitProcess=Environment.Is64BitProcess,Layout=layout,
                WfpApiCalled=false,JobApiCalled=false,NativeFilterFunctionalityQualified=false,ProtectionQualified=false}));
        }
        catch(PlatformNotSupportedException ex)
        {
            return (2,JsonSerializer.Serialize(new {SchemaVersion=1,Scope="CURRENT_PROCESS_MARSHALLING_LAYOUT_ONLY",Status="LAYOUT_NOT_QUALIFIED",
                Runtime=Environment.Version.ToString(),Is64BitProcess=Environment.Is64BitProcess,Layout=layout,
                Failures=WfpNative.Describe(ex),WfpApiCalled=false,JobApiCalled=false,ProtectionQualified=false}));
        }
    }

    public static (int ExitCode, string Report) InspectWfp()
    {
        try
        {
            // ABI guard precedes the first WFP call. No install/private state,
            // caller-provided key, filter changes or process handles are used.
            using var engine=WfpNative.Open();
            // These are independent fixed builtin metadata reads, not a
            // multi-object policy/admission snapshot. Each GetByKey enforces
            // layer READ rights; an explicit engine transaction unnecessarily
            // requires BEGIN_READ_TXN even for this ordinary-user diagnostic.
            var layers=new[]{ReadLayer(WfpNative.ConnectV4),ReadLayer(WfpNative.ConnectV6)};
            return (0,JsonSerializer.Serialize(new {SchemaVersion=1,Scope="LOCAL_WFP_READ_ONLY_BUILTIN_LAYER_QUERY",Status="BUILTIN_LAYERS_OBSERVED",
                Runtime=Environment.Version.ToString(),Layers=layers,ExplicitTransaction=false,ObservationConsistency="INDEPENDENT_BUILTIN_METADATA_READS",
                PolicyModified=false,JobApiCalled=false,NativeFilterFunctionalityQualified=false,ProtectionQualified=false,RebootQualified=false}));

            object ReadLayer(Guid key)
            {
                var status=WfpNative.FwpmLayerGetByKey0(engine,in key,out var pointer);
                try
                {
                    WfpNative.Check(status,"ReadBuiltinConnectLayer");
                    if(pointer==IntPtr.Zero)throw new InvalidDataException("Missing builtin layer response");
                    var layer=Marshal.PtrToStructure<WfpNative.Layer>(pointer);
                    if(layer.Key!=key || layer.FieldCount is <1 or >128 || layer.Fields==IntPtr.Zero)
                        throw new InvalidDataException("Builtin layer response differs");
                    return new {Key=key.ToString("D"),Name=WfpNative.Name(layer.Display.Name),layer.Flags,layer.FieldCount,layer.Id};
                }
                finally{if(pointer!=IntPtr.Zero)WfpNative.FwpmFreeMemory0(ref pointer);}
            }
        }
        catch(Exception ex) when(ex is WfpFailure or System.ComponentModel.Win32Exception or PlatformNotSupportedException or InvalidDataException or AggregateException)
        {
            return (2,JsonSerializer.Serialize(new {SchemaVersion=1,Scope="LOCAL_WFP_READ_ONLY_BUILTIN_LAYER_QUERY",Status="BUILTIN_LAYER_READ_NOT_CONFIRMED",
                Failures=WfpNative.Describe(ex),PolicyModified=false,JobApiCalled=false,ProtectionQualified=false}));
        }
    }

    public static (int ExitCode, string Report) Quarantine()
    {
        ProtectedState.RequireAdministrator();
        var layout = FixedLayout.FromWindows();
        using var state = ProtectedState.OpenExisting(layout);
        var current = CurrentPointer.Parse(state.Read("current.json", 4096), state.InstallationId);
        using var version = VerifiedVersion.Open(layout, state, current.Release);
        if (version.Package.ManifestHash != current.ManifestSHA256)
            throw new InvalidDataException("Current pointer differs from the held installed version");
        AssertInstalledHost(layout, state, version);

        var requestId = Guid.NewGuid().ToString("N");
        var request = BrokerRequest.Parse(JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion = 1, state.InstallationId, RequestId = requestId, Operation = "quarantine", Target = (string?)null
        }));
        var requestHash = request.BindOnce(state);
        state.WriteNew("quarantine-before-" + requestId + ".json", JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion = 1, state.InstallationId, RequestId = requestId, RequestSHA256 = requestHash,
            Release = current.Release, current.ManifestSHA256, Scope = "INSTALLATION_PACKAGE_AND_REGISTERED_JOBS_ONLY",
            Status = "REQUEST_RECORDED_BEFORE_ACTION", AtUtc = DateTime.UtcNow.ToString("o")
        }));

        var fences = new List<PersistentFence>();
        var observations = new List<FenceObservation>();
        var finalObservations = new List<FenceObservation>();
        var failures = new List<object>();
        RegisteredJobObservation? jobs = null;
        var quarantineObserved = false;
        try
        {
            try
            {
                AssertInstalledHost(layout, state, version);
                var plans = FencePlan.ReadAll(state);
                // Preflight every recorded WFP owner before replacing any. A
                // foreign key or inaccessible object is not adopted/deleted.
                foreach (var plan in plans)
                {
                    var fence = PersistentFence.OpenExisting(state, plan.Data.FenceId);
                    fences.Add(fence);
                    _ = fence.Observe();
                }
                if (fences.Count == 0)
                    fences.Add(PersistentFence.CreateQuarantined(state, version));
                else
                    foreach (var fence in fences)
                    {
                        AssertInstalledHost(layout, state, version);
                        _ = fence.ReinstateQuarantine();
                    }
                // Retain independent committed readback, never just an add or
                // transaction return. All observations remain ALE scope only.
                foreach (var fence in fences) observations.Add(fence.Observe());
                quarantineObserved = observations.Count > 0 && observations.All(o => o.FullQuarantineObserved);
                if (!quarantineObserved) throw new InvalidDataException("Complete quarantine was not observed");
            }
            catch (Exception ex) { failures.Add(Failure("quarantine", ex)); }

            // A failed WFP action must not prevent an attempt to stop the exact
            // registered jobs. Open/validate the entire set before terminating
            // members. No process-name/PID fallback is available here.
            try
            {
                AssertInstalledHost(layout, state, version);
                using var owned = RegisteredJobSet.OpenForMaintenance(state);
                jobs = owned.StopAndObserveRegisteredMembers();
            }
            catch (Exception ex) { failures.Add(Failure("registered-jobs", ex)); }

            if (quarantineObserved)
            {
                // Stopping a job can take time. Do not publish the earlier
                // WFP snapshot as if it were a fresh post-stop observation.
                quarantineObserved = false;
                try
                {
                    AssertInstalledHost(layout, state, version);
                    foreach (var fence in fences) finalObservations.Add(fence.Observe());
                    quarantineObserved = finalObservations.Count == fences.Count &&
                        finalObservations.Count > 0 && finalObservations.All(o => o.FullQuarantineObserved);
                    if (!quarantineObserved) throw new InvalidDataException("Post-stop quarantine readback differs");
                }
                catch (Exception ex) { failures.Add(Failure("post-stop-quarantine", ex)); }
            }

            var registeredZeroObserved = jobs is not null && jobs.AllRegisteredMembersZeroObserved;
            var registeredResolved = jobs is not null && jobs.AllRegisteredJobsResolved;
            // A name absent at open is a bounded observation, not proof that
            // all installation processes/escaped processes are absent.
            var status = quarantineObserved && registeredResolved && failures.Count == 0
                ? registeredZeroObserved ? "QUARANTINE_AND_REGISTERED_JOBS_OBSERVED" : "QUARANTINE_AND_REGISTERED_JOBS_RESOLVED"
                : "QUARANTINE_OR_STOP_NOT_CONFIRMED";
            var output = JsonSerializer.Serialize(new {
                SchemaVersion = 1, state.InstallationId, RequestId = requestId, Status = status,
                QuarantineObserved = quarantineObserved, RegisteredJobMembersZeroObserved = registeredZeroObserved,
                FenceCount = fences.Count, RegisteredJobsExpected = jobs?.ExpectedJobs, RegisteredJobsObserved = jobs?.PresentJobs.Length,
                NamesAbsentAtOpen = jobs?.NamesAbsentAtOpen.Length, FailedStages = failures.Count,
                RegisteredJobFailures = jobs?.Failures.Length,
                CompletedAdmissionJobs = jobs?.CompletedAdmissionJobIds.Length,
                RetiredNeverAdmittedJobs = jobs?.RetiredNeverAdmittedJobIds.Length,
                CompleteProcessOwnershipQualified = false, ImmediateDisconnectQualified = false,
                LaunchQualified = false, ProxyQualified = false, RebootQualified = false
            });
            state.WriteNew("quarantine-after-" + requestId + ".json", JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion = 1, state.InstallationId, RequestId = requestId, RequestSHA256 = requestHash,
                Status = status, FenceObservationsBeforeStop = observations, FenceObservationsAfterStop = finalObservations,
                RegisteredJobs = jobs, Failures = failures,
                Scope = "INSTALLATION_PACKAGE_AND_REGISTERED_JOBS_ONLY", AtUtc = DateTime.UtcNow.ToString("o")
            }));
            return (failures.Count == 0 && quarantineObserved && registeredResolved ? 0 : 3, output);
        }
        finally
        {
            // Closing does not remove persistent filters or claim quiescence.
            for (var i = fences.Count - 1; i >= 0; i--) fences[i].Dispose();
        }
    }

    private static void AssertInstalledHost(FixedLayout layout, ProtectedState state, VerifiedVersion version)
    {
        version.AssertHeld(state);
        var admin = WindowsPathSeal.Child(layout.Version(version.Package.Release), "bin/admin");
        var entry = Assembly.GetEntryAssembly();
        var host = Environment.ProcessPath;
        if (host is null || entry is null || entry.GetName().Name != "ProtectionBroker" ||
            !Same(host, WindowsPathSeal.Child(admin, "ProtectionBroker.exe")) ||
            !Same(entry.Location, WindowsPathSeal.Child(admin, "ProtectionBroker.dll")) ||
            !Same(typeof(InstalledBroker).Assembly.Location, WindowsPathSeal.Child(admin, "ProtectionLifecycle.dll")))
            throw new InvalidOperationException("Only the held current installed broker may perform this command");
    }

    private static bool Same(string actual, string expected) =>
        string.Equals(WindowsPathSeal.Canonical(actual), expected, StringComparison.OrdinalIgnoreCase);

    private static object Failure(string stage, Exception error) => new {
        Stage = stage, Failures = WfpNative.Describe(error)
    };
}
