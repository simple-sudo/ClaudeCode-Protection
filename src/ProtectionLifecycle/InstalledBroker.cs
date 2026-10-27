using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace ProtectionLifecycle;

// The production command surface is deliberately smaller than the internal
// owners: no supplied path, SID, PID, key, package, script or activation option.
// Mutations require the installed verified broker and elevation. The two
// explicit diagnostics are read-only and can be separately qualified from a
// development build. Neither diagnostic opens the installed mutation path.
public static class InstalledBroker
{
    // The sole production development-session entry. It deliberately has no
    // target/script/report input and no fallback to a qualification command.
    // There is no positive issuer until current trusted collectors, a confined
    // forwarding channel and the remaining system-security gates exist.
    public static (int ExitCode,string Report) LaunchDevelopmentSession()
    {
        ProtectedState.RequireAdministrator();var layout=FixedLayout.FromWindows();
        using var state=ProtectedState.OpenExisting(layout);
        var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
        using var version=VerifiedVersion.Open(layout,state,current.Release);
        if(version.Package.ManifestHash!=current.ManifestSHA256)throw WfpNative.Contract("InstalledPointerManifestMismatch");
        AssertInstalledHost(layout,state,version);
        return ProtectedSession.Request(layout,state,version,false);
    }

    public static (int ExitCode,string Report) RunSyntheticSession()
    {
        ProtectedSession.AssertSystemTestingAllowed();
        ProtectedState.RequireAdministrator();var layout=FixedLayout.FromWindows();using var state=ProtectedState.OpenExisting(layout);
        var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
        using var version=VerifiedVersion.Open(layout,state,current.Release);
        if(version.Package.ManifestHash!=current.ManifestSHA256)throw WfpNative.Contract("InstalledPointerManifestMismatch");
        AssertInstalledHost(layout,state,version);return ProtectedSession.Request(layout,state,version,true);
    }

    public static int RunAdmissionCanary()
    {ProtectedSession.AssertSystemTestingAllowed();return AtomicChild.RunCanary();}
    public static (int ExitCode,string Report) QualifyWatchdog()
    {
        ProtectedSession.AssertSystemTestingAllowed();
        ProtectedState.RequireAdministrator();var layout=FixedLayout.FromWindows();using var state=ProtectedState.OpenExisting(layout);
        var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);using var version=VerifiedVersion.Open(layout,state,current.Release);
        if(version.Package.ManifestHash!=current.ManifestSHA256)throw WfpNative.Contract("InstalledPointerManifestMismatch");
        AssertInstalledHost(layout,state,version);return WatchdogQualification.Run(layout,state,version);
    }
    public static (int ExitCode,string Report) QualifyGpu()
    {
        ProtectedSession.AssertSystemTestingAllowed();
        ProtectedState.RequireAdministrator();var layout=FixedLayout.FromWindows();using var state=ProtectedState.OpenExisting(layout);
        var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);using var version=VerifiedVersion.Open(layout,state,current.Release);
        if(version.Package.ManifestHash!=current.ManifestSHA256)throw WfpNative.Contract("InstalledPointerManifestMismatch");
        AssertInstalledHost(layout,state,version);return GpuQualification.Run(layout,state,version);
    }
    public static (int ExitCode,string Report) QualifyNetwork()
    {
        ProtectedSession.AssertSystemTestingAllowed();
        ProtectedState.RequireAdministrator();var layout=FixedLayout.FromWindows();
        using var state=ProtectedState.OpenExisting(layout);
        var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
        using var version=VerifiedVersion.Open(layout,state,current.Release);
        if(version.Package.ManifestHash!=current.ManifestSHA256)throw WfpNative.Contract("InstalledPointerManifestMismatch");
        AssertInstalledHost(layout,state,version);return NetworkQualification.Run(layout,state,version);
    }

    public static (int ExitCode,string Report) InspectInstalledFence()
    {
        ProtectedState.RequireAdministrator();var layout=FixedLayout.FromWindows();
        using var state=ProtectedState.OpenExisting(layout);
        var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
        using var version=VerifiedVersion.Open(layout,state,current.Release);
        if(version.Package.ManifestHash!=current.ManifestSHA256)throw WfpNative.Contract("InstalledPointerManifestMismatch");
        AssertInstalledHost(layout,state,version);
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
        var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
        using var version=VerifiedVersion.Open(layout,state,current.Release);
        if(version.Package.ManifestHash!=current.ManifestSHA256)throw WfpNative.Contract("InstalledPointerManifestMismatch");
        AssertInstalledHost(layout,state,version);LifecycleRecovery.AssertNoPending(state);
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
            // A name absent at open is a bounded observation, not proof that
            // all installation processes/escaped processes are absent.
            var status = quarantineObserved && registeredZeroObserved && failures.Count == 0
                ? "QUARANTINE_AND_REGISTERED_JOBS_OBSERVED" : "QUARANTINE_OR_STOP_NOT_CONFIRMED";
            var output = JsonSerializer.Serialize(new {
                SchemaVersion = 1, state.InstallationId, RequestId = requestId, Status = status,
                QuarantineObserved = quarantineObserved, RegisteredJobMembersZeroObserved = registeredZeroObserved,
                FenceCount = fences.Count, RegisteredJobsExpected = jobs?.ExpectedJobs, RegisteredJobsObserved = jobs?.PresentJobs.Length,
                NamesAbsentAtOpen = jobs?.NamesAbsentAtOpen.Length, FailedStages = failures.Count,
                RegisteredJobFailures = jobs?.Failures.Length,
                CompletedAdmissionJobs = jobs?.CompletedAdmissionJobIds.Length,
                CompleteProcessOwnershipQualified = false, ImmediateDisconnectQualified = false,
                LaunchQualified = false, ProxyQualified = false, RebootQualified = false
            });
            state.WriteNew("quarantine-after-" + requestId + ".json", JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion = 1, state.InstallationId, RequestId = requestId, RequestSHA256 = requestHash,
                Status = status, FenceObservationsBeforeStop = observations, FenceObservationsAfterStop = finalObservations,
                RegisteredJobs = jobs, Failures = failures,
                Scope = "INSTALLATION_PACKAGE_AND_REGISTERED_JOBS_ONLY", AtUtc = DateTime.UtcNow.ToString("o")
            }));
            return (failures.Count == 0 && quarantineObserved && registeredZeroObserved ? 0 : 3, output);
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
