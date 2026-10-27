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
            var layers=WfpNative.Transaction(engine,true,()=>new[]{ReadLayer(WfpNative.ConnectV4),ReadLayer(WfpNative.ConnectV6)});
            return (0,JsonSerializer.Serialize(new {SchemaVersion=1,Scope="LOCAL_WFP_READ_ONLY_BUILTIN_LAYER_QUERY",Status="BUILTIN_LAYERS_OBSERVED",
                Runtime=Environment.Version.ToString(),Layers=layers,ReadOnlyTransaction=true,
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
