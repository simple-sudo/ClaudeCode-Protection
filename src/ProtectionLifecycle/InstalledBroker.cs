using System.Reflection;
using System.Text.Json;

namespace ProtectionLifecycle;

// The production command surface is deliberately smaller than the internal
// owners: no supplied path, SID, PID, key, package, script or activation option.
// It requires an already installed, verified current broker and elevation;
// it never elevates itself or makes a development checkout an admin launcher.
public static class InstalledBroker
{
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

            var registeredZeroObserved = jobs is not null && jobs.NamesAbsentAtOpen.Length == 0 &&
                jobs.PresentJobs.All(j => j.ObservedZero);
            // A name absent at open is a bounded observation, not proof that
            // all installation processes/escaped processes are absent.
            var status = quarantineObserved && registeredZeroObserved && failures.Count == 0
                ? "QUARANTINE_AND_REGISTERED_JOBS_OBSERVED" : "QUARANTINE_OR_STOP_NOT_CONFIRMED";
            var output = JsonSerializer.Serialize(new {
                SchemaVersion = 1, state.InstallationId, RequestId = requestId, Status = status,
                QuarantineObserved = quarantineObserved, RegisteredJobMembersZeroObserved = registeredZeroObserved,
                FenceCount = fences.Count, RegisteredJobsObserved = jobs?.PresentJobs.Length,
                NamesAbsentAtOpen = jobs?.NamesAbsentAtOpen.Length, FailedStages = failures.Count,
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
