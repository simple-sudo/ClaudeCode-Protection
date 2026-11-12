using System.ComponentModel;
using System.Linq;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record RegisteredJobFailure(string JobId,string Stage,WfpErrorEvidence[] Errors);
internal sealed record RegisteredJobObservation(int ExpectedJobs,string[] NamesAbsentAtOpen,JobSnapshot[] PresentJobs,RegisteredJobFailure[] Failures,
    string Scope,bool CompleteProcessOwnershipQualified,bool AdmissionOrNetworkQualified,string[] CompletedAdmissionJobIds,string[] RetiredNeverAdmittedJobIds)
{
    // A later zero observation never repairs a failed stop, an unavailable job
    // or a missing observation. All recorded intent entries remain in scope.
    internal bool AllRegisteredMembersZeroObserved=>RetiredNeverAdmittedJobIds.Length==0 && AllRegisteredJobsResolved;
    internal bool AllRegisteredJobsResolved=>NamesAbsentAtOpen.Length==0 && Failures.Length==0 &&
        PresentJobs.Length+CompletedAdmissionJobIds.Length+RetiredNeverAdmittedJobIds.Length==ExpectedJobs && PresentJobs.All(s=>s.ObservedZero);
}

// Holds all recovered handles before terminating any members. This is useful
// to the future runtime owner, but is deliberately NOT ILifecycleRuntimeLease:
// registered-job membership alone cannot prove launch admission or absence of
// unassigned/escaped processes or qualified WFP resources.
internal sealed class RegisteredJobSet : IDisposable
{
    private readonly ProtectedState state;
    private readonly IReadOnlyList<OwnedJobIntent> intents;
    private readonly List<OwnedKernelJob> jobs=new();
    private readonly List<string> absent=new();
    private readonly List<string> completed=new();
    private readonly List<string> retired=new();
    private bool disposed;
    private RegisteredJobSet(ProtectedState state,IReadOnlyList<OwnedJobIntent> intents){this.state=state;this.intents=intents;}
    internal static RegisteredJobSet OpenForMaintenance(ProtectedState state)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();var set=new RegisteredJobSet(state,OwnedJobIntent.ReadAll(state));
        try
        {
            foreach(var intent in set.intents)
            {
                if(UnadmittedJobRetirement.Read(state,intent) || SessionZeroCreatorRecovery.ReadRetired(state,intent))
                {set.retired.Add(intent.JobId);continue;}
                if(AtomicJobCompletion.ReadClosed(state,intent) is not null){set.completed.Add(intent.JobId);continue;}
                var job=OwnedKernelJob.OpenExisting(state,intent);
                if(job is null)set.absent.Add(intent.JobId);else{set.jobs.Add(job);_=job.Observe();}
            }
            set.AssertHeld();return set;
        }
        catch(Exception ex)
        {
            try{state.WriteNew("job-set-failure-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,InstallationId=state.InstallationId,Status="REGISTERED_JOB_SET_NOT_QUALIFIED",OpenedJobIds=set.jobs.Select(j=>j.JobId).ToArray(),
                FailureType=ex.GetType().Name,FailureCode=ex is Win32Exception native?native.NativeErrorCode:ex.HResult,AtUtc=DateTime.UtcNow.ToString("o")
            }));}catch(Exception log){throw new AggregateException("Job-set recovery and failure recording both failed",ex,log);}finally{set.Dispose();}throw;
        }
    }
    private void AssertHeld()
    {
        if(disposed)throw new ObjectDisposedException(nameof(RegisteredJobSet));state.AssertHeld();
        if(!OwnedJobIntent.ReadAll(state).SequenceEqual(intents))throw new InvalidDataException("Registered job set changed during maintenance");
        foreach(var id in completed)if(AtomicJobCompletion.ReadClosed(state,intents.Single(i=>i.JobId==id)) is null)
            throw new InvalidDataException("Completed admission proof changed");
        foreach(var id in retired)
        {
            var intent=intents.Single(i=>i.JobId==id);
            if(!UnadmittedJobRetirement.Read(state,intent) && !SessionZeroCreatorRecovery.ReadRetired(state,intent))
                throw new InvalidDataException("Retired admission proof changed");
        }
    }
    internal RegisteredJobObservation StopAndObserveRegisteredMembers()
    {
        var failures=new List<RegisteredJobFailure>();
        AssertHeld();
        foreach(var job in jobs)
        {
            // Loss of the protected inventory/lock is a global authority error,
            // not a per-job error that permits more termination operations.
            AssertHeld();
            try{_=job.StopAndVerifyZero();}
            catch(Exception ex){failures.Add(new(job.JobId,"stop",WfpNative.Describe(ex)));}
        }
        var snapshots=new List<JobSnapshot>();
        foreach(var job in jobs)
        {
            AssertHeld();
            try
            {
                var snapshot=job.Observe();snapshots.Add(snapshot);
                if(!snapshot.ObservedZero)failures.Add(new(job.JobId,"final-observation",WfpNative.Describe(
                    new InvalidOperationException("A registered job is nonempty during final observation"))));
            }
            catch(Exception ex){failures.Add(new(job.JobId,"final-observation",WfpNative.Describe(ex)));}
        }
        AssertHeld();
        var result=new RegisteredJobObservation(intents.Count,absent.ToArray(),snapshots.ToArray(),failures.ToArray(),"REGISTERED_JOB_MEMBERS_ONLY",false,false,completed.ToArray(),retired.ToArray());
        state.WriteNew("job-set-observed-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=4,InstallationId=state.InstallationId,Status=result.AllRegisteredMembersZeroObserved?"REGISTERED_JOB_MEMBERS_ZERO_OBSERVED":
                result.AllRegisteredJobsResolved?"REGISTERED_JOBS_RESOLVED_WITH_NEVER_ADMITTED_RETIREMENT":"REGISTERED_JOB_STOP_NOT_CONFIRMED",
            Observation=result,AtUtc=DateTime.UtcNow.ToString("o")
        }));
        return result;
    }
    internal void AssertClosedAdmissionsForNetworkMaintenance()
    {
        AssertHeld();
        // Durable CLOSED one-shot admission cannot admit another process. A
        // destroyed private namespace must not be recreated just to query zero.
        // Missing names or an empty Job WITHOUT that proof are insufficient.
        foreach(var intent in intents)
        {
            if(!SessionZeroCreatorRecovery.IsAdmissionResolved(state,intent))throw WfpNative.Contract("NetworkMigrationRequiresClosedAdmission");
        }
        AssertHeld();
    }
    public void Dispose(){if(disposed)return;disposed=true;for(var i=jobs.Count-1;i>=0;i--)jobs[i].Dispose();}
}
