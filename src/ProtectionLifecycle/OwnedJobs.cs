using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed record OwnedJobIntent(int SchemaVersion,string InstallationId,string JobId,string Release,string ManifestSHA256,string Binding,string Scope)
{
    internal static string Leaf(string id)=>"job-intent-"+Identifiers.Hex32(id)+".json";
    internal string Alias=>"CPCJob."+Identifiers.Hex32(InstallationId)+"."+Identifiers.Hex32(JobId);
    internal string Name=>Alias+"\\Session";
    internal CreationTag Tag=>CreationTag.For(CreationRole.OwnedJob,JobId);
    internal static OwnedJobIntent Read(ProtectedState state,string id)
    {
        state.AssertHeld();id=Identifiers.Hex32(id);using var doc=JsonDocument.Parse(state.Read(Leaf(id),8192).Bytes,new JsonDocumentOptions{MaxDepth=4});var r=doc.RootElement;
        StrictJson.Fields(r,"SchemaVersion","InstallationId","JobId","Release","ManifestSHA256","Binding","Scope");
        if(r.GetProperty("SchemaVersion").GetInt32()!=2 || StrictJson.Text(r,"InstallationId")!=state.InstallationId || StrictJson.Text(r,"JobId")!=id ||
            StrictJson.Text(r,"Binding")!="ATOMIC_JOB_LIST_REQUIRED" || StrictJson.Text(r,"Scope")!="JOB_MEMBERS_ONLY")throw new InvalidDataException("Foreign job intent or unsupported binding");
        return new(2,state.InstallationId,id,Identifiers.Hex32(StrictJson.Text(r,"Release")),Identifiers.Hash(StrictJson.Text(r,"ManifestSHA256")),"ATOMIC_JOB_LIST_REQUIRED","JOB_MEMBERS_ONLY");
    }
    internal static IReadOnlyList<OwnedJobIntent> ReadAll(ProtectedState state)
    {
        var leaves=state.ListLeaves("job-intent-");if(leaves.Length>1024)throw new InvalidDataException("Job inventory capacity exceeded; no subset adopted");
        var result=new List<OwnedJobIntent>();
        foreach(var leaf in leaves)
        {
            if(leaf.Length!=48)throw new InvalidDataException("Unexpected job intent name");
            var id=Identifiers.Hex32(leaf.Substring(11,32));if(leaf!=Leaf(id))throw new InvalidDataException("Job intent name differs");
            result.Add(Read(state,id));
        }
        return result.AsReadOnly();
    }
}

internal sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeJobHandle():base(true){}
    protected override bool ReleaseHandle()=>CloseHandle(handle);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
}

internal sealed record JobSnapshot(string JobId,uint LimitFlags,uint ActiveBefore,uint ActiveAfter,uint[] ProcessIds,string AtUtc)
{
    internal bool ExpectedLimits=>LimitFlags==OwnedKernelJob.RequiredLimits;
    internal bool ObservedZero=>ActiveBefore==0 && ActiveAfter==0 && ProcessIds.Length==0;
}

// Concrete kernel owner; no CreateProcess/Assign/Resume, PID-based kill, helper
// executable, or caller-supplied object name. Launch/admission/WFP composition
// remains mandatory and is not implemented by this component.
internal sealed class OwnedKernelJob : IDisposable
{
    internal const uint RequiredLimits=0x2000; // KILL_ON_JOB_CLOSE; no breakaway flags.
    private readonly ProtectedState state;
    private readonly OwnedJobIntent intent;
    private readonly SafeJobHandle handle;
    private readonly PrivateJobNamespace jobNamespace;
    private bool disposed;
    internal string JobId=>intent.JobId;
    private OwnedKernelJob(ProtectedState state,OwnedJobIntent intent,SafeJobHandle handle,PrivateJobNamespace jobNamespace)
    {this.state=state;this.intent=intent;this.handle=handle;this.jobNamespace=jobNamespace;}

    internal static OwnedKernelJob CreateEmpty(ProtectedState state,VerifiedVersion version)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);LifecycleRecovery.AssertNoPending(state);
        var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
        if(current.Release!=version.Package.Release || current.ManifestSHA256!=version.Package.ManifestHash)throw new InvalidDataException("Job version differs from the verified current version");
        if(OwnedJobIntent.ReadAll(state).Count>=1024)throw new InvalidDataException("Job inventory full");
        var intent=new OwnedJobIntent(2,state.InstallationId,Guid.NewGuid().ToString("N"),version.Package.Release,version.Package.ManifestHash,"ATOMIC_JOB_LIST_REQUIRED","JOB_MEMBERS_ONLY");
        state.WriteNew(OwnedJobIntent.Leaf(intent.JobId),JsonSerializer.SerializeToUtf8Bytes(intent)); // Before kernel creation.
        OwnedKernelJob? owner=null;
        try
        {
            owner=CreateNative(state,intent);
            owner.AssertHeld();var limits=new ExtendedLimits();limits.Basic.LimitFlags=RequiredLimits;
            if(!SetInformationJobObject(owner.handle,9,ref limits,(uint)Marshal.SizeOf<ExtendedLimits>()))throw Error("SetOwnedJobLimits");
            var observed=owner.Observe();
            if(!observed.ExpectedLimits || !observed.ObservedZero)throw new InvalidDataException("New job is not empty with the required limits");
            owner.Record("CREATED_EMPTY_OBSERVED",observed);return owner;
        }
        catch(Exception ex)
        {
            try{state.WriteNew("job-create-failure-"+intent.JobId+"-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,InstallationId=state.InstallationId,intent.JobId,Status="JOB_CREATION_NOT_QUALIFIED",FailureType=ex.GetType().Name,
                FailureCode=ex is Win32Exception native?native.NativeErrorCode:ex.HResult,AtUtc=DateTime.UtcNow.ToString("o")
            }));}catch(Exception log){throw new AggregateException("Job creation and failure recording both failed",ex,log);}finally{owner?.Dispose();}throw;
        } // No process launch is exposed before the successful return.
    }
    private static OwnedKernelJob CreateNative(ProtectedState state,OwnedJobIntent intent)
    {
        using var descriptor=new KernelJobSeal.Descriptor(intent.Tag);var attributes=descriptor.Attributes;
        PrivateJobNamespace? jobNamespace=PrivateJobNamespace.CreateNew(state,intent);SafeJobHandle? created=null;
        try
        {
            created=CreateJobObject(ref attributes,intent.Name);var error=Marshal.GetLastWin32Error();
            if(created.IsInvalid)throw new Win32Exception(error,"CreateOwnedJob");
            if(error==183)
            {
                // No global-name fallback or preexisting namespace adoption.
                var collision=new Win32Exception(error,"Existing named job refused");
                try{state.WriteNew("job-collision-"+intent.JobId+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,InstallationId=state.InstallationId,intent.JobId,Status="EXISTING_OBJECT_REFUSED"}));}
                catch(Exception log){throw new AggregateException("Job collision and refusal recording both failed",collision,log);}throw collision;
            }
            var owner=new OwnedKernelJob(state,intent,created,jobNamespace);created=null;jobNamespace=null;return owner;
        }
        finally{try{created?.Dispose();}finally{jobNamespace?.Dispose();}}
    }

    internal static OwnedKernelJob? OpenExisting(ProtectedState state,OwnedJobIntent supplied)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();var intent=OwnedJobIntent.Read(state,supplied.JobId);
        if(intent!=supplied)throw new InvalidDataException("Job intent changed or belongs to another installation");
        // Recovery gets query/terminate/READ_CONTROL, never assignment or setting.
        PrivateJobNamespace? jobNamespace=PrivateJobNamespace.OpenExisting(state,intent);SafeJobHandle? opened=null;
        try
        {
            opened=OpenJobObject(0x0002000c,false,intent.Name);var error=Marshal.GetLastWin32Error();
            if(opened.IsInvalid)
            {
                if(error==2)return null; // Only this exact open inside a held namespace.
                throw new Win32Exception(error,"OpenOwnedJob");
            }
            if(state.ReadOptional("job-collision-"+intent.JobId+".json") is not null)throw new InvalidDataException("A rejected creation cannot authorize adoption");
            KernelJobSeal.AssertOwned(opened,intent.Tag);
            var owner=new OwnedKernelJob(state,intent,opened,jobNamespace);opened=null;jobNamespace=null;return owner;
        }
        finally{try{opened?.Dispose();}finally{jobNamespace?.Dispose();}}
    }
    private void AssertHeld()
    {
        if(disposed || handle.IsClosed || handle.IsInvalid)throw new ObjectDisposedException(nameof(OwnedKernelJob));
        state.AssertHeld();jobNamespace.AssertHeld();KernelJobSeal.AssertOwned(handle,intent.Tag);
    }
    internal JobSnapshot Observe()
    {
        AssertHeld();
        if(!QueryLimits(handle,9,out var limits,(uint)Marshal.SizeOf<ExtendedLimits>(),out _))throw Error("QueryOwnedJobLimits");
        var before=Active();var ids=ProcessIds();var after=Active();
        return new(intent.JobId,limits.Basic.LimitFlags,before,after,ids,DateTime.UtcNow.ToString("o"));
    }
    private uint Active()
    {
        if(!QueryAccounting(handle,1,out var accounting,(uint)Marshal.SizeOf<BasicAccounting>(),out _))throw Error("QueryOwnedJobAccounting");
        return accounting.ActiveProcesses;
    }
    private uint[] ProcessIds()
    {
        for(var capacity=32;capacity<=4096;capacity*=2)
        {
            var length=checked(8+IntPtr.Size*capacity);var buffer=Marshal.AllocHGlobal(length);
            try
            {
                if(!QueryBuffer(handle,3,buffer,(uint)length,out _))
                {var error=Marshal.GetLastWin32Error();if(error==234 && capacity<4096)continue;throw new Win32Exception(error,"QueryOwnedJobMembers");}
                var assigned=Marshal.ReadInt32(buffer,0);var count=Marshal.ReadInt32(buffer,4);
                if(assigned<0 || count<0 || count>capacity || count>assigned)throw new InvalidDataException("Invalid job member buffer");
                if(count<assigned){if(capacity<4096)continue;throw new InvalidDataException("Job member capacity exceeded; no truncated zero observation");}
                var result=new uint[count];
                for(var i=0;i<count;i++)result[i]=checked((uint)Marshal.ReadIntPtr(buffer,8+i*IntPtr.Size).ToInt64());
                if(result.Any(id=>id==0) || result.Distinct().Count()!=result.Length)throw new InvalidDataException("Invalid/duplicate job member identifier");
                return result;
            }
            finally{Marshal.FreeHGlobal(buffer);}
        }
        throw new InvalidDataException("Job member capacity exceeded");
    }
    internal JobSnapshot StopAndVerifyZero()
    {
        AssertHeld();var attempt=Guid.NewGuid().ToString("N");
        try
        {
            var before=Observe();Record("BEFORE_TERMINATE",before,attempt);
            AssertHeld();if(!TerminateJobObject(handle,125))throw Error("TerminateExactOwnedJob");
            var clock=Stopwatch.StartNew();JobSnapshot latest;
            do
            {
                latest=Observe();
                if(latest.ObservedZero){Record("JOB_MEMBERS_ZERO_OBSERVED",latest,attempt);return latest;}
                Thread.Sleep(20);
            }while(clock.ElapsedMilliseconds<5000);
            Record("JOB_MEMBERS_ZERO_TIMEOUT",latest,attempt);throw new TimeoutException("Owned job members were not observed zero within the bounded wait");
        }
        catch(Exception ex)
        {
            try{state.WriteNew("job-failure-"+intent.JobId+"-"+attempt+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,InstallationId=state.InstallationId,intent.JobId,
                Status="STOP_NOT_CONFIRMED",FailureType=ex.GetType().Name,FailureCode=ex is Win32Exception native?native.NativeErrorCode:ex.HResult,AtUtc=DateTime.UtcNow.ToString("o")}));}
            catch(Exception log){throw new AggregateException("Job stop and failure recording both failed",ex,log);}throw;
        }
    }
    private void Record(string status,JobSnapshot snapshot,string? attempt=null)
    {state.WriteNew("job-observed-"+intent.JobId+"-"+(attempt??Guid.NewGuid().ToString("N"))+"-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {
        SchemaVersion=1,InstallationId=state.InstallationId,intent.JobId,Status=status,Snapshot=snapshot,Scope="JOB_MEMBERS_ONLY",AdmissionOrNetworkQualified=false
    }));}
    public void Dispose(){if(disposed)return;disposed=true;try{handle.Dispose();}finally{jobNamespace.Dispose();}} // Closing is not a zero-process observation.
    private static Win32Exception Error(string stage){var result=new Win32Exception(Marshal.GetLastWin32Error());result.Data["Stage"]=stage;return result;}
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits {public long ProcessTime,JobTime;public uint LimitFlags;public UIntPtr MinWorkingSet,MaxWorkingSet;public uint ActiveProcessLimit;public UIntPtr Affinity;public uint PriorityClass,SchedulingClass;}
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters {public ulong ReadOps,WriteOps,OtherOps,ReadBytes,WriteBytes,OtherBytes;}
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits {public BasicLimits Basic;public IoCounters Io;public UIntPtr ProcessMemory,JobMemory,PeakProcessMemory,PeakJobMemory;}
    [StructLayout(LayoutKind.Sequential)] private struct BasicAccounting {public long User,Kernel,PeriodUser,PeriodKernel;public uint PageFaults,TotalProcesses,ActiveProcesses,TerminatedProcesses;}
    [DllImport("kernel32.dll",EntryPoint="CreateJobObjectW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeJobHandle CreateJobObject(ref KernelJobSeal.SecurityAttributes attributes,string name);
    [DllImport("kernel32.dll",EntryPoint="OpenJobObjectW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeJobHandle OpenJobObject(uint access,[MarshalAs(UnmanagedType.Bool)] bool inherit,string name);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetInformationJobObject(SafeJobHandle handle,int info,ref ExtendedLimits limits,uint size);
    [DllImport("kernel32.dll",EntryPoint="QueryInformationJobObject",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryLimits(SafeJobHandle handle,int info,out ExtendedLimits limits,uint size,out uint returned);
    [DllImport("kernel32.dll",EntryPoint="QueryInformationJobObject",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryAccounting(SafeJobHandle handle,int info,out BasicAccounting accounting,uint size,out uint returned);
    [DllImport("kernel32.dll",EntryPoint="QueryInformationJobObject",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryBuffer(SafeJobHandle handle,int info,IntPtr buffer,uint size,out uint returned);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool TerminateJobObject(SafeJobHandle handle,uint exitCode);
}

internal sealed record RegisteredJobFailure(string JobId,string Stage,WfpErrorEvidence[] Errors);
internal sealed record RegisteredJobObservation(int ExpectedJobs,string[] NamesAbsentAtOpen,JobSnapshot[] PresentJobs,RegisteredJobFailure[] Failures,
    string Scope,bool CompleteProcessOwnershipQualified,bool AdmissionOrNetworkQualified)
{
    // A later zero observation never repairs a failed stop, an unavailable job
    // or a missing observation. All recorded intent entries remain in scope.
    internal bool AllRegisteredMembersZeroObserved=>NamesAbsentAtOpen.Length==0 && Failures.Length==0 &&
        PresentJobs.Length==ExpectedJobs && PresentJobs.All(s=>s.ObservedZero);
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
    private bool disposed;
    private RegisteredJobSet(ProtectedState state,IReadOnlyList<OwnedJobIntent> intents){this.state=state;this.intents=intents;}
    internal static RegisteredJobSet OpenForMaintenance(ProtectedState state)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();var set=new RegisteredJobSet(state,OwnedJobIntent.ReadAll(state));
        try
        {
            foreach(var intent in set.intents)
            {
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
        var result=new RegisteredJobObservation(intents.Count,absent.ToArray(),snapshots.ToArray(),failures.ToArray(),"REGISTERED_JOB_MEMBERS_ONLY",false,false);
        state.WriteNew("job-set-observed-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=2,InstallationId=state.InstallationId,Status=result.AllRegisteredMembersZeroObserved?"REGISTERED_JOB_MEMBERS_ZERO_OBSERVED":"REGISTERED_JOB_STOP_NOT_CONFIRMED",
            Observation=result,AtUtc=DateTime.UtcNow.ToString("o")
        }));
        return result;
    }
    public void Dispose(){if(disposed)return;disposed=true;for(var i=jobs.Count-1;i>=0;i--)jobs[i].Dispose();}
}
