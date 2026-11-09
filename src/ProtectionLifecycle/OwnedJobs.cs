using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed record OwnedJobIntent(int SchemaVersion,string InstallationId,string JobId,string Release,string ManifestSHA256,string Binding,string Scope,
    [property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)] string? CreatorServiceSid=null)
{
    private const string AtomicBinding="ATOMIC_JOB_LIST_REQUIRED",PrivateScope="JOB_MEMBERS_ONLY",CreatorScope="SESSION_ZERO_CREATOR_JOB_MEMBERS_ONLY";
    internal static string Leaf(string id)=>"job-intent-"+Identifiers.Hex32(id)+".json";
    internal string Alias=>"CPCJob."+Identifiers.Hex32(InstallationId)+"."+Identifiers.Hex32(JobId);
    internal string Name=>CreatorServiceSid is null?Alias+"\\Session":CreatorJobName(InstallationId,JobId);
    internal static string CreatorJobName(string installationId,string jobId)=>@"Global\CPCSessionJob."+Identifiers.Hex32(installationId)+"."+Identifiers.Hex32(jobId);
    internal CreationTag Tag=>CreationTag.For(CreationRole.OwnedJob,JobId);
    internal static OwnedJobIntent ForNewJob(string installationId,string release,string manifest,string? creatorServiceSid)
    {
        if(creatorServiceSid is not null)AssertCreatorSid(creatorServiceSid);
        return new(creatorServiceSid is null?2:3,installationId,Guid.NewGuid().ToString("N"),release,manifest,AtomicBinding,
            creatorServiceSid is null?PrivateScope:CreatorScope,creatorServiceSid);
    }
    internal static OwnedJobIntent Read(ProtectedState state,string id)
    {
        state.AssertHeld();id=Identifiers.Hex32(id);using var doc=JsonDocument.Parse(state.Read(Leaf(id),8192).Bytes,new JsonDocumentOptions{MaxDepth=4});
        return Parse(doc.RootElement,state.InstallationId,id);
    }
    internal static OwnedJobIntent Parse(JsonElement r,string installationId,string id)
    {
        var schema=r.GetProperty("SchemaVersion").GetInt32();
        string[] fields=["SchemaVersion","InstallationId","JobId","Release","ManifestSHA256","Binding","Scope"];
        if(schema is not (2 or 3))throw new InvalidDataException("Unsupported job intent schema");
        StrictJson.Fields(r,schema==3?[..fields,"CreatorServiceSid"]:fields);
        var scope=schema==3?CreatorScope:PrivateScope;
        if(StrictJson.Text(r,"InstallationId")!=installationId || StrictJson.Text(r,"JobId")!=id ||
            StrictJson.Text(r,"Binding")!=AtomicBinding || StrictJson.Text(r,"Scope")!=scope)throw new InvalidDataException("Foreign job intent or unsupported binding");
        var creator=schema==3?StrictJson.Text(r,"CreatorServiceSid"):null;
        if(creator is not null)AssertCreatorSid(creator);
        return new(schema,installationId,id,Identifiers.Hex32(StrictJson.Text(r,"Release")),Identifiers.Hash(StrictJson.Text(r,"ManifestSHA256")),AtomicBinding,scope,creator);
    }
    private static void AssertCreatorSid(string sid)
    {
        // Service-specific SID only. Reject the shared LocalService and the
        // all-services group, as well as our own synthetic creation tag space.
        var segments=sid.Split('-');
        if(!sid.StartsWith("S-1-5-80-",StringComparison.Ordinal) || segments.Length!=9 ||
            !segments.Skip(4).All(s=>uint.TryParse(s,System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out var value) &&
                s==value.ToString(System.Globalization.CultureInfo.InvariantCulture)) || CreationTag.TryParse(sid) is not null)
            throw new InvalidDataException("Exact creator service SID required");
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
    internal SafeJobHandle DuplicateAssignment()
    {
        // The creation attribute needs assignment. Query, terminate and
        // policy changes stay on the original Job owner's handle.
        var current=new IntPtr(-1);
        if(DuplicateHandle(current,this,current,out var assignment,0x0001,false,0))return assignment;
        var error=new Win32Exception(Marshal.GetLastWin32Error());
        assignment?.Dispose();error.Data["Stage"]="DuplicateJobAssignmentOnly";throw error;
    }
    protected override bool ReleaseHandle()=>CloseHandle(handle);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess,SafeJobHandle source,IntPtr targetProcess,out SafeJobHandle target,
        uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint options);
}

internal sealed record JobSnapshot(string JobId,uint LimitFlags,uint ActiveBefore,uint ActiveAfter,uint[] ProcessIds,string AtUtc)
{
    internal bool ExpectedLimits=>LimitFlags==OwnedKernelJob.RequiredLimits;
    internal bool ObservedZero=>ActiveBefore==0 && ActiveAfter==0 && ProcessIds.Length==0;
}

// Concrete kernel owner. Atomic admission reserves one creation using JOB_LIST;
// there is no post-creation Assign or PID-based termination fallback.
internal sealed class OwnedKernelJob : IDisposable
{
    internal const uint RequiredLimits=0x2000; // KILL_ON_JOB_CLOSE; no breakaway flags.
    private readonly ProtectedState state;
    private readonly OwnedJobIntent intent;
    private readonly SafeJobHandle handle;
    private readonly PrivateJobNamespace? jobNamespace;
    private bool disposed;
    private bool admissionClaimed,admissionClosed;
    private bool creatorGrantAttempted,creatorReleaseConfirmed;
    internal string JobId=>intent.JobId;
    internal string SessionZeroCreatorSid=>intent.CreatorServiceSid??throw WfpNative.Contract("SessionZeroCreatorJobRequired");
    internal bool AtomicAdmissionReserved=>admissionClaimed;
    internal SafeJobHandle ToolCreationHandle(ProtectedSession.ResourceQualification permit)
    {
        AssertHeld();permit.AssertCurrent();
        if(!admissionClaimed || admissionClosed || permit.SessionId.Length!=32)throw WfpNative.Contract("OwnedToolJobAdmissionClosed");
        permit.AssertExactToolJob(this);return handle;
    }
    internal SafeJobHandle ReserveAtomicAdmission(VerifiedVersion version)
    {
        if(intent.CreatorServiceSid is not null)throw WfpNative.Contract("SessionZeroJobRequiresBoundCreator");
        ReserveAdmission(version);return handle;
    }
    internal void ReserveSessionZeroAdmission(VerifiedVersion version,SecurityIdentifier exactCreatorSid)
    {
        if(intent.CreatorServiceSid is null || intent.CreatorServiceSid!=exactCreatorSid.Value)throw WfpNative.Contract("SessionZeroJobCreatorMismatch");
        AssertHeld();AssertCreatorProof(state,intent);
        if(Accounting().TotalProcesses!=0)throw WfpNative.Contract("SessionZeroJobAlreadyHadAMember");
        AssertExclusiveCreatorJob();
        ReserveAdmission(version);
        creatorGrantAttempted=true;
        if(KernelJobSeal.SetCreatorAccess(handle,intent,grant:true))throw WfpNative.Contract("SessionZeroCreatorGrantAlreadyPresent");
    }
    // Call only after the authenticated creator has returned from the atomic
    // creation syscall and released its Job handle. ACL changes alone do not
    // revoke rights already present on another open handle.
    internal void ConfirmSessionZeroCreatorReleased()
    {
        AssertHeld();
        if(!admissionClaimed || admissionClosed || !creatorGrantAttempted || creatorReleaseConfirmed)
            throw WfpNative.Contract("SessionZeroCreatorReleaseOutOfOrder");
        if(!KernelJobSeal.SetCreatorAccess(handle,intent,grant:false))throw WfpNative.Contract("SessionZeroCreatorGrantMissingBeforeRelease");
        AssertExclusiveCreatorJob();
        creatorReleaseConfirmed=true;
    }
    internal void AssertCreatorSealedBeforeResume()
    {
        if(intent.CreatorServiceSid is null)return;
        if(!creatorReleaseConfirmed || admissionClosed)throw WfpNative.Contract("SessionZeroCreatorReleaseUnconfirmed");
        AssertExclusiveCreatorJob();
    }
    internal void AssertCreatorProfileCleanupAllowed(ProtectedState exactState)
    {
        if(!ReferenceEquals(state,exactState) || intent.CreatorServiceSid is null || !creatorReleaseConfirmed || !admissionClosed ||
            AtomicJobCompletion.ReadClosed(state,intent) is null)throw WfpNative.Contract("CreatorProfileCleanupNeedsClosedAdmission");
        AssertExclusiveCreatorJob();
        if(!Observe().ObservedZero)throw WfpNative.Contract("CreatorProfileCleanupNeedsOriginalJobZero");
    }
    private void AssertExclusiveCreatorJob()
    {
        if(KernelJobSeal.AssertJobDescriptor(KernelJobSeal.ReadJobDescriptor(handle,true),intent))
            throw WfpNative.Contract("SessionZeroCreatorAssignmentStillGranted");
        AssertSoleJobHandle(handle);
    }
    internal static void AssertSoleJobHandle(SafeJobHandle handle)
    {
        const uint size=14*sizeof(uint); // PUBLIC_OBJECT_BASIC_INFORMATION
        var basic=new uint[14];
        var status=NtQueryObject(handle,0,basic,size,out var returned);
        if(status!=0)throw new Win32Exception(unchecked((int)RtlNtStatusToDosError(status)),"ReadCreatorJobHandleCount");
        if(returned!=size || basic[2]!=1)throw WfpNative.Contract("SessionZeroCreatorJobNotExclusivelyHeld");
    }
    private void ReserveAdmission(VerifiedVersion version)
    {
        AssertHeld();version.AssertHeld(state);
        if(admissionClaimed || admissionClosed || intent.Release!=version.Package.Release || intent.ManifestSHA256!=version.Package.ManifestHash)
            throw new InvalidOperationException("One-shot job admission is unavailable");
        var observed=Observe();if(!observed.ExpectedLimits || !observed.ObservedZero)throw WfpNative.Contract("AtomicAdmissionRequiresEmptySealedJob");
        state.WriteNew("job-admission-"+intent.JobId+".json",JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,state.InstallationId,intent.JobId,intent.Release,intent.ManifestSHA256,Binding="ATOMIC_JOB_LIST_AT_CREATION",Reusable=false
        }));
        admissionClaimed=true;
    }
    internal JobSnapshot CloseAtomicAdmissionAndStop()
    {
        AssertHeld();if(!admissionClaimed)throw new InvalidOperationException("No atomic admission was reserved");
        admissionClosed=true;
        Exception? revokeFailure=null;
        if(intent.CreatorServiceSid is not null)
            try{_=KernelJobSeal.SetCreatorAccess(handle,intent,grant:false);}catch(Exception error){revokeFailure=error;}
        JobSnapshot snapshot;
        try{snapshot=StopAndVerifyZero();}
        catch(Exception error) when(revokeFailure is not null){throw new AggregateException("Creator grant removal and Job stop both failed",revokeFailure,error);}
        if(revokeFailure is not null)System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(revokeFailure).Throw();
        if(intent.CreatorServiceSid is not null)
        {
            AssertExclusiveCreatorJob();
            if(creatorGrantAttempted && !creatorReleaseConfirmed)throw WfpNative.Contract("SessionZeroCreatorReleaseUnconfirmedAtStop");
        }
        var admission=state.Read("job-admission-"+intent.JobId+".json",8192);
        state.WriteNew("job-completed-"+intent.JobId+".json",JsonSerializer.SerializeToUtf8Bytes(new AtomicJobCompletion(1,state.InstallationId,intent.JobId,
            intent.Release,intent.ManifestSHA256,admission.SHA256,"ADMISSION_CLOSED_MEMBERS_ZERO_OBSERVED",snapshot,intent.CreatorServiceSid is null?null:true)));
        return snapshot;
    }
    private OwnedKernelJob(ProtectedState state,OwnedJobIntent intent,SafeJobHandle handle,PrivateJobNamespace? jobNamespace)
    {this.state=state;this.intent=intent;this.handle=handle;this.jobNamespace=jobNamespace;}

    internal static OwnedKernelJob CreateEmpty(ProtectedState state,VerifiedVersion version)
        =>CreateEmpty(state,version,null);
    // Only the fixed SCM owner may select this scope after verifying its
    // exact service SID. This does not start or authenticate a creator.
    internal static OwnedKernelJob CreateForSessionZero(ProtectedState state,VerifiedVersion version,SessionZeroCreatorRegistration creator)
        =>CreateEmpty(state,version,creator);
    private static OwnedKernelJob CreateEmpty(ProtectedState state,VerifiedVersion version,SessionZeroCreatorRegistration? creator)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);LifecycleRecovery.AssertNoPending(state,preparingCreator:creator);
        var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
        if(current.Release!=version.Package.Release || current.ManifestSHA256!=version.Package.ManifestHash)throw new InvalidDataException("Job version differs from the verified current version");
        if(OwnedJobIntent.ReadAll(state).Count>=1024)throw new InvalidDataException("Job inventory full");
        var intent=OwnedJobIntent.ForNewJob(state.InstallationId,version.Package.Release,version.Package.ManifestHash,creator?.Sid.Value);
        if(creator is not null)
        {
            _=creator.AssertReadyForJob(state,version);
            intent=intent with {JobId=creator.JobId};
        }
        state.WriteNew(OwnedJobIntent.Leaf(intent.JobId),JsonSerializer.SerializeToUtf8Bytes(intent)); // Before kernel creation.
        OwnedKernelJob? owner=null;
        try
        {
            owner=CreateNative(state,intent);
            owner.AssertHeld();var limits=new ExtendedLimits();limits.Basic.LimitFlags=RequiredLimits;
            if(!SetInformationJobObject(owner.handle,9,ref limits,(uint)Marshal.SizeOf<ExtendedLimits>()))throw Error("SetOwnedJobLimits");
            var observed=owner.Observe();
            if(!observed.ExpectedLimits || !observed.ObservedZero)throw new InvalidDataException("New job is not empty with the required limits");
            if(intent.CreatorServiceSid is not null)
                state.WriteNew(CreatorProofLeaf(intent),JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,IntentSHA256=IntentHash(state,intent)}));
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
        using var descriptor=new KernelJobSeal.Descriptor(intent);var attributes=descriptor.Attributes;
        PrivateJobNamespace? jobNamespace=intent.CreatorServiceSid is null?PrivateJobNamespace.CreateNew(state,intent):null;SafeJobHandle? created=null;
        try
        {
            if(intent.CreatorServiceSid is not null)created=CreateFreshSessionZeroJob(intent,attributes.Descriptor);
            else
            {
                created=CreateJobObject(ref attributes,intent.Name);var error=Marshal.GetLastWin32Error();
                if(created.IsInvalid)throw new Win32Exception(error,"CreateOwnedJob");
                if(error==183)
                {
                    // The private namespace is held and has no public fallback.
                    var collision=new Win32Exception(error,"Existing named job refused");
                    try{state.WriteNew("job-collision-"+intent.JobId+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,InstallationId=state.InstallationId,intent.JobId,Status="EXISTING_OBJECT_REFUSED"}));}
                    catch(Exception log){throw new AggregateException("Job collision and refusal recording both failed",collision,log);}throw collision;
                }
            }
            var owner=new OwnedKernelJob(state,intent,created,jobNamespace);created=null;jobNamespace=null;return owner;
        }
        finally{try{created?.Dispose();}finally{jobNamespace?.Dispose();}}
    }
    // Global names can be preempted. Creating without OBJ_OPENIF never
    // acquires an existing handle whose eventual close might kill its members.
    internal static SafeJobHandle CreateFreshSessionZeroJob(OwnedJobIntent intent,IntPtr descriptor)
    {
        if(!Environment.Is64BitProcess || Marshal.SizeOf<NativeUnicodeString>()!=16 || Marshal.SizeOf<NativeObjectAttributes>()!=48 ||
            intent.CreatorServiceSid is null || descriptor==IntPtr.Zero)
            throw new InvalidOperationException("Named creator Job requires the x64 layout and a sealed Session 0 intent");
        var name=@"\BaseNamedObjects\"+intent.Name["Global\\".Length..];
        var nameBuffer=Marshal.StringToHGlobalUni(name);
        var nativeName=IntPtr.Zero;
        try
        {
            var length=checked((ushort)(name.Length*sizeof(char)));
            nativeName=Marshal.AllocHGlobal(Marshal.SizeOf<NativeUnicodeString>());
            Marshal.StructureToPtr(new NativeUnicodeString{Length=length,MaximumLength=checked((ushort)(length+sizeof(char))),Buffer=nameBuffer},nativeName,false);
            var attributes=new NativeObjectAttributes{Length=Marshal.SizeOf<NativeObjectAttributes>(),Name=nativeName,SecurityDescriptor=descriptor};
            var status=NtCreateJobObject(out var created,KernelJobSeal.CreatorJobOwnerRights,ref attributes);
            if(status==0 && created is {IsInvalid:false})return created;
            created?.Dispose();
            if(status==0)throw WfpNative.Contract("FreshSessionZeroJobHandleMissing");
            var failure=new Win32Exception(unchecked((int)RtlNtStatusToDosError(status)),"CreateFreshSessionZeroJob");
            failure.Data["NTSTATUS"]=status;
            throw failure;
        }
        finally{Marshal.FreeHGlobal(nativeName);Marshal.FreeHGlobal(nameBuffer);}
    }

    internal static OwnedKernelJob? OpenExisting(ProtectedState state,OwnedJobIntent supplied)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();var intent=OwnedJobIntent.Read(state,supplied.JobId);
        if(intent!=supplied)throw new InvalidDataException("Job intent changed or belongs to another installation");
        // A durable creation record cannot authenticate the current global
        // object. Closed admissions are handled by the ledger before this call.
        if(intent.CreatorServiceSid is not null)throw WfpNative.Contract("SessionZeroJobRecoveryRequiresOriginalOwnerProof");
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
            KernelJobSeal.AssertOwned(opened,intent);
            var owner=new OwnedKernelJob(state,intent,opened,jobNamespace);opened=null;jobNamespace=null;return owner;
        }
        finally{try{opened?.Dispose();}finally{jobNamespace?.Dispose();}}
    }
    private static string CreatorProofLeaf(OwnedJobIntent intent)=>"job-creator-confirmed-"+intent.JobId+".json";
    internal static void AssertCreatorNameAbsent(OwnedJobIntent intent)
    {
        if(intent.CreatorServiceSid is null)throw WfpNative.Contract("CreatorJobAbsenceRequiresCreatorIntent");
        using var observed=OpenJobObject(4,false,intent.Name); // Query only. Never adopt an object found at this name.
        var error=Marshal.GetLastWin32Error();
        if(!observed.IsInvalid || error!=2)throw WfpNative.Contract("LegacyCreatorJobNameAbsenceUnconfirmed");
    }
    private static string IntentHash(ProtectedState state,OwnedJobIntent intent)=>state.Read(OwnedJobIntent.Leaf(intent.JobId),8192).SHA256;
    private static void AssertCreatorProof(ProtectedState state,OwnedJobIntent intent)
    {
        using var doc=JsonDocument.Parse(state.Read(CreatorProofLeaf(intent),4096).Bytes,new JsonDocumentOptions{MaxDepth=2});
        ValidateCreatorProof(doc.RootElement,IntentHash(state,intent));
    }
    internal static void ValidateCreatorProof(JsonElement proof,string intentHash)
    {
        StrictJson.Fields(proof,"SchemaVersion","IntentSHA256");
        if(proof.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(proof,"IntentSHA256")!=intentHash)
            throw new InvalidDataException("Session zero job creation unconfirmed");
    }
    private void AssertHeld()
    {
        if(disposed || handle.IsClosed || handle.IsInvalid)throw new ObjectDisposedException(nameof(OwnedKernelJob));
        state.AssertHeld();jobNamespace?.AssertHeld();KernelJobSeal.AssertOwned(handle,intent);
    }
    internal JobSnapshot Observe()
    {
        AssertHeld();
        if(!QueryLimits(handle,9,out var limits,(uint)Marshal.SizeOf<ExtendedLimits>(),out _))throw Error("QueryOwnedJobLimits");
        var before=Active();var ids=ProcessIds();var after=Active();
        return new(intent.JobId,limits.Basic.LimitFlags,before,after,ids,DateTime.UtcNow.ToString("o"));
    }
    internal bool ContainsProcess(SafeProcessHandle process)
    {
        AssertHeld();if(!IsProcessInJob(process,handle,out var belongs))throw Error("InspectExactJobMembership");return belongs;
    }
    internal void AssertSingleProcessEverAdmitted()
    {
        AssertHeld();
        if(Accounting().TotalProcesses!=1)throw WfpNative.Contract("OfflineConsoleJobProcessCountDiffers");
    }
    private uint Active()=>Accounting().ActiveProcesses;
    private BasicAccounting Accounting()
    {
        if(!QueryAccounting(handle,1,out var accounting,(uint)Marshal.SizeOf<BasicAccounting>(),out _))throw Error("QueryOwnedJobAccounting");
        return accounting;
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
    public void Dispose(){if(disposed)return;disposed=true;try{handle.Dispose();}finally{jobNamespace?.Dispose();}} // Closing is not a zero-process observation.
    private static Win32Exception Error(string stage){var result=new Win32Exception(Marshal.GetLastWin32Error());result.Data["Stage"]=stage;return result;}
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits {public long ProcessTime,JobTime;public uint LimitFlags;public UIntPtr MinWorkingSet,MaxWorkingSet;public uint ActiveProcessLimit;public UIntPtr Affinity;public uint PriorityClass,SchedulingClass;}
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters {public ulong ReadOps,WriteOps,OtherOps,ReadBytes,WriteBytes,OtherBytes;}
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits {public BasicLimits Basic;public IoCounters Io;public UIntPtr ProcessMemory,JobMemory,PeakProcessMemory,PeakJobMemory;}
    [StructLayout(LayoutKind.Sequential)] private struct BasicAccounting {public long User,Kernel,PeriodUser,PeriodKernel;public uint PageFaults,TotalProcesses,ActiveProcesses,TerminatedProcesses;}
    [StructLayout(LayoutKind.Sequential)] private struct NativeUnicodeString {internal ushort Length,MaximumLength;internal IntPtr Buffer;}
    [StructLayout(LayoutKind.Sequential)] private struct NativeObjectAttributes {internal int Length;internal IntPtr Root,Name;internal uint Attributes;internal IntPtr SecurityDescriptor,SecurityQualityOfService;}
    [DllImport("ntdll.dll",ExactSpelling=true)] private static extern int NtCreateJobObject(out SafeJobHandle handle,int access,ref NativeObjectAttributes attributes);
    [DllImport("ntdll.dll",ExactSpelling=true)] private static extern int NtQueryObject(SafeJobHandle handle,int info,[Out] uint[] buffer,uint size,out uint returned);
    [DllImport("ntdll.dll",ExactSpelling=true)] private static extern uint RtlNtStatusToDosError(int status);
    [DllImport("kernel32.dll",EntryPoint="CreateJobObjectW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeJobHandle CreateJobObject(ref KernelJobSeal.SecurityAttributes attributes,string name);
    [DllImport("kernel32.dll",EntryPoint="OpenJobObjectW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeJobHandle OpenJobObject(uint access,[MarshalAs(UnmanagedType.Bool)] bool inherit,string name);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetInformationJobObject(SafeJobHandle handle,int info,ref ExtendedLimits limits,uint size);
    [DllImport("kernel32.dll",EntryPoint="QueryInformationJobObject",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryLimits(SafeJobHandle handle,int info,out ExtendedLimits limits,uint size,out uint returned);
    [DllImport("kernel32.dll",EntryPoint="QueryInformationJobObject",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryAccounting(SafeJobHandle handle,int info,out BasicAccounting accounting,uint size,out uint returned);
    [DllImport("kernel32.dll",EntryPoint="QueryInformationJobObject",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryBuffer(SafeJobHandle handle,int info,IntPtr buffer,uint size,out uint returned);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool TerminateJobObject(SafeJobHandle handle,uint exitCode);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool IsProcessInJob(SafeProcessHandle process,SafeJobHandle job,[MarshalAs(UnmanagedType.Bool)] out bool belongs);
}

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
                if(SessionZeroCreatorRecovery.ReadRetired(state,intent)){set.retired.Add(intent.JobId);continue;}
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
        foreach(var id in retired)if(!SessionZeroCreatorRecovery.ReadRetired(state,intents.Single(i=>i.JobId==id)))
            throw new InvalidDataException("Retired admission proof changed");
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
