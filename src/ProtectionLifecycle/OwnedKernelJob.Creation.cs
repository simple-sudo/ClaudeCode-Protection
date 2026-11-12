using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed partial class OwnedKernelJob
{
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
        var intentHash=state.WriteNew(OwnedJobIntent.Leaf(intent.JobId),JsonSerializer.SerializeToUtf8Bytes(intent)); // Before kernel creation.
        OwnedKernelJob? owner=null;
        try
        {
            owner=CreateNative(state,intent,intentHash);
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
    private static OwnedKernelJob CreateNative(ProtectedState state,OwnedJobIntent intent,string intentHash)
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
            var owner=new OwnedKernelJob(state,intent,created,jobNamespace,intentHash);created=null;jobNamespace=null;return owner;
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
}
