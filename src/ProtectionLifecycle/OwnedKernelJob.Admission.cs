using System.ComponentModel;
using System.Security.Principal;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed partial class OwnedKernelJob
{
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
    internal void AssertCreatorProfileBeforeFirstProcess()
    {
        AssertHeld();
        if(intent.CreatorServiceSid is null || !admissionClaimed || admissionClosed || !creatorGrantAttempted || creatorReleaseConfirmed ||
            Accounting().TotalProcesses!=0)
            throw WfpNative.Contract("CreatorProfileRecordRequiresJobBeforeFirstProcess");
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
        if(state.ReadOptional(UnadmittedJobRetirement.Leaf(intent.JobId)) is not null)
            throw WfpNative.Contract("RetiredJobCannotReserveAdmission");
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

    internal JobSnapshot StopAndRetireUnadmitted()
    {
        AssertHeld();
        if(admissionClaimed || admissionClosed || originalIntentHash is null || intent.CreatorServiceSid is not null)
            throw WfpNative.Contract("UnadmittedRetirementRequiresOriginalPrivateJob");
        admissionClosed=true;
        var snapshot=StopAndVerifyZero();
        UnadmittedJobRetirement.AssertNoAdmissionEvidence(state,intent);
        AssertSoleJobHandle(handle);
        var totalProcesses=Accounting().TotalProcesses;
        if(!snapshot.ExpectedLimits || totalProcesses!=0 ||
            state.Read(OwnedJobIntent.Leaf(intent.JobId),8192).SHA256!=originalIntentHash)
            throw WfpNative.Contract("UnadmittedJobRetirementEvidenceMismatch");
        var retirement=new UnadmittedJobRetirement(1,originalIntentHash,UnadmittedJobRetirement.Disposition,totalProcesses,snapshot);
        state.WriteNew(UnadmittedJobRetirement.Leaf(intent.JobId),JsonSerializer.SerializeToUtf8Bytes(retirement));
        return snapshot;
    }
}
