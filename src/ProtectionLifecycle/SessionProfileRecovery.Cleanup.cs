using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;

internal static partial class SessionProfileRecovery
{
    private static (string? JobId,string? BindingSHA256,string? CompletionSHA256) ClosedBinding(ProtectedState state,ProfileStorageReceipt record)
    {
        var binding=state.ReadOptional("profile-job-"+record.ProfileId+".json");
        if(binding is null)return(null,null,null); // v2 writer persists this BEFORE any process creation attempt.
        using var doc=JsonDocument.Parse(binding.Bytes,new JsonDocumentOptions{MaxDepth=3});var r=doc.RootElement;
        StrictJson.Fields(r,"SchemaVersion","InstallationId","ProfileId","CreatedSHA256","JobId");
        if(r.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(r,"InstallationId")!=state.InstallationId ||
            StrictJson.Text(r,"ProfileId")!=record.ProfileId || StrictJson.Text(r,"CreatedSHA256")!=state.Read("profile-created-"+record.ProfileId+".json",8192).SHA256)
            throw WfpNative.Contract("ProfileJobBindingMismatch");
        var job=OwnedJobIntent.Read(state,Identifiers.Hex32(StrictJson.Text(r,"JobId")));
        if(AtomicJobCompletion.ReadClosed(state,job) is null)throw WfpNative.Contract("ProfileRecoveryNeedsDurableClosedJobZero");
        return(job.JobId,binding.SHA256,state.Read("job-completed-"+job.JobId+".json",8192).SHA256);
    }
    internal static void WriteCleanupIntent(ProtectedState state,ProfileStorageReceipt record)
    {
        state.AssertHeld();var raw=state.Read("profile-created-"+record.ProfileId+".json",8192);
        if(ReadCreated(state,"profile-created-"+record.ProfileId+".json",raw)!=record)throw WfpNative.Contract("ProfileCreationChanged");
        var binding=ClosedBinding(state,record);var leaf="profile-delete-intent-"+record.ProfileId+".json";
        if(state.ReadOptional(leaf) is null)state.WriteNew(leaf,JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=2,state.InstallationId,
            record.ProfileId,CreatedSHA256=raw.SHA256,binding.JobId,binding.BindingSHA256,binding.CompletionSHA256,
            Scope="EXACT_CREATED_CURRENT_USER_PROFILE_ONLY",NewProcessAdmissionAllowed=false}));
        _=ValidateCleanupIntent(state,record);
    }
    internal static string ValidateCleanupIntent(ProtectedState state,ProfileStorageReceipt record)
    {
        state.AssertHeld();
        var createdLeaf="profile-created-"+record.ProfileId+".json";
        var created=state.Read(createdLeaf,8192);
        if(ReadCreated(state,createdLeaf,created)!=record)throw WfpNative.Contract("ProfileCreationChanged");
        var raw=state.Read("profile-delete-intent-"+record.ProfileId+".json",8192);
        using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=3});var r=doc.RootElement;
        StrictJson.Fields(r,"SchemaVersion","InstallationId","ProfileId","CreatedSHA256","JobId","BindingSHA256","CompletionSHA256","Scope","NewProcessAdmissionAllowed");
        var binding=ClosedBinding(state,record);
        if(r.GetProperty("SchemaVersion").GetInt32()!=2 || StrictJson.Text(r,"InstallationId")!=state.InstallationId ||
            StrictJson.Text(r,"ProfileId")!=record.ProfileId || StrictJson.Text(r,"CreatedSHA256")!=state.Read("profile-created-"+record.ProfileId+".json",8192).SHA256 ||
            LifecycleJournal.NullableText(r,"JobId")!=binding.JobId || LifecycleJournal.NullableText(r,"BindingSHA256")!=binding.BindingSHA256 ||
            LifecycleJournal.NullableText(r,"CompletionSHA256")!=binding.CompletionSHA256 ||
            StrictJson.Text(r,"Scope")!="EXACT_CREATED_CURRENT_USER_PROFILE_ONLY" || r.GetProperty("NewProcessAdmissionAllowed").GetBoolean())
            throw WfpNative.Contract("ProfileCleanupIntentMismatch");
        return raw.SHA256;
    }
    private static bool InspectStorage(ProfileStorageReceipt record)
        =>InspectExactStorage(record.StorageRoot,record.StorageIdentity);
    internal static bool InspectExactStorage(string path,string identity)
    {
        // All descendants are inspected without following reparse points and
        // held until traversal finishes. No partial/best-effort deletion.
        // The protected Job must already be durably CLOSED/zero. Another
        // trusted host process or administrator is outside this guarantee.
        var held=new List<IDisposable>();
        try
        {
            Microsoft.Win32.SafeHandles.SafeFileHandle root;
            try{root=WindowsPathSeal.Open(path,true,false);}
            catch(ExactPathAbsentException ex)when(string.Equals(ex.FailedPath,path,StringComparison.OrdinalIgnoreCase)){return false;}
            held.Add(root);if(WindowsPathSeal.Identity(root)!=identity)throw WfpNative.Contract("ProfileStorageWasReplaced");
            var pending=new Stack<(string Path,int Depth,Microsoft.Win32.SafeHandles.SafeFileHandle Handle)>();pending.Push((path,0,root));var count=0;
            while(pending.Count>0)
            {
                var next=pending.Pop();if(next.Depth>16)throw WfpNative.Contract("ProfileCleanupDepthExceeded");
                foreach(var name in WindowsPathSeal.EnumerateNames(next.Handle,next.Path,2048))
                {
                    var child=WindowsPathSeal.Child(next.Path,name);
                    if(++count>2048)throw WfpNative.Contract("ProfileCleanupInventoryExceeded");
                    var attributes=File.GetAttributes(child);
                    if((attributes&FileAttributes.ReparsePoint)!=0)throw WfpNative.Contract("ProfileCleanupReparsePointRefused");
                    var directory=(attributes&FileAttributes.Directory)!=0;
                    var entry=WindowsPathSeal.Open(child,directory,false);held.Add(entry);
                    if(directory)pending.Push((child,next.Depth+1,entry));
                }
            }
            return true;
        }
        finally{for(var i=held.Count-1;i>=0;i--)held[i].Dispose();}
    }
    internal static void Cleanup(ProtectedState state,ProfileStorageReceipt record)
    {
        WriteCleanupIntent(state,record);
        SessionTaskWorkspace.Cleanup(state,record);
        using var parent=WindowsPathSeal.LockDirectory(Path.GetDirectoryName(record.StorageRoot)!,PathPolicy.Source);
        if(parent.ObjectIdentity()!=record.ParentIdentity)throw WfpNative.Contract("ProfileStorageParentWasReplaced");
        _=InspectStorage(record);
        // Windows requires storage handles closed before this API. The held
        // parent remains outside the profile; there are no live owned children.
        var status=DeleteAppContainerProfile(record.Name);bool absent=false;
        if(status==0)absent=!InspectStorage(record);
        var intent=ValidateCleanupIntent(state,record);
        var result=new {SchemaVersion=2,state.InstallationId,record.ProfileId,
            CreatedSHA256=state.Read("profile-created-"+record.ProfileId+".json",8192).SHA256,CleanupIntentSHA256=intent,
            Status=status==0 && absent?"EXACT_PROFILE_DELETE_AND_STORAGE_ABSENCE_OBSERVED":"PROFILE_CLEANUP_NOT_CONFIRMED",
            HResult=status,StorageRootAbsent=absent,ProfileRegistrationAbsenceQualified=false};
        var bytes=JsonSerializer.SerializeToUtf8Bytes(result);
        state.WriteNew("profile-cleanup-observed-"+record.ProfileId+"-"+Guid.NewGuid().ToString("N")+".json",bytes);
        if(status!=0)throw new WfpFailure("DeleteExactCreatedInstallationProfile",unchecked((uint)status));
        if(!absent)throw WfpNative.Contract("ProfileDeleteReturnedSuccessButStorageRemains");
        state.WriteNew("profile-cleaned-"+record.ProfileId+".json",bytes);
    }
    internal static (int ExitCode,string Report) RecoverClosed(ProtectedState state)
    {
        state.AssertHeld();InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var job in OwnedJobIntent.ReadAll(state))
            if(!SessionZeroCreatorRecovery.IsAdmissionResolved(state,job))throw WfpNative.Contract("ResourceRecoveryRequiresAllAdmissionsClosed");
        var fences=FencePlan.ReadAll(state);if(fences.Count==0)throw WfpNative.Contract("ResourceRecoveryNeedsQuarantine");
        foreach(var plan in fences)
        {using var fence=PersistentFence.OpenExisting(state,plan.Data.FenceId);if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("ResourceRecoveryNeedsFullQuarantine");}
        var records=Pending(state);var recovered=new List<string>();
        foreach(var record in records)_=ValidateCleanupIntent(state,record);
        foreach(var record in records)
        {
            // An uncertain crash before checkpoint remains UNKNOWN. No new
            // cleanup intent is invented by the cross-process recovery path.
            _=ValidateCleanupIntent(state,record);Cleanup(state,record);recovered.Add(record.ProfileId);
        }
        AssertNoPending(state);
        return(0,JsonSerializer.Serialize(new {SchemaVersion=1,Scope="OWNED_PROFILE_POST_CLOSED_JOB_CLEANUP_ONLY",
            Status=recovered.Count==0?"NO_PENDING_PROFILE_CLEANUP":"EXACT_PROFILE_STORAGE_RECOVERED",RecoveredProfileIds=recovered,
            ProfileRegistrationAbsenceQualified=false,ControllerCrashQualified=false,RebootRecoveryQualified=false,
            LaunchAuthorized=false,NetworkPolicyModified=false,ClaudeLaunched=false}));
    }
    internal static (int ExitCode,string Report) InspectRecovery(ProtectedState state)
    {
        state.AssertHeld();
        var jobs=OwnedJobIntent.ReadAll(state);
        var allResolved=true;
        var retiredCount=0;
        var legacyRetirementChecked=false;
        foreach(var job in jobs)
        {
            if(UnadmittedJobRetirement.Read(state,job)){retiredCount++;continue;}
            if(SessionZeroCreatorRecovery.ReadRetired(state,job)){retiredCount++;legacyRetirementChecked=true;continue;}
            if(AtomicJobCompletion.ReadClosed(state,job) is null)allResolved=false;
        }
        var pending=Pending(state);if(pending.Count>64)throw WfpNative.Contract("ProfileRecoveryInventoryExceeded");
        var items=new List<object>();
        foreach(var record in pending)
        {
            var bound=state.ReadOptional("profile-job-"+record.ProfileId+".json") is not null;
            var checkpoint=state.ReadOptional("profile-delete-intent-"+record.ProfileId+".json") is not null;
            string route;
            if(!allResolved)route="BLOCKED_ADMISSION_CLOSURE_NOT_CONFIRMED";
            else if(!bound)
            {
                if(checkpoint)_=ValidateCleanupIntent(state,record);
                route="EXPLICIT_NEVER_STARTED_RECOVERY";
            }
            else if(checkpoint){_=ValidateCleanupIntent(state,record);route="EXISTING_CLOSED_JOB_CHECKPOINT_RECOVERY";}
            else route="BLOCKED_POST_CREATION_WITHOUT_CLEANUP_CHECKPOINT";
            items.Add(new {record.ProfileId,ProcessBindingPresent=bound,CleanupCheckpointPresent=checkpoint,Route=route});
        }
        return(pending.Count==0?0:3,JsonSerializer.Serialize(new {SchemaVersion=1,Scope="RESOURCE_RECOVERY_JOURNAL_READ_ONLY",
            Status=pending.Count==0?"NO_PENDING_PROFILE_CLEANUP":"PROFILE_RECOVERY_DECISION_REQUIRED",AllAdmissionsClosed=allResolved && retiredCount==0,
            AllJobHistoriesResolved=allResolved,RetiredNeverAdmittedJobs=retiredCount,
            Pending=items,StorageIdentityAndQuarantineCheckedByRecoveryOnly=true,StateModified=false,JobApiCalled=legacyRetirementChecked,
            CleanupAuthorized=false,LaunchAuthorized=false}));
    }
    internal static (int ExitCode,string Report) RecoverNeverStarted(ProtectedState state)
    {
        state.AssertHeld();InstallationLoopbackLease.AssertClosedHistory(state);
        var retiredCount=0;
        foreach(var job in OwnedJobIntent.ReadAll(state))
        {
            if(UnadmittedJobRetirement.Read(state,job) || SessionZeroCreatorRecovery.ReadRetired(state,job)){retiredCount++;continue;}
            if(AtomicJobCompletion.ReadClosed(state,job) is null)throw WfpNative.Contract("UnstartedRecoveryRequiresAllAdmissionsClosed");
        }
        var fences=FencePlan.ReadAll(state);if(fences.Count==0)throw WfpNative.Contract("UnstartedRecoveryNeedsQuarantine");
        foreach(var plan in fences)
        {using var fence=PersistentFence.OpenExisting(state,plan.Data.FenceId);if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("UnstartedRecoveryNeedsFullQuarantine");}
        var records=Pending(state);if(records.Count>64)throw WfpNative.Contract("ProfileRecoveryInventoryExceeded");
        // Validate the WHOLE target set before writing any new deletion intent.
        // BeforeProcessCreation persists profile-job under this same exclusive
        // state lease BEFORE calling Windows. A present binding never becomes
        // a never-started proof merely because the process/Job is now absent.
        foreach(var record in records)
        {
            if(state.ReadOptional("profile-job-"+record.ProfileId+".json") is not null)
                throw WfpNative.Contract("UnstartedRecoveryRefusesAnyProcessBinding");
            if(state.ReadOptional("profile-delete-intent-"+record.ProfileId+".json") is not null)_=ValidateCleanupIntent(state,record);
        }
        var recovered=new List<string>();
        foreach(var record in records)
        {
            // The existing cleanup owner still binds current human, profile
            // SID/name, original storage/parent IDs and exact task inventory.
            // No fabricated Job completion or replaced/unknown tree adoption.
            WriteCleanupIntent(state,record);Cleanup(state,record);recovered.Add(record.ProfileId);
        }
        AssertNoPending(state);
        return(0,JsonSerializer.Serialize(new {SchemaVersion=1,Scope="EXPLICIT_V2_CREATED_NO_PROCESS_BINDING_RECOVERY_ONLY",
            Status=recovered.Count==0?"NO_PENDING_PROFILE_CLEANUP":"EXACT_NEVER_STARTED_PROFILE_STORAGE_RECOVERED",RecoveredProfileIds=recovered,
            ProcessBindingAbsenceRequired=true,AllAdmissionsClosed=retiredCount==0,AllJobHistoriesResolved=true,
            RetiredNeverAdmittedJobs=retiredCount,JobCompletionInvented=false,NetworkPolicyModified=false,
            ProfileRegistrationAbsenceQualified=false,ControllerCrashQualified=false,RebootRecoveryQualified=false,LaunchAuthorized=false}));
    }
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] private static extern int DeleteAppContainerProfile(string name);
}
