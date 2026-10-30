using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record ProfileStorageReceipt(int SchemaVersion,string InstallationId,string ProfileId,bool Control,string OwnerSid,
    string Name,string Sid,string StorageRoot,string StorageIdentity,string ParentIdentity,string Status);

// Same profile owner as AtomicChild. Recovery accepts no caller path, SID,
// PID, receipt, or deletion target. Existing post-creation recovery requires a
// durable pre-delete checkpoint. Explicit never-started recovery additionally
// accepts a validated v2 creation with NO durable process binding; the writer
// must persist that binding before every process creation attempt. Neither
// path adopts legacy, incomplete-creation or uncertain post-creation state.
internal static class SessionProfileRecovery
{
    private static string OwnerSid()
    {using var user=WindowsIdentity.GetCurrent();return user.User?.Value??throw WfpNative.Contract("ProfileHumanOwnerMissing");}
    private static string Storage(string name)=>WindowsPathSeal.Child(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Packages/"+name);
    internal static PathLease PrepareFreshStorage(string name)
    {
        var path=Storage(name);var parent=WindowsPathSeal.LockDirectory(Path.GetDirectoryName(path)!,PathPolicy.Source);
        try
        {
            try{using var exists=WindowsPathSeal.Open(path,true,false);throw WfpNative.Contract("ExistingProfileStorageCannotBeAdopted");}
            catch(ExactPathAbsentException ex)when(string.Equals(ex.FailedPath,path,StringComparison.OrdinalIgnoreCase)){}
            return parent;
        }
        catch{parent.Dispose();throw;}
    }
    internal static ProfileStorageReceipt RecordCreated(ProtectedState state,InstallationPackageSid package,string id,bool control,PathLease parent)
    {
        state.AssertHeld();parent.AssertHeld();var path=Storage(package.Name);
        // This fixed deployment layout is checked against the OS result, not
        // inferred solely from a directory name or a serialized input path.
        var local=SessionResources.ProfileFolder(package.Value);
        if(!string.Equals(local,path,StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(local,WindowsPathSeal.Child(path,"AC"),StringComparison.OrdinalIgnoreCase))
            throw WfpNative.Contract("UnexpectedFreshProfileStorageLayout");
        using var root=WindowsPathSeal.Open(path,true,false);
        var record=new ProfileStorageReceipt(2,state.InstallationId,Identifiers.Hex32(id),control,OwnerSid(),package.Name,package.Value,
            path,WindowsPathSeal.Identity(root),parent.ObjectIdentity(),"CREATED_IN_THIS_PROCESS");
        state.WriteNew("profile-created-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(record));return record;
    }
    private static ProfileStorageReceipt ReadCreated(ProtectedState state,string leaf,BoundBytes raw)
    {
        using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=3});var r=doc.RootElement;
        StrictJson.Fields(r,"SchemaVersion","InstallationId","ProfileId","Control","OwnerSid","Name","Sid","StorageRoot","StorageIdentity","ParentIdentity","Status");
        var value=JsonSerializer.Deserialize<ProfileStorageReceipt>(raw.Bytes)??throw WfpNative.Contract("ProfileCreationReceiptMissing");
        using var expected=value.Control?InstallationPackageSid.ForNetworkControl(state):new InstallationPackageSid(state);
        if(value.SchemaVersion!=2 || value.InstallationId!=state.InstallationId || leaf!="profile-created-"+Identifiers.Hex32(value.ProfileId)+".json" ||
            value.OwnerSid!=OwnerSid() || value.Name!=expected.Name || value.Sid!=expected.Value || value.StorageRoot!=Storage(expected.Name) ||
            value.Status!="CREATED_IN_THIS_PROCESS")throw WfpNative.Contract("ProfileRecoveryOwnershipMismatch");
        using var plan=JsonDocument.Parse(state.Read("profile-intent-"+value.ProfileId+".json",8192).Bytes,new JsonDocumentOptions{MaxDepth=3});var p=plan.RootElement;
        StrictJson.Fields(p,"SchemaVersion","InstallationId","ProfileId","Control","Name","Sid","Status","ExistingProfileAdoptionAllowed","AtUtc");
        if(p.GetProperty("SchemaVersion").GetInt32()!=2 || StrictJson.Text(p,"InstallationId")!=value.InstallationId ||
            StrictJson.Text(p,"ProfileId")!=value.ProfileId || p.GetProperty("Control").GetBoolean()!=value.Control ||
            StrictJson.Text(p,"Name")!=value.Name || StrictJson.Text(p,"Sid")!=value.Sid ||
            StrictJson.Text(p,"Status")!="FRESH_PROFILE_CREATION_PLANNED" || p.GetProperty("ExistingProfileAdoptionAllowed").GetBoolean())
            throw WfpNative.Contract("CreatedProfilePlanDiffers");
        _=Identifiers.ObjectIdentity(value.StorageIdentity);_=Identifiers.ObjectIdentity(value.ParentIdentity);return value;
    }
    private static IReadOnlyList<ProfileStorageReceipt> Pending(ProtectedState state)
    {
        state.AssertHeld();var leaves=state.ListLeaves("profile-created-");
        var plans=state.ListLeaves("profile-intent-");if(leaves.Length>2048 || plans.Length>2048)throw WfpNative.Contract("ProfileInventoryCapacityExceeded");
        foreach(var planLeaf in plans)
        {
            using var doc=JsonDocument.Parse(state.Read(planLeaf,8192).Bytes,new JsonDocumentOptions{MaxDepth=3});var p=doc.RootElement;
            var schema=p.GetProperty("SchemaVersion").GetInt32();
            if(schema==1)continue; // Preserved historical attempts; never recovery authority.
            StrictJson.Fields(p,"SchemaVersion","InstallationId","ProfileId","Control","Name","Sid","Status","ExistingProfileAdoptionAllowed","AtUtc");
            var profile=Identifiers.Hex32(StrictJson.Text(p,"ProfileId"));
            using var expected=p.GetProperty("Control").GetBoolean()?InstallationPackageSid.ForNetworkControl(state):new InstallationPackageSid(state);
            if(schema!=2 || planLeaf!="profile-intent-"+profile+".json" || StrictJson.Text(p,"InstallationId")!=state.InstallationId ||
                StrictJson.Text(p,"Name")!=expected.Name || StrictJson.Text(p,"Sid")!=expected.Value ||
                StrictJson.Text(p,"Status")!="FRESH_PROFILE_CREATION_PLANNED" || p.GetProperty("ExistingProfileAdoptionAllowed").GetBoolean())
                throw WfpNative.Contract("ProfileCreationPlanMismatch");
            if(!leaves.Contains("profile-created-"+profile+".json",StringComparer.Ordinal))
                throw WfpNative.Contract("ProfileCreationInterruptedOrUnconfirmedPreserved");
        }
        var result=new List<ProfileStorageReceipt>();
        foreach(var leaf in leaves)
        {
            var raw=state.Read(leaf,8192);using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=3});
            if(doc.RootElement.GetProperty("SchemaVersion").GetInt32()==1)
            {
                // Original records remain historical evidence. They contain
                // neither filesystem identity nor durable process binding.
                StrictJson.Fields(doc.RootElement,"SchemaVersion","InstallationId","Name","Sid","Status");continue;
            }
            var record=ReadCreated(state,leaf,raw);
            if(!plans.Contains("profile-intent-"+record.ProfileId+".json",StringComparer.Ordinal))throw WfpNative.Contract("ProfileCreationPlanMissing");
            var closed=state.ReadOptional("profile-cleaned-"+record.ProfileId+".json");
            if(closed is null){result.Add(record);continue;}
            SessionTaskWorkspace.AssertClosed(state,record);
            using var completion=JsonDocument.Parse(closed.Bytes,new JsonDocumentOptions{MaxDepth=3});var c=completion.RootElement;
            StrictJson.Fields(c,"SchemaVersion","InstallationId","ProfileId","CreatedSHA256","CleanupIntentSHA256","Status","HResult","StorageRootAbsent","ProfileRegistrationAbsenceQualified");
            if(c.GetProperty("SchemaVersion").GetInt32()!=2 || StrictJson.Text(c,"InstallationId")!=state.InstallationId ||
                StrictJson.Text(c,"ProfileId")!=record.ProfileId || StrictJson.Text(c,"CreatedSHA256")!=raw.SHA256 ||
                StrictJson.Text(c,"CleanupIntentSHA256")!=ValidateCleanupIntent(state,record) ||
                StrictJson.Text(c,"Status")!="EXACT_PROFILE_DELETE_AND_STORAGE_ABSENCE_OBSERVED" || c.GetProperty("HResult").GetInt32()!=0 ||
                !c.GetProperty("StorageRootAbsent").GetBoolean() || c.GetProperty("ProfileRegistrationAbsenceQualified").GetBoolean())
                throw WfpNative.Contract("ProfileCleanupReceiptMismatch");
        }
        return result.AsReadOnly();
    }
    internal static void AssertNoPending(ProtectedState state)
    {if(Pending(state).Count!=0)throw WfpNative.Contract("OwnedProfileCleanupRequiresRecovery");}
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
    private static string ValidateCleanupIntent(ProtectedState state,ProfileStorageReceipt record)
    {
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
    {
        // All descendants are inspected without following reparse points and
        // held until traversal finishes. No partial/best-effort deletion.
        // The protected Job must already be durably CLOSED/zero. Another
        // trusted host process or administrator is outside this guarantee.
        var held=new List<IDisposable>();
        try
        {
            Microsoft.Win32.SafeHandles.SafeFileHandle root;
            try{root=WindowsPathSeal.Open(record.StorageRoot,true,false);}
            catch(ExactPathAbsentException ex)when(string.Equals(ex.FailedPath,record.StorageRoot,StringComparison.OrdinalIgnoreCase)){return false;}
            held.Add(root);if(WindowsPathSeal.Identity(root)!=record.StorageIdentity)throw WfpNative.Contract("ProfileStorageWasReplaced");
            var pending=new Stack<(string Path,int Depth,Microsoft.Win32.SafeHandles.SafeFileHandle Handle)>();pending.Push((record.StorageRoot,0,root));var count=0;
            while(pending.Count>0)
            {
                var next=pending.Pop();if(next.Depth>16)throw WfpNative.Contract("ProfileCleanupDepthExceeded");
                foreach(var name in WindowsPathSeal.EnumerateNames(next.Handle,next.Path,2048))
                {
                    var path=WindowsPathSeal.Child(next.Path,name);
                    if(++count>2048)throw WfpNative.Contract("ProfileCleanupInventoryExceeded");
                    var attributes=File.GetAttributes(path);
                    if((attributes&FileAttributes.ReparsePoint)!=0)throw WfpNative.Contract("ProfileCleanupReparsePointRefused");
                    var directory=(attributes&FileAttributes.Directory)!=0;
                    var entry=WindowsPathSeal.Open(path,directory,false);held.Add(entry);
                    if(directory)pending.Push((path,next.Depth+1,entry));
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
            if(AtomicJobCompletion.ReadClosed(state,job) is null)throw WfpNative.Contract("ResourceRecoveryRequiresAllAdmissionsClosed");
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
        var allClosed=jobs.All(job=>AtomicJobCompletion.ReadClosed(state,job) is not null);
        var pending=Pending(state);if(pending.Count>64)throw WfpNative.Contract("ProfileRecoveryInventoryExceeded");
        var items=new List<object>();
        foreach(var record in pending)
        {
            var bound=state.ReadOptional("profile-job-"+record.ProfileId+".json") is not null;
            var checkpoint=state.ReadOptional("profile-delete-intent-"+record.ProfileId+".json") is not null;
            string route;
            if(!allClosed)route="BLOCKED_ADMISSION_CLOSURE_NOT_CONFIRMED";
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
            Status=pending.Count==0?"NO_PENDING_PROFILE_CLEANUP":"PROFILE_RECOVERY_DECISION_REQUIRED",AllAdmissionsClosed=allClosed,
            Pending=items,StorageIdentityAndQuarantineCheckedByRecoveryOnly=true,StateModified=false,JobApiCalled=false,
            CleanupAuthorized=false,LaunchAuthorized=false}));
    }
    internal static (int ExitCode,string Report) RecoverNeverStarted(ProtectedState state)
    {
        state.AssertHeld();InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var job in OwnedJobIntent.ReadAll(state))
            if(AtomicJobCompletion.ReadClosed(state,job) is null)throw WfpNative.Contract("UnstartedRecoveryRequiresAllAdmissionsClosed");
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
            ProcessBindingAbsenceRequired=true,AllAdmissionsClosed=true,JobCompletionInvented=false,NetworkPolicyModified=false,
            ProfileRegistrationAbsenceQualified=false,ControllerCrashQualified=false,RebootRecoveryQualified=false,LaunchAuthorized=false}));
    }
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] private static extern int DeleteAppContainerProfile(string name);
}
