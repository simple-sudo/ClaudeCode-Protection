using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;

// Same profile owner as AtomicChild. Recovery accepts no caller path, SID,
// PID, receipt, or deletion target. Existing post-creation recovery requires a
// durable pre-delete checkpoint. Explicit never-started recovery additionally
// accepts a validated v2 creation with NO durable process binding; the writer
// must persist that binding before every process creation attempt. Neither
// path adopts legacy, incomplete-creation or uncertain post-creation state.
internal static partial class SessionProfileRecovery
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
}
