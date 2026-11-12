using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed record TaskWorkspaceIntent(int SchemaVersion,string InstallationId,string ProfileId,string SessionId,
    string ProfileCreatedSHA256,string ParentIdentity,string Scope);

// Narrow native boundary for the unrecorded-empty recovery transaction. The
// production implementation is the only default; tests inject a fake to drive
// every failure edge without mutating the host filesystem.
internal interface ITaskWorkspaceRecoveryOps
{
    PathLease LockParent(string path);
    string Canonical(string path);
    SafeFileHandle OpenDirectoryForDelete(string path);
    string Identity(SafeFileHandle handle);
    void AssertFreshWorkspace(SafeFileHandle handle,string ownerSid,string packageSid);
    string[] EnumerateNames(SafeFileHandle handle,string path,int maximum);
    void VerifyObject(SafeFileHandle handle,string path,bool directory);
    void MarkDelete(SafeFileHandle handle);
    void AssertAbsent(string path);
}

// Tool-owned disposable task data with publicly traversable ancestry. This
// avoids granting access to private user-profile ancestors for Win32 tools'
// getcwd/path normalization. The task DACL itself remains package-specific.
// This owner is called ONLY through the existing profile/closed-Job cleanup.
internal static partial class SessionTaskWorkspace
{
    internal static string PathFor(string session)=>PathFor(session,Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
    internal static string PathFor(string session,string programFiles)=>WindowsPathSeal.Child(programFiles,
        "ClaudeCodeProtection-Task-"+Identifiers.Hex32(session));
    private static string IntentLeaf(string profile)=>"task-workspace-intent-"+Identifiers.Hex32(profile)+".json";
    private static string CreatedLeaf(string profile)=>"task-workspace-created-"+Identifiers.Hex32(profile)+".json";
    private static string ClosedLeaf(string profile)=>"task-workspace-closed-"+Identifiers.Hex32(profile)+".json";
    // READ_CONTROL | DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE.
    // The exact-entry handle must carry DELETE for FileDispositionInfoEx.
    internal const uint CleanupEntryAccess=0x00030180;
    internal static void Plan(ProtectedState state,ProfileStorageReceipt profile,string session)
    {
        state.AssertHeld();if(profile.Control)throw WfpNative.Contract("ControlProfileCannotOwnTaskWorkspace");
        using var parent=WindowsPathSeal.LockDirectory(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),PathPolicy.CreationParent);
        var path=PathFor(session);
        try{using var existing=WindowsPathSeal.Open(path,true,false);throw WfpNative.Contract("ExistingTaskWorkspaceNotAdopted");}
        catch(ExactPathAbsentException ex)when(string.Equals(ex.FailedPath,path,StringComparison.OrdinalIgnoreCase)){}
        state.WriteNew(IntentLeaf(profile.ProfileId),JsonSerializer.SerializeToUtf8Bytes(new TaskWorkspaceIntent(1,state.InstallationId,profile.ProfileId,
            Identifiers.Hex32(session),state.Read("profile-created-"+profile.ProfileId+".json",8192).SHA256,parent.ObjectIdentity(),"FRESH_DISPOSABLE_TASK_DIRECTORY_ONLY")));
    }
    private static (TaskWorkspaceIntent Value,BoundBytes Raw) ReadIntent(ProtectedState state,ProfileStorageReceipt profile)
    {
        var raw=state.Read(IntentLeaf(profile.ProfileId),8192);using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=3});
        StrictJson.Fields(doc.RootElement,"SchemaVersion","InstallationId","ProfileId","SessionId","ProfileCreatedSHA256","ParentIdentity","Scope");
        var value=JsonSerializer.Deserialize<TaskWorkspaceIntent>(raw.Bytes)??throw WfpNative.Contract("TaskWorkspaceIntentMissing");
        if(value.SchemaVersion!=1 || value.InstallationId!=state.InstallationId || value.ProfileId!=profile.ProfileId || profile.Control ||
            value.ProfileCreatedSHA256!=state.Read("profile-created-"+profile.ProfileId+".json",8192).SHA256 || value.Scope!="FRESH_DISPOSABLE_TASK_DIRECTORY_ONLY")
            throw WfpNative.Contract("TaskWorkspaceIntentOwnershipMismatch");
        _=Identifiers.Hex32(value.SessionId);_=Identifiers.ObjectIdentity(value.ParentIdentity);return(value,raw);
    }
    internal static void RecordCreated(ProtectedState state,ProfileStorageReceipt profile,string session,PathLease workspace)
    {
        state.AssertHeld();var intent=ReadIntent(state,profile);
        if(intent.Value.SessionId!=session || workspace.Path!=PathFor(session))throw WfpNative.Contract("TaskWorkspaceCreationBindingMismatch");
        state.WriteNew(CreatedLeaf(profile.ProfileId),JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,profile.ProfileId,
            SessionId=session,IntentSHA256=intent.Raw.SHA256,WorkspaceIdentity=workspace.ObjectIdentity()}));
    }
    private static (TaskWorkspaceIntent Intent,string Identity,BoundBytes Created) ReadCreated(ProtectedState state,ProfileStorageReceipt profile)
    {
        var intent=ReadIntent(state,profile);var raw=state.ReadOptional(CreatedLeaf(profile.ProfileId))??throw WfpNative.Contract("TaskWorkspaceCreationUnconfirmedPreserved");
        using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=3});var r=doc.RootElement;
        StrictJson.Fields(r,"SchemaVersion","InstallationId","ProfileId","SessionId","IntentSHA256","WorkspaceIdentity");
        if(r.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(r,"InstallationId")!=state.InstallationId ||
            StrictJson.Text(r,"ProfileId")!=profile.ProfileId || StrictJson.Text(r,"SessionId")!=intent.Value.SessionId || StrictJson.Text(r,"IntentSHA256")!=intent.Raw.SHA256)
            throw WfpNative.Contract("TaskWorkspaceCreatedReceiptMismatch");
        return(intent.Value,Identifiers.ObjectIdentity(StrictJson.Text(r,"WorkspaceIdentity")),raw);
    }
    internal static void AssertClosed(ProtectedState state,ProfileStorageReceipt profile)
    {
        if(state.ReadOptional(IntentLeaf(profile.ProfileId)) is null)return;
        var intent=ReadIntent(state,profile);
        // A workspace closure receipt is not cleanup authority. Re-validate
        // the exact profile cleanup scope and any closed-Job binding every
        // time the receipt is consumed.
        var cleanupIntentSHA256=SessionProfileRecovery.ValidateCleanupIntent(state,profile);
        var created=state.ReadOptional(CreatedLeaf(profile.ProfileId));
        var raw=state.ReadOptional(ClosedLeaf(profile.ProfileId))??throw WfpNative.Contract("TaskWorkspaceCleanupPending");
        using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=3});var r=doc.RootElement;
        if(created is null)
        {
            StrictJson.Fields(r,"SchemaVersion","InstallationId","ProfileId","IntentSHA256","ProfileCleanupIntentSHA256","Status","RootAbsent","RemovedEntries","WorkspaceIdentity");
            var identity=LifecycleJournal.NullableText(r,"WorkspaceIdentity");
            var removed=r.GetProperty("RemovedEntries").GetInt32();
            if(r.GetProperty("SchemaVersion").GetInt32()!=2 || StrictJson.Text(r,"InstallationId")!=state.InstallationId ||
                StrictJson.Text(r,"ProfileId")!=profile.ProfileId || StrictJson.Text(r,"IntentSHA256")!=intent.Raw.SHA256 ||
                StrictJson.Text(r,"ProfileCleanupIntentSHA256")!=cleanupIntentSHA256 ||
                StrictJson.Text(r,"Status")!="UNRECORDED_EMPTY_TASK_DIRECTORY_ABSENCE_OBSERVED" || !r.GetProperty("RootAbsent").GetBoolean() ||
                removed is <0 or >1 || (removed==0)!=(identity is null) || state.ReadOptional("profile-job-"+profile.ProfileId+".json") is not null)
                throw WfpNative.Contract("UnrecordedTaskWorkspaceCleanupReceiptMismatch");
            if(identity is not null)_=Identifiers.ObjectIdentity(identity);
            using var parent=WindowsPathSeal.LockDirectory(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),PathPolicy.CreationParent);
            if(parent.ObjectIdentity()!=intent.Value.ParentIdentity)throw WfpNative.Contract("TaskWorkspaceParentChanged");
            var path=PathFor(intent.Value.SessionId);
            try{using var exists=WindowsPathSeal.Open(path,true,false);throw WfpNative.Contract("UnrecordedTaskWorkspaceStillPresent");}
            catch(ExactPathAbsentException ex)when(string.Equals(ex.FailedPath,path,StringComparison.OrdinalIgnoreCase)){}
            return;
        }
        var creation=ReadCreated(state,profile);
        StrictJson.Fields(r,"SchemaVersion","InstallationId","ProfileId","CreatedSHA256","ProfileCleanupIntentSHA256","Status","RootAbsent","RemovedEntries");
        if(r.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(r,"InstallationId")!=state.InstallationId ||
            StrictJson.Text(r,"ProfileId")!=profile.ProfileId || StrictJson.Text(r,"CreatedSHA256")!=creation.Created.SHA256 ||
            StrictJson.Text(r,"ProfileCleanupIntentSHA256")!=cleanupIntentSHA256 ||
            StrictJson.Text(r,"Status")!="EXACT_TASK_DIRECTORY_ABSENCE_OBSERVED" || !r.GetProperty("RootAbsent").GetBoolean() ||
            r.GetProperty("RemovedEntries").GetInt32() is <0 or >4096)throw WfpNative.Contract("TaskWorkspaceCleanupReceiptMismatch");
    }
    internal static void RequireUnrecordedWorkspaceRecoveryAuthority(bool profileOwned,bool noProcessBinding,bool parentIdentityMatches,
        bool exactTaskPath,bool cleanupIntentHeld)
    {
        if(!profileOwned || !noProcessBinding || !parentIdentityMatches || !exactTaskPath || !cleanupIntentHeld)
            throw WfpNative.Contract("UnrecordedTaskWorkspaceRecoveryAuthorityIncomplete");
    }
    private static void RecordCleanupFailure(ProtectedState state,ProfileStorageReceipt profile,int removed,Exception ex)
    {
        try{state.WriteNew("task-workspace-failure-"+profile.ProfileId+"-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,state.InstallationId,profile.ProfileId,RemovedEntries=removed,Status="NOT_CONFIRMED",Failures=WfpNative.Describe(ex)}));}
        catch(Exception log){throw new AggregateException("Exact task cleanup and failure recording both failed",ex,log);}
    }
}
