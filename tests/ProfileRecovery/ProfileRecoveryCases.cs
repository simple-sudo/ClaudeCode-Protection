using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

// Source-link the real profile and task-workspace recovery control flow.
// Protected-state, kernel and native filesystem boundaries are faked: tests
// execute the real decisions/receipt code against simulated native operations,
// never host filesystem deletion, AppContainer deletion, WFP, Job or processes.
namespace ProtectionLifecycle;

internal static class ProfileRecoveryCases
{
    internal static void Run()
    {
        var state=new ProtectedState();var id=new string('a',32);var job=new string('b',32);
        using var expected=new InstallationPackageSid(state);using var identity=WindowsIdentity.GetCurrent();
        var record=new ProfileStorageReceipt(2,state.InstallationId,id,false,identity.User!.Value,expected.Name,expected.Value,
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Packages",expected.Name),
            "00000001:00000002:00000003","00000001:00000002:00000004","CREATED_IN_THIS_PROCESS");
        state.Set("profile-intent-"+id+".json",new {SchemaVersion=2,state.InstallationId,ProfileId=id,Control=false,expected.Name,Sid=expected.Value,
            Status="FRESH_PROFILE_CREATION_PLANNED",ExistingProfileAdoptionAllowed=false,AtUtc=DateTime.UtcNow.ToString("o")});
        Expect(()=>SessionProfileRecovery.AssertNoPending(state),"ProfileCreationInterruptedOrUnconfirmedPreserved");
        var created="profile-created-"+id+".json";state.Set(created,record);
        Expect(()=>SessionProfileRecovery.AssertNoPending(state),"OwnedProfileCleanupRequiresRecovery");
        // No process binding permits a pre-process cleanup checkpoint, never
        // a session launch or a fabricated closed-Job completion.
        SessionProfileRecovery.WriteCleanupIntent(state,record);
        var initial=state.Read("profile-delete-intent-"+id+".json").SHA256;
        SessionProfileRecovery.WriteCleanupIntent(state,record);
        if(initial!=state.Read("profile-delete-intent-"+id+".json").SHA256)throw new Exception("cleanup checkpoint changed on readback");
        state.Remove("profile-delete-intent-"+id+".json");
        state.Set("profile-job-"+id+".json",new {SchemaVersion=1,state.InstallationId,ProfileId=id,CreatedSHA256=state.Read(created).SHA256,JobId=job});
        Expect(()=>SessionProfileRecovery.WriteCleanupIntent(state,record),"ProfileRecoveryNeedsDurableClosedJobZero");
        if(state.ReadOptional("profile-delete-intent-"+id+".json") is not null)throw new Exception("unclosed Job issued cleanup authority");
        state.Closed=true;state.Set("job-completed-"+job+".json",new {Status="FAKE_CLOSED_ZERO_FOR_READER_CASE_ONLY"});
        SessionProfileRecovery.WriteCleanupIntent(state,record);
        // Foreign user/installation/storage and changed creation bytes must
        // never inherit a previously valid deletion checkpoint.
        foreach(var changed in new[]{record with {OwnerSid="S-1-5-18"},record with {InstallationId=new string('c',32)},
            record with {StorageRoot=Path.GetPathRoot(record.StorageRoot)!},record with {Control=true},
            record with {StorageIdentity="bad"}})
        {
            state.Set(created,changed);ExpectAny(()=>SessionProfileRecovery.AssertNoPending(state));
        }
        state.Set(created,record);
        // Changed completion bytes also invalidate the bound pre-delete intent.
        state.Set("job-completed-"+job+".json",new {Status="CHANGED"});
        Expect(()=>SessionProfileRecovery.WriteCleanupIntent(state,record),"ProfileCleanupIntentMismatch");
        // Exercise the actual unrecorded-empty cleanup control flow and the
        // actual closed-receipt reader. Only the native filesystem boundary is
        // faked; all state, authority, decision, failure and receipt code is real.
        SessionResources.ProfileRoot=record.StorageRoot;
        var session=new string('d',32);
        ProtectedState BuildTaskState()
        {
            var taskState=new ProtectedState();
            taskState.Set("profile-intent-"+id+".json",new {
                SchemaVersion=2,taskState.InstallationId,ProfileId=id,Control=false,Name=record.Name,Sid=record.Sid,
                Status="FRESH_PROFILE_CREATION_PLANNED",ExistingProfileAdoptionAllowed=false,AtUtc=DateTime.UtcNow.ToString("o")
            });
            taskState.Set(created,record);
            SessionProfileRecovery.WriteCleanupIntent(taskState,record);
            taskState.Set("task-workspace-intent-"+id+".json",new TaskWorkspaceIntent(1,taskState.InstallationId,id,session,
                taskState.Read(created).SHA256,record.ParentIdentity,"FRESH_DISPOSABLE_TASK_DIRECTORY_ONLY"));
            WindowsPathSeal.ParentIdentity=record.ParentIdentity;
            WindowsPathSeal.PresentPath=null;
            return taskState;
        }
        var taskPath=SessionTaskWorkspace.PathFor(session);
        var absentState=BuildTaskState();
        var absentOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=false,ParentIdentity=record.ParentIdentity};
        SessionTaskWorkspace.Cleanup(absentState,record,absentOps);
        SessionTaskWorkspace.AssertClosed(absentState,record);
        Require(absentOps.OpenCount==1 && absentOps.DeleteCount==0,
            "recovery records exact absence when the interrupted task directory was never created");

        // A crash can also occur after the directory deletion succeeds but
        // before the closed receipt is durably written. The next recovery
        // observes the exact fixed path absent and completes the receipt
        // without issuing a second delete or adopting another object.
        var replayAbsentState=BuildTaskState();
        var replayAbsentOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=false,ParentIdentity=record.ParentIdentity};
        SessionTaskWorkspace.Cleanup(replayAbsentState,record,replayAbsentOps);
        SessionTaskWorkspace.AssertClosed(replayAbsentState,record);
        Require(replayAbsentOps.OpenCount==1 && replayAbsentOps.DeleteCount==0 &&
            replayAbsentState.Read("task-workspace-closed-"+id+".json").Bytes.Length>0,
            "recovery is idempotent after deletion completed but before closed receipt persistence");

        var emptyState=BuildTaskState();
        var emptyOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity=record.ParentIdentity,Names=Array.Empty<string>()};
        SessionTaskWorkspace.Cleanup(emptyState,record,emptyOps);
        SessionTaskWorkspace.AssertClosed(emptyState,record);
        Require(emptyOps.DeleteCount==1 && !emptyOps.DirectoryExists,
            "recovery deletes exactly one verified empty directory and records its identity");

        var absentLowLabelState=BuildTaskState();
        var absentLowLabelOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity=record.ParentIdentity,
            LowLabelExact=false,LowLabelAbsent=true};
        SessionTaskWorkspace.Cleanup(absentLowLabelState,record,absentLowLabelOps);
        SessionTaskWorkspace.AssertClosed(absentLowLabelState,record);
        Require(absentLowLabelOps.DeleteCount==1,
            "the narrowly permitted crash window with an absent low-integrity label remains recoverable");

        var invalidLowLabelState=BuildTaskState();
        var invalidLowLabelOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity=record.ParentIdentity,
            LowLabelExact=false,LowLabelAbsent=false};
        ExpectAny(()=>SessionTaskWorkspace.Cleanup(invalidLowLabelState,record,invalidLowLabelOps));
        Require(invalidLowLabelOps.DeleteCount==0 && invalidLowLabelOps.DirectoryExists,
            "an unexpected low-integrity label never reaches deletion");

        var invalidCleanupState=BuildTaskState();
        invalidCleanupState.Set("profile-delete-intent-"+id+".json",new {
            SchemaVersion=2,invalidCleanupState.InstallationId,ProfileId=id,
            CreatedSHA256=invalidCleanupState.Read(created).SHA256,
            JobId=(string?)null,BindingSHA256=(string?)null,CompletionSHA256=(string?)null,
            Scope="OTHER_PROFILE",NewProcessAdmissionAllowed=false
        });
        var invalidCleanupOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity=record.ParentIdentity};
        ExpectAny(()=>SessionTaskWorkspace.Cleanup(invalidCleanupState,record,invalidCleanupOps));
        Require(invalidCleanupOps.OpenCount==0 && invalidCleanupOps.DeleteCount==0 && invalidCleanupOps.DirectoryExists,
            "an invalid profile cleanup scope is rejected before opening the task directory");

        var invalidIdentityState=BuildTaskState();
        var invalidIdentityOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity=record.ParentIdentity,
            WorkspaceIdentity="not-an-object-identity"};
        ExpectAny(()=>SessionTaskWorkspace.Cleanup(invalidIdentityState,record,invalidIdentityOps));
        Require(invalidIdentityOps.DeleteCount==0 && invalidIdentityOps.DirectoryExists,
            "an invalid filesystem object identity is rejected before deletion");

        var enumerationFailureState=BuildTaskState();
        var enumerationFailureOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity=record.ParentIdentity,
            EnumerationFails=true};
        ExpectAny(()=>SessionTaskWorkspace.Cleanup(enumerationFailureState,record,enumerationFailureOps));
        Require(enumerationFailureOps.DeleteCount==0 && enumerationFailureOps.DirectoryExists,
            "an incomplete directory inventory cannot authorize deletion");

        var pathMismatchState=BuildTaskState();
        var pathMismatchOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity=record.ParentIdentity,
            PathMatches=false};
        ExpectAny(()=>SessionTaskWorkspace.Cleanup(pathMismatchState,record,pathMismatchOps));
        Require(pathMismatchOps.DeleteCount==0 && pathMismatchOps.DirectoryExists,
            "a changed opened-object path cannot authorize deletion");

        var nonEmptyState=BuildTaskState();
        var nonEmptyOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity=record.ParentIdentity,Names=new[]{"unexpected.txt"}};
        ExpectAny(()=>SessionTaskWorkspace.Cleanup(nonEmptyState,record,nonEmptyOps));
        Require(nonEmptyOps.DeleteCount==0 && nonEmptyOps.DirectoryExists &&
            nonEmptyState.ReadOptional("task-workspace-closed-"+id+".json") is null &&
            nonEmptyState.ListLeaves("task-workspace-failure-"+id+"-").Length==1,
            "non-empty interrupted workspace is preserved and failure is journaled");

        var wrongAclState=BuildTaskState();
        var wrongAclOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity=record.ParentIdentity,DescriptorValid=false};
        ExpectAny(()=>SessionTaskWorkspace.Cleanup(wrongAclState,record,wrongAclOps));
        Require(wrongAclOps.DeleteCount==0 && wrongAclOps.DirectoryExists,"wrong owner/group/DACL/label never reaches deletion");

        var reparseState=BuildTaskState();
        var reparseOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity=record.ParentIdentity,NoReparse=false};
        ExpectAny(()=>SessionTaskWorkspace.Cleanup(reparseState,record,reparseOps));
        Require(reparseOps.DeleteCount==0 && reparseOps.DirectoryExists,"reparse-point task root is preserved");

        var wrongParentState=BuildTaskState();
        var wrongParentOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity="00000001:00000002:00000005"};
        ExpectAny(()=>SessionTaskWorkspace.Cleanup(wrongParentState,record,wrongParentOps));
        Require(wrongParentOps.OpenCount==0 && wrongParentOps.DeleteCount==0,"changed Program Files parent identity blocks filesystem access");

        var boundState=BuildTaskState();
        // BuildTaskState wrote a valid no-binding intent. Remove that fixture
        // leaf before creating the distinct immutable bound-job scenario.
        boundState.Remove("profile-delete-intent-"+id+".json");
        boundState.Closed=true;
        boundState.Set("job-completed-"+job+".json",new {Status="FAKE_CLOSED_ZERO_FOR_READER_CASE_ONLY"});
        boundState.Set("profile-job-"+id+".json",new {SchemaVersion=1,boundState.InstallationId,ProfileId=id,
            CreatedSHA256=boundState.Read(created).SHA256,JobId=job});
        SessionProfileRecovery.WriteCleanupIntent(boundState,record);
        var boundOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity=record.ParentIdentity};
        ExpectAny(()=>SessionTaskWorkspace.Cleanup(boundState,record,boundOps));
        Require(boundOps.OpenCount==0 && boundOps.DeleteCount==0,
            "even a durably closed process binding cannot use unrecorded-empty recovery");

        var deleteFailureState=BuildTaskState();
        var deleteFailureOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity=record.ParentIdentity,DeleteSucceeds=false};
        try{SessionTaskWorkspace.Cleanup(deleteFailureState,record,deleteFailureOps);throw new Exception("delete failure was accepted");}
        catch(WfpFailure){}
        Require(deleteFailureOps.DirectoryExists && deleteFailureOps.DeleteCount==1 &&
            deleteFailureState.ReadOptional("task-workspace-closed-"+id+".json") is null,
            "native delete failure produces no closed receipt and preserves the task root");

        var stillPresentState=BuildTaskState();
        var stillPresentOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity=record.ParentIdentity,KeepPresentAfterDelete=true};
        ExpectAny(()=>SessionTaskWorkspace.Cleanup(stillPresentState,record,stillPresentOps));
        Require(stillPresentOps.DeleteCount==1 && stillPresentOps.DirectoryExists &&
            stillPresentState.ReadOptional("task-workspace-closed-"+id+".json") is null,
            "recovery refuses to issue a closed receipt when post-delete absence is not observed");

        var changedAfterDeleteState=BuildTaskState();
        var changedAfterDeleteOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity=record.ParentIdentity};
        changedAfterDeleteOps.AfterDelete=()=>changedAfterDeleteState.Set("profile-delete-intent-"+id+".json",new {SchemaVersion=2,Changed=true});
        ExpectAny(()=>SessionTaskWorkspace.Cleanup(changedAfterDeleteState,record,changedAfterDeleteOps));
        Require(!changedAfterDeleteOps.DirectoryExists &&
            changedAfterDeleteState.ReadOptional("task-workspace-closed-"+id+".json") is null,
            "cleanup-intent drift after deletion prevents a false closed receipt");

        var changedTaskIntentAfterDeleteState=BuildTaskState();
        var changedTaskIntentAfterDeleteOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity=record.ParentIdentity};
        changedTaskIntentAfterDeleteOps.AfterDelete=()=>changedTaskIntentAfterDeleteState.Set("task-workspace-intent-"+id+".json",
            new TaskWorkspaceIntent(1,changedTaskIntentAfterDeleteState.InstallationId,id,new string('e',32),
                changedTaskIntentAfterDeleteState.Read(created).SHA256,record.ParentIdentity,"FRESH_DISPOSABLE_TASK_DIRECTORY_ONLY"));
        ExpectAny(()=>SessionTaskWorkspace.Cleanup(changedTaskIntentAfterDeleteState,record,changedTaskIntentAfterDeleteOps));
        Require(!changedTaskIntentAfterDeleteOps.DirectoryExists &&
            changedTaskIntentAfterDeleteState.ReadOptional("task-workspace-closed-"+id+".json") is null,
            "task-intent drift after deletion prevents a false closed receipt");

        var changedCreatedAfterDeleteState=BuildTaskState();
        var changedCreatedAfterDeleteOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity=record.ParentIdentity};
        changedCreatedAfterDeleteOps.AfterDelete=()=>changedCreatedAfterDeleteState.Set(created,
            record with {StorageIdentity="00000001:00000002:00000009"});
        ExpectAny(()=>SessionTaskWorkspace.Cleanup(changedCreatedAfterDeleteState,record,changedCreatedAfterDeleteOps));
        Require(!changedCreatedAfterDeleteOps.DirectoryExists &&
            changedCreatedAfterDeleteState.ReadOptional("task-workspace-closed-"+id+".json") is null,
            "profile-created receipt drift after deletion prevents a false closed receipt");

        var bindingAfterDeleteState=BuildTaskState();
        var bindingAfterDeleteOps=new FakeTaskWorkspaceRecoveryOps{DirectoryExists=true,ParentIdentity=record.ParentIdentity};
        bindingAfterDeleteOps.AfterDelete=()=>bindingAfterDeleteState.Set("profile-job-"+id+".json",
            new {SchemaVersion=1,bindingAfterDeleteState.InstallationId,ProfileId=id,
                CreatedSHA256=bindingAfterDeleteState.Read(created).SHA256,JobId=job});
        ExpectAny(()=>SessionTaskWorkspace.Cleanup(bindingAfterDeleteState,record,bindingAfterDeleteOps));
        Require(!bindingAfterDeleteOps.DirectoryExists &&
            bindingAfterDeleteState.ReadOptional("task-workspace-closed-"+id+".json") is null,
            "a process binding appearing during cleanup prevents a false closed receipt");

        ProtectedState BuildClosedReceiptState(int removed=0,string? workspaceIdentity=null,bool rootAbsent=true)
        {
            var taskState=BuildTaskState();
            var intentLeaf="task-workspace-intent-"+id+".json";
            taskState.Set("task-workspace-closed-"+id+".json",new {
                SchemaVersion=2,taskState.InstallationId,ProfileId=id,IntentSHA256=taskState.Read(intentLeaf).SHA256,
                ProfileCleanupIntentSHA256=taskState.Read("profile-delete-intent-"+id+".json").SHA256,
                Status="UNRECORDED_EMPTY_TASK_DIRECTORY_ABSENCE_OBSERVED",RootAbsent=rootAbsent,
                RemovedEntries=removed,WorkspaceIdentity=workspaceIdentity
            });
            return taskState;
        }
        SessionTaskWorkspace.AssertClosed(BuildClosedReceiptState(),record);
        foreach(var invalid in new[]{
            BuildClosedReceiptState(rootAbsent:false),
            BuildClosedReceiptState(removed:1),
            BuildClosedReceiptState(removed:1,workspaceIdentity:"bad"),
        }) ExpectAny(()=>SessionTaskWorkspace.AssertClosed(invalid,record));
        var changedIntent=BuildClosedReceiptState();
        changedIntent.Set("task-workspace-intent-"+id+".json",new TaskWorkspaceIntent(1,changedIntent.InstallationId,id,
            new string('e',32),changedIntent.Read(created).SHA256,record.ParentIdentity,"FRESH_DISPOSABLE_TASK_DIRECTORY_ONLY"));
        ExpectAny(()=>SessionTaskWorkspace.AssertClosed(changedIntent,record));
        var changedCleanup=BuildClosedReceiptState();
        changedCleanup.Set("profile-delete-intent-"+id+".json",new {SchemaVersion=2,Changed=true});
        ExpectAny(()=>SessionTaskWorkspace.AssertClosed(changedCleanup,record));
        var boundTask=BuildClosedReceiptState();
        boundTask.Set("profile-job-"+id+".json",new {SchemaVersion=1,JobId=job});
        ExpectAny(()=>SessionTaskWorkspace.AssertClosed(boundTask,record));
        var parentMismatch=BuildClosedReceiptState();
        WindowsPathSeal.ParentIdentity="00000001:00000002:00000005";
        ExpectAny(()=>SessionTaskWorkspace.AssertClosed(parentMismatch,record));
        var rootStillPresent=BuildClosedReceiptState();
        WindowsPathSeal.ParentIdentity=record.ParentIdentity;
        WindowsPathSeal.PresentPath=taskPath;
        ExpectAny(()=>SessionTaskWorkspace.AssertClosed(rootStillPresent,record));
        WindowsPathSeal.PresentPath=null;

        // Unexpected fields are rejected by the actual strict JSON reader.
        state.Set(created,new {record.SchemaVersion,record.InstallationId,record.ProfileId,record.Control,record.OwnerSid,record.Name,record.Sid,
            record.StorageRoot,record.StorageIdentity,record.ParentIdentity,record.Status,Extra="foreign"});
        ExpectAny(()=>SessionProfileRecovery.AssertNoPending(state));
    }
    private static void Require(bool condition,string message)
    {if(!condition)throw new Exception(message);}
    private static void Expect(Action action,string reason)
    {try{action();}catch(InvalidDataException ex)when(ex.Message==reason){return;}throw new Exception("profile reader did not refuse: "+reason);}
    private static void ExpectAny(Action action)
    {try{action();}catch(InvalidDataException){return;}throw new Exception("profile reader accepted foreign data");}
}
internal sealed record BoundBytes(byte[] Bytes,string SHA256);
internal sealed class ProtectedState
{
    private readonly Dictionary<string,BoundBytes> files=new(StringComparer.Ordinal);
    internal string InstallationId=>new('1',32);
    internal bool Closed;
    internal void AssertHeld(){}
    internal void Set(string leaf,object value){var bytes=JsonSerializer.SerializeToUtf8Bytes(value);files[leaf]=new(bytes,Convert.ToHexString(SHA256.HashData(bytes)));}
    internal void Remove(string leaf)=>files.Remove(leaf);
    internal BoundBytes Read(string leaf,int maximum=8192)=>files[leaf];
    internal BoundBytes? ReadOptional(string leaf)=>files.GetValueOrDefault(leaf);
    internal void WriteNew(string leaf,byte[] bytes)=>files.Add(leaf,new(bytes,Convert.ToHexString(SHA256.HashData(bytes))));
    internal string[] ListLeaves(string prefix)=>files.Keys.Where(k=>k.StartsWith(prefix,StringComparison.Ordinal)).OrderBy(k=>k,StringComparer.Ordinal).ToArray();
}
internal static class WfpNative
{
    internal static InvalidDataException Contract(string reason)=>new(reason);
    internal static string Describe(Exception error)=>error.GetType().Name+": "+error.Message;
}
internal static class Identifiers
{
    internal static string Hex32(string value)=>value.Length==32 && value.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f')?value:throw new InvalidDataException("id");
    internal static string ObjectIdentity(string value)=>value.Length==26 && value.Split(':').Length==3?value:throw new InvalidDataException("identity");
}
internal static class StrictJson
{
    internal static void Fields(JsonElement root,params string[] expected)
    {var names=root.EnumerateObject().Select(p=>p.Name).ToArray();if(names.Length!=expected.Length || names.Distinct().Count()!=names.Length || names.Except(expected).Any())throw new InvalidDataException("fields");}
    internal static string Text(JsonElement root,string name)=>root.GetProperty(name).GetString()??throw new InvalidDataException("text");
}
internal static class LifecycleJournal{internal static string? NullableText(JsonElement root,string name)=>root.GetProperty(name).ValueKind==JsonValueKind.Null?null:StrictJson.Text(root,name);}
internal sealed class InstallationPackageSid : IDisposable
{
    internal string Name{get;}internal string Value=>"S-1-15-2-TEST-"+Name;
    internal InstallationPackageSid(ProtectedState state):this("ClaudeCodeProtection."+state.InstallationId){}
    private InstallationPackageSid(string name){Name=name;}
    internal static InstallationPackageSid ForNetworkControl(ProtectedState state)=>new("CPC.NetControl."+state.InstallationId);
    public void Dispose(){}
}
internal sealed record OwnedJobIntent(string JobId){internal static OwnedJobIntent Read(ProtectedState state,string job)=>new(job);internal static OwnedJobIntent[] ReadAll(ProtectedState state)=>throw new Exception("native collaborator forbidden in reader tests");}
internal static class AtomicJobCompletion{internal static object? ReadClosed(ProtectedState state,OwnedJobIntent job)=>state.Closed?new object():null;}
internal static class UnadmittedJobRetirement
{
    internal static bool Read(ProtectedState state,OwnedJobIntent job)=>throw new Exception("Job inventory forbidden in reader tests");
}
internal static class SessionZeroCreatorRecovery
{
    internal static bool IsAdmissionResolved(ProtectedState state,OwnedJobIntent job)=>throw new Exception("native Job inventory forbidden in reader tests");
    internal static bool ReadRetired(ProtectedState state,OwnedJobIntent job)=>throw new Exception("native Job inventory forbidden in reader tests");
}
internal enum PathPolicy{Source,CreationParent}
internal sealed class PathLease : IDisposable
{
    internal string Path{get;}
    private readonly string identity;
    internal PathLease(string path,string objectIdentity){Path=path;identity=objectIdentity;}
    internal void AssertHeld(){}
    internal string ObjectIdentity()=>identity;
    public void Dispose(){}
}
internal static class WindowsPathSeal
{
    internal static string? PresentPath;
    internal static string ParentIdentity="00000001:00000002:00000004";
    internal static string Child(string path,string relative)=>Path.GetFullPath(Path.Combine(path,relative.Replace('/',Path.DirectorySeparatorChar)));
    internal static string Canonical(string path)=>Path.GetFullPath(path);
    internal static PathLease LockDirectory(string path,PathPolicy policy)=>new(Path.GetFullPath(path),ParentIdentity);
    internal static SafeFileHandle Open(string path,bool directory,bool read)
    {
        if(string.Equals(Path.GetFullPath(path),PresentPath,StringComparison.OrdinalIgnoreCase))
            return new SafeFileHandle(IntPtr.Zero,false);
        throw new ExactPathAbsentException(2,Path.GetFullPath(path));
    }
    internal static string Identity(SafeFileHandle handle)=>throw new Exception("native forbidden");
    internal static string[] EnumerateNames(SafeFileHandle handle,string path,int maximum)=>throw new Exception("native forbidden");
    internal static void VerifyObject(SafeFileHandle handle,string path,bool directory)=>throw new Exception("native forbidden");
}
internal sealed class ExactPathAbsentException : Exception
{
    internal string FailedPath{get;}
    internal ExactPathAbsentException(int error,string path):base("exact path absent ("+error+")"){FailedPath=path;}
}
internal static class SessionResources
{
    internal static string ProfileRoot="";
    internal static string ProfileFolder(string sid)=>ProfileRoot;
    internal static void AssertFreshWorkspaceForRecovery(SafeFileHandle handle,string human,string package)=>throw new Exception("native recovery mutation forbidden");
    internal static void AssertMutableWorkspace(SafeFileHandle handle,string human,string package)=>throw new Exception("native cleanup forbidden");
}
internal static class InstallationLoopbackLease{internal static void AssertClosedHistory(ProtectedState state)=>throw new Exception("native forbidden");}
internal sealed class FencePlan{internal FencePlan Data=>this;internal string FenceId=>throw new Exception("native forbidden");internal static IReadOnlyList<FencePlan> ReadAll(ProtectedState state)=>throw new Exception("native forbidden");}
internal sealed class PersistentFence : IDisposable{internal static PersistentFence OpenExisting(ProtectedState state,string id)=>throw new Exception("native forbidden");internal (bool FullQuarantineObserved, bool Unused) Observe()=>throw new Exception("native forbidden");public void Dispose(){}}
internal sealed class WfpFailure : IOException{internal WfpFailure(string stage,uint status):base(stage){}}
internal sealed class FakeTaskWorkspaceRecoveryOps : ITaskWorkspaceRecoveryOps
{
    internal string ParentIdentity="00000001:00000002:00000004";
    internal bool DirectoryExists;
    internal bool DescriptorValid=true;
    internal bool LowLabelExact=true;
    internal bool LowLabelAbsent;
    internal bool NoReparse=true;
    internal bool PathMatches=true;
    internal bool EnumerationFails;
    internal bool DeleteSucceeds=true;
    internal bool KeepPresentAfterDelete;
    internal string WorkspaceIdentity="00000001:00000002:00000006";
    internal string[] Names=Array.Empty<string>();
    internal int OpenCount,DeleteCount;
    internal Action? AfterDelete;
    public PathLease LockParent(string path)=>new(Path.GetFullPath(path),ParentIdentity);
    public string Canonical(string path)=>Path.GetFullPath(path);
    public SafeFileHandle OpenDirectoryForDelete(string path)
    {
        OpenCount++;
        if(!DirectoryExists)throw new ExactPathAbsentException(2,Path.GetFullPath(path));
        return new SafeFileHandle(IntPtr.Zero,false);
    }
    public string Identity(SafeFileHandle handle)=>WorkspaceIdentity;
    public void AssertFreshWorkspace(SafeFileHandle handle,string ownerSid,string packageSid)
    {if(!DescriptorValid || (!LowLabelExact && !LowLabelAbsent))throw WfpNative.Contract("WorkspaceGrantOrLowIntegrityMismatch");}
    public string[] EnumerateNames(SafeFileHandle handle,string path,int maximum)
    {if(EnumerationFails)throw WfpNative.Contract("TaskWorkspaceInventoryIncomplete");return Names.Take(maximum).ToArray();}
    public void VerifyObject(SafeFileHandle handle,string path,bool directory)
    {if(!NoReparse)throw WfpNative.Contract("TaskWorkspaceReparsePointRefused");if(!PathMatches)throw WfpNative.Contract("TaskWorkspaceOpenedObjectPathMismatch");}
    public void MarkDelete(SafeFileHandle handle)
    {
        DeleteCount++;
        if(!DeleteSucceeds)throw new WfpFailure("FakeTaskWorkspaceDelete",5);
        if(!KeepPresentAfterDelete)DirectoryExists=false;
        AfterDelete?.Invoke();
    }
    public void AssertAbsent(string path)
    {if(DirectoryExists)throw WfpNative.Contract("UnrecordedTaskWorkspaceStillPresent");}
}
