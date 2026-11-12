using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

// Source-link the real profile journal reader. Only the protected-state/kernel
// collaborators are fakes. Every native mutation/storage collaborator throws:
// these cases cannot execute profile deletion, WFP, Job or process admission.
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
        // Exercise the actual task-workspace closure receipt reader with a
        // fake state journal and a fake native filesystem boundary. No
        // directory deletion, AppContainer deletion, Job or process is run.
        SessionResources.ProfileRoot=record.StorageRoot;
        var session=new string('d',32);
        ProtectedState BuildTaskState(int removed=0,string? workspaceIdentity=null,bool rootAbsent=true)
        {
            var taskState=new ProtectedState();
            taskState.Set("profile-intent-"+id+".json",new {
                SchemaVersion=2,taskState.InstallationId,ProfileId=id,Control=false,Name=record.Name,Sid=record.Sid,
                Status="FRESH_PROFILE_CREATION_PLANNED",ExistingProfileAdoptionAllowed=false,AtUtc=DateTime.UtcNow.ToString("o")
            });
            taskState.Set(created,record);
            SessionProfileRecovery.WriteCleanupIntent(taskState,record);
            var taskIntent=new TaskWorkspaceIntent(1,taskState.InstallationId,id,session,
                taskState.Read(created).SHA256,record.ParentIdentity,"FRESH_DISPOSABLE_TASK_DIRECTORY_ONLY");
            var intentLeaf="task-workspace-intent-"+id+".json";
            taskState.Set(intentLeaf,taskIntent);
            taskState.Set("task-workspace-closed-"+id+".json",new {
                SchemaVersion=2,taskState.InstallationId,ProfileId=id,
                IntentSHA256=taskState.Read(intentLeaf).SHA256,
                ProfileCleanupIntentSHA256=taskState.Read("profile-delete-intent-"+id+".json").SHA256,
                Status="UNRECORDED_EMPTY_TASK_DIRECTORY_ABSENCE_OBSERVED",RootAbsent=rootAbsent,
                RemovedEntries=removed,WorkspaceIdentity=workspaceIdentity
            });
            WindowsPathSeal.ParentIdentity=record.ParentIdentity;
            WindowsPathSeal.PresentPath=null;
            return taskState;
        }
        var taskPath=SessionTaskWorkspace.PathFor(session);
        SessionTaskWorkspace.AssertClosed(BuildTaskState(),record);
        foreach(var invalid in new[]{
            BuildTaskState(rootAbsent:false),
            BuildTaskState(removed:1),
            BuildTaskState(removed:1,workspaceIdentity:"bad"),
        }) ExpectAny(()=>SessionTaskWorkspace.AssertClosed(invalid,record));
        var changedIntent=BuildTaskState();
        changedIntent.Set("task-workspace-intent-"+id+".json",new TaskWorkspaceIntent(1,changedIntent.InstallationId,id,
            new string('e',32),changedIntent.Read(created).SHA256,record.ParentIdentity,"FRESH_DISPOSABLE_TASK_DIRECTORY_ONLY"));
        ExpectAny(()=>SessionTaskWorkspace.AssertClosed(changedIntent,record));
        var changedCleanup=BuildTaskState();
        changedCleanup.Set("profile-delete-intent-"+id+".json",new {SchemaVersion=2,Changed=true});
        ExpectAny(()=>SessionTaskWorkspace.AssertClosed(changedCleanup,record));
        var boundTask=BuildTaskState();
        boundTask.Set("profile-job-"+id+".json",new {SchemaVersion=1,JobId=job});
        ExpectAny(()=>SessionTaskWorkspace.AssertClosed(boundTask,record));
        var parentMismatch=BuildTaskState();
        WindowsPathSeal.ParentIdentity="00000001:00000002:00000005";
        ExpectAny(()=>SessionTaskWorkspace.AssertClosed(parentMismatch,record));
        var rootStillPresent=BuildTaskState();
        WindowsPathSeal.ParentIdentity=record.ParentIdentity;
        WindowsPathSeal.PresentPath=taskPath;
        ExpectAny(()=>SessionTaskWorkspace.AssertClosed(rootStillPresent,record));
        WindowsPathSeal.PresentPath=null;

        // Unexpected fields are rejected by the actual strict JSON reader.
        state.Set(created,new {record.SchemaVersion,record.InstallationId,record.ProfileId,record.Control,record.OwnerSid,record.Name,record.Sid,
            record.StorageRoot,record.StorageIdentity,record.ParentIdentity,record.Status,Extra="foreign"});
        ExpectAny(()=>SessionProfileRecovery.AssertNoPending(state));
    }
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
    internal static string Child(string path,string relative)=>Path.Combine(path,relative.Replace('/',Path.DirectorySeparatorChar));
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
