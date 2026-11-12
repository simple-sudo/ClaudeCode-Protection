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
internal static class SessionTaskWorkspace
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
    private sealed class NativeTaskWorkspaceRecoveryOps : ITaskWorkspaceRecoveryOps
    {
        internal static readonly NativeTaskWorkspaceRecoveryOps Instance=new();
        public PathLease LockParent(string path)=>WindowsPathSeal.LockDirectory(path,PathPolicy.CreationParent);
        public string Canonical(string path)=>WindowsPathSeal.Canonical(path);
        public SafeFileHandle OpenDirectoryForDelete(string path)=>Open(path,true);
        public string Identity(SafeFileHandle handle)=>WindowsPathSeal.Identity(handle);
        public void AssertFreshWorkspace(SafeFileHandle handle,string ownerSid,string packageSid)
            =>SessionResources.AssertFreshWorkspaceForRecovery(handle,ownerSid,packageSid);
        public string[] EnumerateNames(SafeFileHandle handle,string path,int maximum)
            =>WindowsPathSeal.EnumerateNames(handle,path,maximum);
        public void VerifyObject(SafeFileHandle handle,string path,bool directory)
            =>WindowsPathSeal.VerifyObject(handle,path,directory);
        public void MarkDelete(SafeFileHandle handle)
        {
            var disposition=0x17u;
            if(!SetFileInformationByHandle(handle,21,ref disposition,4))
                throw new WfpFailure("DeleteUnrecordedEmptyTaskWorkspace",unchecked((uint)Marshal.GetLastWin32Error()));
        }
        public void AssertAbsent(string path)
        {
            try{using var exists=WindowsPathSeal.Open(path,true,false);throw WfpNative.Contract("UnrecordedTaskWorkspaceStillPresent");}
            catch(ExactPathAbsentException ex)when(string.Equals(ex.FailedPath,path,StringComparison.OrdinalIgnoreCase)){}
        }
    }
    private static void CleanupUnrecordedEmpty(ProtectedState state,ProfileStorageReceipt profile,ref int removed,ITaskWorkspaceRecoveryOps native)
    {
        state.AssertHeld();
        var intent=ReadIntent(state,profile);
        // This verifies the immutable exact-profile deletion scope and,
        // when present, the durable closed/zero Job binding. A raw file hash
        // alone is not sufficient cleanup authority.
        var cleanupIntentSHA256=SessionProfileRecovery.ValidateCleanupIntent(state,profile);
        var binding=state.ReadOptional("profile-job-"+profile.ProfileId+".json");
        var parentPath=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        using var parent=native.LockParent(parentPath);
        var path=PathFor(intent.Value.SessionId);
        var canonical=native.Canonical(path);
        var parentMatches=parent.ObjectIdentity()==intent.Value.ParentIdentity;
        var exactPath=string.Equals(Path.GetDirectoryName(canonical),parent.Path,StringComparison.OrdinalIgnoreCase) &&
            string.Equals(canonical,path,StringComparison.OrdinalIgnoreCase);
        RequireUnrecordedWorkspaceRecoveryAuthority(
            profileOwned:!profile.Control && intent.Value.ProfileCreatedSHA256==state.Read("profile-created-"+profile.ProfileId+".json",8192).SHA256,
            noProcessBinding:binding is null,parentIdentityMatches:parentMatches,exactTaskPath:exactPath,cleanupIntentHeld:
                state.Read("profile-delete-intent-"+profile.ProfileId+".json",8192).SHA256==cleanupIntentSHA256);
        void AssertAuthority()
        {
            state.AssertHeld();
            if(state.Read(IntentLeaf(profile.ProfileId),8192).SHA256!=intent.Raw.SHA256 ||
                state.Read("profile-created-"+profile.ProfileId+".json",8192).SHA256!=intent.Value.ProfileCreatedSHA256 ||
                state.Read("profile-delete-intent-"+profile.ProfileId+".json",8192).SHA256!=cleanupIntentSHA256 ||
                state.ReadOptional("profile-job-"+profile.ProfileId+".json") is not null)
                throw WfpNative.Contract("UnrecordedTaskWorkspaceCleanupAuthorityChanged");
        }
        string? identity=null;
        using var package=new InstallationPackageSid(state);
        try
        {
            // The native adapter opens a DELETE-capable, no-share-delete handle,
            // verifies NTFS/no-reparse identity, exact owner/group/DACL and label,
            // and only exposes MarkDelete after the empty-directory preflight.
            using(var root=native.OpenDirectoryForDelete(path))
            {
                identity=Identifiers.ObjectIdentity(native.Identity(root));
                native.AssertFreshWorkspace(root,profile.OwnerSid,package.Value);
                var names=native.EnumerateNames(root,path,1);
                var empty=names.Length==0;
                // OpenDirectoryForDelete has already pinned the exact NTFS,
                // no-reparse object; AssertFreshWorkspace verified the exact
                // owner/group/DACL and expected-or-absent low label. Only the
                // empty-directory fact remains to decide deletion.
                if(!empty)throw WfpNative.Contract("UnrecordedTaskWorkspaceNotEmpty");
                AssertAuthority();
                native.VerifyObject(root,path,true);
                native.MarkDelete(root);
            }
            removed++;
        }
        catch(ExactPathAbsentException ex)when(string.Equals(ex.FailedPath,path,StringComparison.OrdinalIgnoreCase)){}
        AssertAuthority();
        native.AssertAbsent(path);
        state.WriteNew(ClosedLeaf(profile.ProfileId),JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=2,state.InstallationId,profile.ProfileId,
            IntentSHA256=intent.Raw.SHA256,ProfileCleanupIntentSHA256=cleanupIntent.SHA256,
            Status="UNRECORDED_EMPTY_TASK_DIRECTORY_ABSENCE_OBSERVED",RootAbsent=true,RemovedEntries=removed,WorkspaceIdentity=identity}));
    }
    internal static void Cleanup(ProtectedState state,ProfileStorageReceipt profile)
        =>Cleanup(state,profile,NativeTaskWorkspaceRecoveryOps.Instance);
    internal static void Cleanup(ProtectedState state,ProfileStorageReceipt profile,ITaskWorkspaceRecoveryOps recoveryNative)
    {
        if(recoveryNative is null)throw new ArgumentNullException(nameof(recoveryNative));
        state.AssertHeld();if(state.ReadOptional(IntentLeaf(profile.ProfileId)) is null)return;
        if(state.ReadOptional(ClosedLeaf(profile.ProfileId)) is not null){AssertClosed(state,profile);return;}
        var removed=0;
        if(state.ReadOptional(CreatedLeaf(profile.ProfileId)) is null)
        {
            try{CleanupUnrecordedEmpty(state,profile,ref removed,recoveryNative);}
            catch(Exception ex){RecordCleanupFailure(state,profile,removed,ex);throw;}
            return;
        }
        // The caller has already validated the profile's durable closed-Job
        // binding and written its immutable cleanup intent. Bind to that proof.
        var profileIntent=state.Read("profile-delete-intent-"+profile.ProfileId+".json",8192);
        var creation=ReadCreated(state,profile);var path=PathFor(creation.Intent.SessionId);
        using var parent=WindowsPathSeal.LockDirectory(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),PathPolicy.CreationParent);
        if(parent.ObjectIdentity()!=creation.Intent.ParentIdentity)throw WfpNative.Contract("TaskWorkspaceParentChanged");
        removed=0;
        try
        {
            using var package=new InstallationPackageSid(state);
            DeleteExactTree(state,path,creation.Identity,profile.OwnerSid,package.Value,()=>
            {
                if(state.Read("profile-delete-intent-"+profile.ProfileId+".json",8192).SHA256!=profileIntent.SHA256)
                    throw WfpNative.Contract("TaskWorkspaceCleanupAuthorityChanged");
            },ref removed);
            state.WriteNew(ClosedLeaf(profile.ProfileId),JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,profile.ProfileId,
                CreatedSHA256=creation.Created.SHA256,ProfileCleanupIntentSHA256=profileIntent.SHA256,
                Status="EXACT_TASK_DIRECTORY_ABSENCE_OBSERVED",RootAbsent=true,RemovedEntries=removed}));
        }
        catch(Exception ex){RecordCleanupFailure(state,profile,removed,ex);throw;}
    }

    internal static void DeleteExactTree(ProtectedState state,string path,string identity,string audience,string packageSid,Action assertAuthority,ref int removed,
        bool allowAlreadyAbsent=true,IReadOnlySet<string>? expectedEmptyDirectories=null)
        =>InspectOrDeleteExactTree(state,path,identity,audience,packageSid,assertAuthority,ref removed,allowAlreadyAbsent,expectedEmptyDirectories,inspectOnly:false);

    internal static void AssertExactEmptyTree(ProtectedState state,string path,string identity,string audience,string packageSid,IReadOnlySet<string> expectedEmptyDirectories)
    {
        var removed=0;
        InspectOrDeleteExactTree(state,path,identity,audience,packageSid,()=>{},ref removed,false,expectedEmptyDirectories,inspectOnly:true);
    }

    private static void InspectOrDeleteExactTree(ProtectedState state,string path,string identity,string audience,string packageSid,Action assertAuthority,ref int removed,
        bool allowAlreadyAbsent,IReadOnlySet<string>? expectedEmptyDirectories,bool inspectOnly)
    {
        var entries=new List<(string Path,bool Directory,SafeFileHandle Handle)>();
        try
        {
            SafeFileHandle? root=null;
            try{root=Open(path,true);}
            catch(ExactPathAbsentException ex)when(allowAlreadyAbsent && string.Equals(ex.FailedPath,path,StringComparison.OrdinalIgnoreCase)){}
            if(root is not null)
            {
                entries.Add((path,true,root));
                if(WindowsPathSeal.Identity(root)!=identity)throw WfpNative.Contract("TaskWorkspaceRootReplaced");
                SessionResources.AssertMutableWorkspace(root,audience,packageSid);
                var pending=new Stack<(string Path,int Depth,SafeFileHandle Handle)>();pending.Push((path,0,root));
                while(pending.Count>0)
                {
                    state.AssertHeld();
                    var next=pending.Pop();if(next.Depth>16)throw WfpNative.Contract("TaskWorkspaceCleanupDepthExceeded");
                    foreach(var name in WindowsPathSeal.EnumerateNames(next.Handle,next.Path,4096))
                    {
                        var child=WindowsPathSeal.Child(next.Path,name);
                        if(expectedEmptyDirectories is not null && !expectedEmptyDirectories.Contains(child))
                            throw WfpNative.Contract("LegacyCreatorWorkspaceUnexpectedEntry");
                        if(entries.Count>=4096)throw WfpNative.Contract("TaskWorkspaceCleanupInventoryExceeded");
                        var attributes=File.GetAttributes(child);if((attributes&FileAttributes.ReparsePoint)!=0)throw WfpNative.Contract("TaskWorkspaceReparsePointRefused");
                        var directory=(attributes&FileAttributes.Directory)!=0;
                        if(expectedEmptyDirectories is not null && !directory)throw WfpNative.Contract("LegacyCreatorWorkspaceExpectedDirectory");
                        var entry=Open(child,directory);entries.Add((child,directory,entry));if(directory)pending.Push((child,next.Depth+1,entry));
                        if(expectedEmptyDirectories is not null)SessionResources.AssertMutableWorkspace(entry,audience,packageSid);
                    }
                }
                if(expectedEmptyDirectories is not null && !expectedEmptyDirectories.SetEquals(entries.Skip(1).Select(entry=>entry.Path)))
                    throw WfpNative.Contract("LegacyCreatorWorkspaceInventoryIncomplete");
                // Complete no-follow/single-link preflight before any deletion.
                // All handles/ancestors stay held against replacement. Changes
                // by another trusted host process can cause a refusal, never a
                // recursive pathname fallback or deletion outside this root.
                foreach(var entry in entries)WindowsPathSeal.VerifyObject(entry.Handle,entry.Path,entry.Directory);
                if(inspectOnly)return;
                foreach(var entry in entries.OrderByDescending(e=>e.Path.Length))
                {
                    state.AssertHeld();
                    assertAuthority();
                    if(entry.Path!=path && !entry.Path.StartsWith(path+"\\",StringComparison.OrdinalIgnoreCase))throw WfpNative.Contract("TaskCleanupEscapedRoot");
                    WindowsPathSeal.VerifyObject(entry.Handle,entry.Path,entry.Directory);
                    var disposition=0x17u; // DELETE | POSIX | FORCE_IMAGE_SECTION_CHECK | IGNORE_READONLY_ATTRIBUTE; no ON_CLOSE.
                    if(!SetFileInformationByHandle(entry.Handle,21,ref disposition,4))throw new WfpFailure("DeleteExactTaskEntry",unchecked((uint)Marshal.GetLastWin32Error()));
                    entry.Handle.Dispose();removed++;
                }
            }
            try{using var exists=WindowsPathSeal.Open(path,true,false);throw WfpNative.Contract("TaskWorkspaceStillPresent");}
            catch(ExactPathAbsentException ex)when(string.Equals(ex.FailedPath,path,StringComparison.OrdinalIgnoreCase)){}
        }
        finally{for(var i=entries.Count-1;i>=0;i--)entries[i].Handle.Dispose();}
    }
    private static SafeFileHandle Open(string path,bool directory)
    {
        path=WindowsPathSeal.Canonical(path);
        var handle=CreateFile(path,CleanupEntryAccess,1,IntPtr.Zero,3,0x00200000u|(directory?0x02000000u:0u),IntPtr.Zero);
        if(handle.IsInvalid)
        {
            var error=Marshal.GetLastWin32Error();handle.Dispose();
            if(error is 2 or 3)throw new ExactPathAbsentException(error,path);
            throw new WfpFailure("OpenExactTaskCleanupEntry",unchecked((uint)error));
        }
        try{WindowsPathSeal.VerifyObject(handle,path,directory);return handle;}catch{handle.Dispose();throw;}
    }
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr attributes,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetFileInformationByHandle(SafeFileHandle handle,int informationClass,ref uint information,uint length);
}
