using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed record TaskWorkspaceIntent(int SchemaVersion,string InstallationId,string ProfileId,string SessionId,
    string ProfileCreatedSHA256,string ParentIdentity,string Scope);

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
        var creation=ReadCreated(state,profile);var raw=state.ReadOptional(ClosedLeaf(profile.ProfileId))??throw WfpNative.Contract("TaskWorkspaceCleanupPending");
        using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=3});var r=doc.RootElement;
        StrictJson.Fields(r,"SchemaVersion","InstallationId","ProfileId","CreatedSHA256","ProfileCleanupIntentSHA256","Status","RootAbsent","RemovedEntries");
        if(r.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(r,"InstallationId")!=state.InstallationId ||
            StrictJson.Text(r,"ProfileId")!=profile.ProfileId || StrictJson.Text(r,"CreatedSHA256")!=creation.Created.SHA256 ||
            StrictJson.Text(r,"ProfileCleanupIntentSHA256")!=state.Read("profile-delete-intent-"+profile.ProfileId+".json",8192).SHA256 ||
            StrictJson.Text(r,"Status")!="EXACT_TASK_DIRECTORY_ABSENCE_OBSERVED" || !r.GetProperty("RootAbsent").GetBoolean() ||
            r.GetProperty("RemovedEntries").GetInt32() is <0 or >4096)throw WfpNative.Contract("TaskWorkspaceCleanupReceiptMismatch");
    }
    internal static void Cleanup(ProtectedState state,ProfileStorageReceipt profile)
    {
        state.AssertHeld();if(state.ReadOptional(IntentLeaf(profile.ProfileId)) is null)return;
        if(state.ReadOptional(ClosedLeaf(profile.ProfileId)) is not null){AssertClosed(state,profile);return;}
        // The caller has already validated the profile's durable closed-Job
        // binding and written its immutable cleanup intent. Bind to that proof.
        var profileIntent=state.Read("profile-delete-intent-"+profile.ProfileId+".json",8192);
        var creation=ReadCreated(state,profile);var path=PathFor(creation.Intent.SessionId);
        using var parent=WindowsPathSeal.LockDirectory(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),PathPolicy.CreationParent);
        if(parent.ObjectIdentity()!=creation.Intent.ParentIdentity)throw WfpNative.Contract("TaskWorkspaceParentChanged");
        var removed=0;
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
        catch(Exception ex)
        {
            try{state.WriteNew("task-workspace-failure-"+profile.ProfileId+"-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,state.InstallationId,profile.ProfileId,RemovedEntries=removed,Status="NOT_CONFIRMED",Failures=WfpNative.Describe(ex)}));}
            catch(Exception log){throw new AggregateException("Exact task cleanup and failure recording both failed",ex,log);}throw;
        }
    }

    internal static void DeleteExactTree(ProtectedState state,string path,string identity,string audience,string packageSid,Action assertAuthority,ref int removed,
        bool allowAlreadyAbsent=true)
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
                        if(entries.Count>=4096)throw WfpNative.Contract("TaskWorkspaceCleanupInventoryExceeded");
                        var attributes=File.GetAttributes(child);if((attributes&FileAttributes.ReparsePoint)!=0)throw WfpNative.Contract("TaskWorkspaceReparsePointRefused");
                        var directory=(attributes&FileAttributes.Directory)!=0;
                        var entry=Open(child,directory);entries.Add((child,directory,entry));if(directory)pending.Push((child,next.Depth+1,entry));
                    }
                }
                // Complete no-follow/single-link preflight before any deletion.
                // All handles/ancestors stay held against replacement. Changes
                // by another trusted host process can cause a refusal, never a
                // recursive pathname fallback or deletion outside this root.
                foreach(var entry in entries)WindowsPathSeal.VerifyObject(entry.Handle,entry.Path,entry.Directory);
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
        var handle=CreateFile(path,0x00030180,1,IntPtr.Zero,3,0x00200000u|(directory?0x02000000u:0u),IntPtr.Zero);
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
