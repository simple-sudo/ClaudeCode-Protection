using System.Text.Json;

namespace ProtectionLifecycle;

// A Broker-owned disposable task directory. The service SID supplies the
// ordinary half of the LPAC access check; the package supplies the other.
// Its pending service ledger is completed only after this tree is removed.
internal sealed class SessionZeroOfflineWorkspace : IDisposable
{
    private readonly ProtectedState state;
    private readonly OwnedKernelJob job;
    private readonly PathLease parent,root;
    private readonly OfflineConsoleStorage storage;
    private readonly string identity,audience,package,createdHash;
    private bool handlesReleased;
    private string? closedHash;
    internal string Path=>root.Path;
    internal string Temp=>storage.View.Temp;
    internal string LocalData=>storage.View.LocalData;

    private SessionZeroOfflineWorkspace(ProtectedState state,OwnedKernelJob job,PathLease parent,PathLease root,OfflineConsoleStorage storage,
        string identity,string audience,string package,string createdHash)
    {
        this.state=state;this.job=job;this.parent=parent;this.root=root;this.storage=storage;
        this.identity=identity;this.audience=audience;this.package=package;this.createdHash=createdHash;
    }

    internal static SessionZeroOfflineWorkspace Create(ProtectedState state,OwnedKernelJob job,SessionZeroCreatorRegistration creator)
    {
        state.AssertHeld();
        var audience=creator.Sid.Value;
        if(job.JobId!=creator.JobId || job.SessionZeroCreatorSid!=audience)throw WfpNative.Contract("CreatorWorkspaceJobMismatch");
        var programFiles=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var path=SessionTaskWorkspace.PathFor(job.JobId,programFiles);
        using var package=new InstallationPackageSid(state);
        var parent=WindowsPathSeal.LockDirectory(programFiles,PathPolicy.CreationParent);
        PathLease? root=null;
        OfflineConsoleStorage? storage=null;
        try
        {
            state.WriteNew("creator-workspace-intent-"+job.JobId+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,state.InstallationId,job.JobId,CreatorSid=audience,PackageSid=package.Value,ParentIdentity=parent.ObjectIdentity()
            }));
            root=SessionResources.CreateWorkspace(path,audience,package.Value,true);
            storage=OfflineConsoleStorage.Create(state,root,audience);
            var identity=root.ObjectIdentity();
            var hash=state.WriteNew(CreatedLeaf(job.JobId),JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,state.InstallationId,job.JobId,WorkspaceIdentity=identity
            }));
            return new(state,job,parent,root,storage,identity,audience,package.Value,hash);
        }
        catch{storage?.Dispose();root?.Dispose();parent.Dispose();throw;}
    }

    internal void AssertHeld()
    {
        state.AssertHeld();
        parent.AssertHeld();
        storage.AssertHeld(root);
        using var opened=WindowsPathSeal.Open(Path,true,false);
        if(WindowsPathSeal.Identity(opened)!=identity)throw WfpNative.Contract("CreatorWorkspaceRootReplaced");
        SessionResources.AssertMutableWorkspace(opened,audience,package);
    }

    internal void CloseAfterProfileCleanup(SessionZeroCreatorChannel channel)
    {
        if(!channel.ConfirmsProfileCleanupFor(job))throw WfpNative.Contract("CreatorWorkspaceRequiresProfileClosure");
        job.AssertCreatorProfileCleanupAllowed(state);
        AssertHeld();
        var intent="creator-workspace-cleanup-"+job.JobId+".json";
        var proof=state.WriteNew(intent,JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,job.JobId,CreatedSHA256=createdHash}));
        ReleasePaths();
        var removed=0;
        SessionTaskWorkspace.DeleteExactTree(state,Path,identity,audience,package,()=>
        {
            parent.AssertHeld();
            if(state.Read(intent,4096).SHA256!=proof || state.Read(CreatedLeaf(job.JobId),4096).SHA256!=createdHash)
                throw WfpNative.Contract("CreatorWorkspaceCleanupAuthorityChanged");
        },ref removed,allowAlreadyAbsent:false);
        closedHash=state.WriteNew(ClosedLeaf(job.JobId),JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,state.InstallationId,job.JobId,IntentSHA256=proof,RemovedEntries=removed,RootAbsent=true
        }));
    }
    internal void AssertClosedFor(ProtectedState exactState,string jobId)
    {
        state.AssertHeld();parent.AssertHeld();
        if(!ReferenceEquals(state,exactState) || job.JobId!=jobId || closedHash is null || state.Read(ClosedLeaf(jobId),4096).SHA256!=closedHash)
            throw WfpNative.Contract("CreatorWorkspaceClosureProofMissing");
        try{using var unexpected=WindowsPathSeal.Open(Path,true,false);throw WfpNative.Contract("CreatorWorkspaceReappeared");}
        catch(ExactPathAbsentException error)when(string.Equals(error.FailedPath,Path,StringComparison.OrdinalIgnoreCase)){}
    }
    private static string CreatedLeaf(string id)=>"creator-workspace-created-"+id+".json";
    private static string ClosedLeaf(string id)=>"creator-workspace-closed-"+id+".json";
    private void ReleasePaths()
    {
        if(handlesReleased)return;
        handlesReleased=true;storage.Dispose();root.Dispose();
    }
    public void Dispose(){ReleasePaths();parent.Dispose();}
}
