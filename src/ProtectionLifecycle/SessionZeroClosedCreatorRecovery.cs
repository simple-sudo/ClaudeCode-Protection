using System.IO.Pipes;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;

namespace ProtectionLifecycle;

// A closed admission is a prerequisite for recovery. The original failed
// run stays authoritative for launch and identity qualification.
internal static class SessionZeroClosedCreatorRecovery
{
    internal const string Release="aa781cf904fa42be9671e0ddd3a9bb4d";
    internal const string Manifest="86F88D2BD6AFDC4B4E6CAC3CECFAF6943A794DA7C36FFD014A73AFF27CB29751";
    internal const string ServiceVerb="session-zero-profile-recovery";
    private const string Disposition="CLOSED_CREATOR_RESIDUE_RECOVERED";
    private const uint OriginalStop=0xC5620026;
    private const string Asset="ProtectionBootstrap";

    internal sealed record Approval(string InstallationId,string JobId,string WorkerId,string FailedRunSHA256,
        DateTimeOffset WindowStartUtc,DateTimeOffset WindowEndUtc,DateTimeOffset ExpiresUtc)
    {
        internal void AssertFresh()
        {
            if(DateTimeOffset.UtcNow>=ExpiresUtc)throw WfpNative.Contract("ClosedCreatorRecoveryApprovalExpired");
        }

        internal static Approval Read(Stream stream)
        {
            if(stream.Length is <1 or >4096)throw WfpNative.Contract("ClosedCreatorRecoveryApprovalSize");
            using var doc=JsonDocument.Parse(stream,new JsonDocumentOptions{MaxDepth=2});
            var r=doc.RootElement;
            StrictJson.Fields(r,"SchemaVersion","InstallationId","JobId","WorkerId","FailedRunSHA256","WindowStartUtc","WindowEndUtc","ExpiresUtc");
            var approval=new Approval(Identifiers.Hex32(StrictJson.Text(r,"InstallationId")),Identifiers.Hex32(StrictJson.Text(r,"JobId")),
                Identifiers.Hex32(StrictJson.Text(r,"WorkerId")),Identifiers.Hash(StrictJson.Text(r,"FailedRunSHA256")),
                r.GetProperty("WindowStartUtc").GetDateTimeOffset(),r.GetProperty("WindowEndUtc").GetDateTimeOffset(),
                r.GetProperty("ExpiresUtc").GetDateTimeOffset());
            if(r.GetProperty("SchemaVersion").GetInt32()!=1 || approval.WorkerId==approval.JobId ||
                approval.WindowStartUtc.Offset!=TimeSpan.Zero || approval.WindowEndUtc.Offset!=TimeSpan.Zero ||
                approval.ExpiresUtc.Offset!=TimeSpan.Zero || approval.WindowStartUtc>=approval.WindowEndUtc ||
                approval.WindowEndUtc-approval.WindowStartUtc>TimeSpan.FromMinutes(2) || approval.WindowEndUtc>=DateTimeOffset.UtcNow)
                throw WfpNative.Contract("ClosedCreatorRecoveryApprovalInvalid");
            approval.AssertFresh();
            return approval;
        }
    }

    private sealed record Original(string JobIntentSHA256,string JobCreatedSHA256,string CompletionSHA256,string ServiceIntentSHA256,
        string ServiceStartSHA256,string WorkspaceIntentSHA256,string WorkspaceCreatedSHA256,string FailedRunSHA256,
        string WorkspaceParentIdentity,string WorkspaceIdentity,string PackageSid);

    private static Approval ReadEmbedded()
    {
        using var resource=Assembly.GetEntryAssembly()?.GetManifestResourceStream(Asset+".ClosedCreatorRecoveryApproval.json")
            ??throw WfpNative.Contract("ClosedCreatorRecoveryApprovalMissing");
        return Approval.Read(resource);
    }

    internal static Approval AssertWorkerImage(string serviceId)
    {
        var approval=ReadEmbedded();
        var entry=Assembly.GetEntryAssembly();
        var root=Path.GetDirectoryName(Environment.ProcessPath)??"";
        var prefix=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ClaudeCodeProtection-Update-");
        if(approval.WorkerId!=serviceId || entry?.GetName().Name!=Asset || !root.StartsWith(prefix,StringComparison.OrdinalIgnoreCase) ||
            Identifiers.Hex32(root[prefix.Length..]).Length!=32 ||
            !string.Equals(Environment.ProcessPath,Path.Combine(root,Asset+".exe"),StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(entry.Location,Path.Combine(root,Asset+".dll"),StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(typeof(SessionZeroClosedCreatorRecovery).Assembly.Location,Path.Combine(root,"ProtectionLifecycle.dll"),StringComparison.OrdinalIgnoreCase))
            throw WfpNative.Contract("ClosedCreatorRecoveryWorkerImageMismatch");
        return approval;
    }

    internal static void RunWorker(Approval approval,SecurityIdentifier sid)
    {
        using var handle=SessionZeroCreatorClient.OpenOwnerPipeHandle(approval.WorkerId);
        SessionZeroCreatorClient.AssertOwnerPipe(KernelJobSeal.ReadCreatorPipeDescriptor(handle),sid);
        var peer=SessionZeroCreatorClient.ReadServerPeer(handle);
        using var pipe=new NamedPipeClientStream(PipeDirection.InOut,true,true,handle);
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var cancel=deadline.Token;
        var request=SessionZeroCreatorChannel.ParseRequest(ReadFrame(pipe,SessionZeroCreatorChannel.RequestSize,cancel),approval.WorkerId,peer.Pid,peer.Session);
        if(request.InstallationId!=approval.InstallationId || SessionZeroCreatorClient.ReadServerPeer(handle)!=peer)
            throw WfpNative.Contract("ClosedCreatorRecoveryOwnerChanged");
        var identity=SessionZeroCreatorChannel.ParseProfileCreated(ReadFrame(pipe,SessionZeroCreatorChannel.ProfileReplySize,cancel),request.Nonce);
        using var package=InstallationPackageSid.FromInstallationId(request.InstallationId);
        using var parent=WindowsPathSeal.LockCreatorProfileParent(SessionZeroCreatorProfile.StorageParentPath(requireLocalService:true));
        var storage=WindowsPathSeal.Child(parent.Path,package.Name);
        if(parent.ObjectIdentity()!=identity.ParentIdentity)throw WfpNative.Contract("ClosedCreatorRecoveryProfileParentChanged");
        SessionZeroCreatorProfile.AssertExistingStorage(package,storage,identity.StorageIdentity);
        Send(pipe,SessionZeroCreatorChannel.CreateProfileRecorded(request.Nonce),cancel);
        SessionZeroCreatorTerminal.AssertCloseFrame(ReadFrame(pipe,SessionZeroCreatorTerminal.CloseSize,cancel),request.Nonce);
        approval.AssertFresh();
        if(SessionZeroCreatorClient.ReadServerPeer(handle)!=peer || parent.ObjectIdentity()!=identity.ParentIdentity)
            throw WfpNative.Contract("ClosedCreatorRecoveryOwnerOrParentChanged");
        SessionZeroCreatorProfile.DeleteVerifiedStorage(package,storage,identity.StorageIdentity);
        parent.AssertHeld();
        Send(pipe,SessionZeroCreatorTerminal.CleanedFrame(request.Nonce),cancel);
    }

    internal static string Recover(BootstrapApproval bootstrap,Action<string> reportStage)
    {
        ProtectedState.RequireAdministrator();
        var approval=ReadEmbedded();
        var layout=FixedLayout.FromWindows();
        using var state=ProtectedState.OpenExisting(layout);
        using var version=VerifiedVersion.Open(layout,state,Release);
        var pointer=state.Read("current.json",4096);
        var current=CurrentPointer.Parse(pointer,state.InstallationId);
        if(state.InstallationId!=approval.InstallationId || current.Release!=Release || current.ManifestSHA256!=Manifest ||
            version.Package.ManifestHash!=Manifest)
            throw WfpNative.Contract("ClosedCreatorRecoveryRequiresExactInactiveInstallation");
        var job=OwnedJobIntent.Read(state,approval.JobId);
        var original=ReadOriginal(state,job);
        if(original.FailedRunSHA256!=approval.FailedRunSHA256 || state.ReadOptional(AttemptLeaf(job.JobId)) is not null ||
            state.ReadOptional(ProfileLeaf(job.JobId)) is not null ||
            state.ReadOptional(ReceiptLeaf(job.JobId)) is not null)
            throw WfpNative.Contract("ClosedCreatorRecoveryOutsideFreshApproval");
        LifecycleRecovery.AssertNoPending(state,recoveringCreator:job);
        InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var other in OwnedJobIntent.ReadAll(state))
            if(other.JobId!=job.JobId && !SessionZeroCreatorRecovery.IsAdmissionResolved(state,other))
                throw WfpNative.Contract("ClosedCreatorRecoveryOtherAdmissionUnresolved");
        var plans=FencePlan.ReadAll(state);
        if(plans.Count==0)throw WfpNative.Contract("ClosedCreatorRecoveryRequiresQuarantine");
        var fences=new List<PersistentFence>();
        try
        {
            foreach(var plan in plans)fences.Add(PersistentFence.OpenExisting(state,plan.Data.FenceId));
            using var stopped=SessionZeroCreatorRegistration.HoldForRecovery(job,
                WindowsPathSeal.Child(layout.Version(Release),"bin/admin/ProtectionBroker.exe"),OriginalStop);
            var programFiles=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            using var workspaceParent=WindowsPathSeal.LockDirectory(programFiles,PathPolicy.CreationParent);
            using var package=InstallationPackageSid.FromInstallationId(state.InstallationId);
            var workspace=SessionTaskWorkspace.PathFor(job.JobId,programFiles);
            var view=OfflineConsoleStorage.Resolve(workspace,package.Name);
            var expected=new HashSet<string>([view.Base,view.Packages,view.Package,view.LocalData,view.Temp],StringComparer.Ordinal);
            var profileParentPath=SessionZeroCreatorProfile.StorageParentPath(requireLocalService:false);
            if(!profileParentPath.StartsWith(@"C:\Windows\",StringComparison.OrdinalIgnoreCase))
                throw WfpNative.Contract("ClosedCreatorRecoveryVolumeMismatch");
            using var profileParent=WindowsPathSeal.LockCreatorProfileParent(profileParentPath);
            var profile=WindowsPathSeal.Child(profileParent.Path,package.Name);
            reportStage("VERIFY_ORIGINAL_OBJECTS");
            using var profileRoot=WindowsPathSeal.LockDirectory(profile,PathPolicy.Source);
            var identity=new SessionZeroCreatorChannel.CreatedProfile(profileParent.ObjectIdentity(),profileRoot.ObjectIdentity());
            AssertBeforeMutation();
            SessionTaskWorkspace.AssertExactEmptyTree(state,workspace,original.WorkspaceIdentity,job.CreatorServiceSid!,package.Value,expected);
            if(CreatorProfileLineage.Observe(package.Name,identity.ParentIdentity,identity.StorageIdentity,
                approval.WindowStartUtc.ToFileTime(),approval.WindowEndUtc.ToFileTime())!=CreatorProfileLineage.Evidence.Match)
                throw WfpNative.Contract("ClosedCreatorRecoveryLineageUnconfirmed");
            profileRoot.AssertHeld();
            SessionZeroCreatorRegistration.AssertRecoveryRegistrationAbsent(approval.WorkerId);
            if(!ProcessIdToSessionId((uint)Environment.ProcessId,out var ownerSession) || ownerSession==0)
                throw WfpNative.Contract("ClosedCreatorRecoveryOwnerSessionUnconfirmed");
            AssertBeforeMutation();
            var attempt=state.WriteNew(AttemptLeaf(job.JobId),JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,state.InstallationId,job.JobId,approval.WorkerId,Original=original,
                identity.ParentIdentity,identity.StorageIdentity,Status="CLOSED_CREATOR_RECOVERY_STARTED"
            }));
            reportStage("START_PROFILE_RECOVERY_WORKER");
            var workerImage=Environment.ProcessPath!;
            using var worker=SessionZeroCreatorRegistration.ProfileRecoveryWorker.Register(approval.WorkerId,workerImage);
            var name=SessionZeroCreatorChannel.NameForJob(approval.WorkerId);
            var sid=(SecurityIdentifier)new NTAccount("NT SERVICE",name).Translate(typeof(SecurityIdentifier));
            using var pipe=SessionZeroCreatorChannel.CreateOwnerPipe(name,sid);
            AssertAttempt();
            var process=worker.StartAndHold();
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var cancel=deadline.Token;
            pipe.WaitForConnectionAsync(cancel).GetAwaiter().GetResult();
            var nonce=RandomNumberGenerator.GetBytes(16);
            AssertWorkerPeer();
            Send(pipe,SessionZeroCreatorChannel.CreateRequest(nonce,state.InstallationId,approval.WorkerId,(uint)Environment.ProcessId,ownerSession),cancel);
            Send(pipe,SessionZeroCreatorChannel.CreateProfileCreated(new(state.InstallationId,approval.WorkerId,nonce),identity),cancel);
            SessionZeroCreatorChannel.AssertProfileRecorded(ReadFrame(pipe,SessionZeroCreatorChannel.ProfileRecordedSize,cancel),nonce);
            AssertWorkerPeer();
            AssertAttempt();
            profileRoot.AssertHeld();
            profileRoot.Dispose(); // The per-user delete API must not run with our profile storage handles open.
            reportStage("REMOVE_VERIFIED_PROFILE");
            Send(pipe,SessionZeroCreatorTerminal.CloseFrame(nonce),cancel);
            SessionZeroCreatorTerminal.ReadCleaned(pipe,nonce,cancel);
            AssertProfileAbsent();
            AssertAttempt();
            var profileProof=state.WriteNew(ProfileLeaf(job.JobId),JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,state.InstallationId,job.JobId,approval.WorkerId,AttemptSHA256=attempt,
                Status="LOCAL_SERVICE_DELETE_AND_MAPPING_AND_STORAGE_READBACK"
            }));
            worker.RemoveAfterSuccess();
            reportStage("REMOVE_ORIGINAL_WORKSPACE");
            var removed=0;
            SessionTaskWorkspace.DeleteExactTree(state,workspace,original.WorkspaceIdentity,job.CreatorServiceSid!,package.Value,AssertAfterProfile,ref removed,
                allowAlreadyAbsent:false,expectedEmptyDirectories:expected);
            if(removed!=expected.Count+1)throw WfpNative.Contract("ClosedCreatorRecoveryWorkspaceRemovalUnconfirmed");
            AssertAfterProfile();
            reportStage("REMOVE_ORIGINAL_REGISTRATION");
            stopped.Remove();
            AssertProfileAbsent();
            AssertTerminal(state,job,approval.WorkerId,original);
            AssertAuthority();
            if(state.Read(AttemptLeaf(job.JobId),8192).SHA256!=attempt || state.Read(ProfileLeaf(job.JobId),4096).SHA256!=profileProof)
                throw WfpNative.Contract("ClosedCreatorRecoveryAttemptChanged");
            return PublishReceipt(state,job,approval.WorkerId,attempt,profileProof);

            void AssertAuthority()
            {
                approval.AssertFresh();bootstrap.AssertHeld();version.AssertHeld(state);
                if(state.Read("current.json",4096).SHA256!=pointer.SHA256 || ReadOriginal(state,job)!=original ||
                    workspaceParent.ObjectIdentity()!=original.WorkspaceParentIdentity || profileParent.ObjectIdentity()!=identity.ParentIdentity ||
                    !FencePlan.ReadAll(state).Select(p=>p.Data.FenceId).SequenceEqual(plans.Select(p=>p.Data.FenceId)) ||
                    fences.Any(f=>!f.Observe().FullQuarantineObserved))
                    throw WfpNative.Contract("ClosedCreatorRecoveryAuthorityChanged");
            }
            void AssertBeforeMutation()
            {
                AssertAuthority();
                OwnedKernelJob.AssertCreatorNameAbsent(job);
                stopped.AssertStoppedWithoutStart();
            }
            void AssertWorkerPeer()
            {
                SessionZeroCreatorChannel.AssertServicePeer(pipe.SafePipeHandle,process,ownerSession);
                SessionZeroCreatorChannel.AssertImage(process,workerImage);
            }
            void AssertAttempt()
            {
                AssertBeforeMutation();
                if(state.Read(AttemptLeaf(job.JobId),8192).SHA256!=attempt)
                    throw WfpNative.Contract("ClosedCreatorRecoveryAttemptChanged");
            }
            void AssertProfileAbsent()
            {
                profileParent.AssertHeld();
                AssertDirectoryAbsent(profile,"ClosedCreatorRecoveryProfileStoragePresent");
            }
            void AssertAfterProfile()
            {
                AssertAttempt();
                AssertProfileAbsent();
                if(state.Read(ProfileLeaf(job.JobId),4096).SHA256!=profileProof)
                    throw WfpNative.Contract("ClosedCreatorRecoveryProfileProofChanged");
                SessionZeroCreatorRegistration.AssertRecoveryRegistrationAbsent(approval.WorkerId);
            }
        }
        finally{foreach(var fence in fences)fence.Dispose();}
    }

    internal static string ReceiptLeaf(string id)=>"creator-closed-recovered-"+Identifiers.Hex32(id)+".json";
    private static string AttemptLeaf(string id)=>"creator-closed-recovery-attempt-"+Identifiers.Hex32(id)+".json";
    private static string ProfileLeaf(string id)=>"creator-closed-recovery-profile-"+Identifiers.Hex32(id)+".json";

    internal static bool ReadRecovered(ProtectedState state,OwnedJobIntent job)
    {
        var raw=state.ReadOptional(ReceiptLeaf(job.JobId));
        if(raw is null)return false;
        var original=ReadOriginal(state,job);
        using var receipt=Read(raw);
        var r=receipt.RootElement;
        StrictJson.Fields(r,"SchemaVersion","InstallationId","JobId","WorkerId","AttemptSHA256","ProfileSHA256","Status");
        AssertBinding(r,job);
        var workerId=Identifiers.Hex32(StrictJson.Text(r,"WorkerId"));
        if(workerId==job.JobId || StrictJson.Text(r,"Status")!=Disposition ||
            !ReadProgress(state,job,workerId,original).Matches(StrictJson.Text(r,"AttemptSHA256"),StrictJson.Text(r,"ProfileSHA256")))
            throw WfpNative.Contract("ClosedCreatorRecoveryReceiptMismatch");
        AssertTerminal(state,job,workerId,original);
        return true;
    }

    private sealed record Progress(string AttemptSHA256,string ProfileSHA256,string ParentIdentity)
    {
        internal bool Matches(string attempt,string profile)=>AttemptSHA256==attempt && ProfileSHA256==profile;
    }

    private static Progress ReadProgress(ProtectedState state,OwnedJobIntent job,string workerId,Original original)
    {
        var attempt=state.Read(AttemptLeaf(job.JobId),8192);
        var profile=state.Read(ProfileLeaf(job.JobId),4096);
        using var closedProfile=Read(profile);
        var p=closedProfile.RootElement;
        StrictJson.Fields(p,"SchemaVersion","InstallationId","JobId","WorkerId","AttemptSHA256","Status");
        AssertBinding(p,job);
        if(StrictJson.Text(p,"WorkerId")!=workerId || StrictJson.Text(p,"AttemptSHA256")!=attempt.SHA256 ||
            StrictJson.Text(p,"Status")!="LOCAL_SERVICE_DELETE_AND_MAPPING_AND_STORAGE_READBACK")
            throw WfpNative.Contract("ClosedCreatorRecoveryProfileProofMismatch");
        using var started=Read(attempt);
        var a=started.RootElement;
        StrictJson.Fields(a,"SchemaVersion","InstallationId","JobId","WorkerId","Original","ParentIdentity","StorageIdentity","Status");
        AssertBinding(a,job);
        if(StrictJson.Text(a,"Status")!="CLOSED_CREATOR_RECOVERY_STARTED" || StrictJson.Text(a,"WorkerId")!=workerId ||
            a.GetProperty("Original").Deserialize<Original>()!=original)
            throw WfpNative.Contract("ClosedCreatorRecoveryAttemptMismatch");
        var parent=StrictJson.Text(a,"ParentIdentity");
        SessionZeroCreatorChannel.AssertProfileIdentity(new(parent,StrictJson.Text(a,"StorageIdentity")));
        return new(attempt.SHA256,profile.SHA256,parent);
    }

    // The original owner already confirmed LocalService deletion, mapping
    // and disk readback. Complete a lost final receipt only from that durable
    // proof and fresh absence checks, without repeating any deletion.
    internal static string FinalizeClosed(BootstrapApproval bootstrap)
    {
        ProtectedState.RequireAdministrator();
        var approval=ReadEmbedded();
        var layout=FixedLayout.FromWindows();
        using var state=ProtectedState.OpenExisting(layout);
        using var version=VerifiedVersion.Open(layout,state,Release);
        var pointer=state.Read("current.json",4096);
        var current=CurrentPointer.Parse(pointer,state.InstallationId);
        if(state.InstallationId!=approval.InstallationId || current.Release!=Release || current.ManifestSHA256!=Manifest ||
            version.Package.ManifestHash!=Manifest)
            throw WfpNative.Contract("ClosedCreatorFinalizationRequiresExactInactiveInstallation");
        var job=OwnedJobIntent.Read(state,approval.JobId);
        var original=ReadOriginal(state,job);
        if(original.FailedRunSHA256!=approval.FailedRunSHA256 || state.ReadOptional(ReceiptLeaf(job.JobId)) is not null)
            throw WfpNative.Contract("ClosedCreatorFinalizationOutsideFreshApproval");
        LifecycleRecovery.AssertNoPending(state,recoveringCreator:job);
        InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var other in OwnedJobIntent.ReadAll(state))
            if(other.JobId!=job.JobId && !SessionZeroCreatorRecovery.IsAdmissionResolved(state,other))
                throw WfpNative.Contract("ClosedCreatorFinalizationOtherAdmissionUnresolved");
        var plans=FencePlan.ReadAll(state);
        if(plans.Count==0)throw WfpNative.Contract("ClosedCreatorFinalizationRequiresQuarantine");
        var fences=new List<PersistentFence>();
        try
        {
            foreach(var plan in plans)fences.Add(PersistentFence.OpenExisting(state,plan.Data.FenceId));
            var progress=ReadProgress(state,job,approval.WorkerId,original);
            using var profileParent=WindowsPathSeal.LockCreatorProfileParent(SessionZeroCreatorProfile.StorageParentPath(requireLocalService:false));
            using var package=InstallationPackageSid.FromInstallationId(state.InstallationId);
            var profile=WindowsPathSeal.Child(profileParent.Path,package.Name);
            AssertTerminal(state,job,approval.WorkerId,original);
            AssertDirectoryAbsent(profile,"ClosedCreatorFinalizationProfileStoragePresent");
            approval.AssertFresh();bootstrap.AssertHeld();version.AssertHeld(state);
            if(state.Read("current.json",4096).SHA256!=pointer.SHA256 || ReadOriginal(state,job)!=original ||
                ReadProgress(state,job,approval.WorkerId,original)!=progress || profileParent.ObjectIdentity()!=progress.ParentIdentity ||
                !FencePlan.ReadAll(state).Select(p=>p.Data.FenceId).SequenceEqual(plans.Select(p=>p.Data.FenceId)) ||
                fences.Any(f=>!f.Observe().FullQuarantineObserved))
                throw WfpNative.Contract("ClosedCreatorFinalizationAuthorityChanged");
            AssertTerminal(state,job,approval.WorkerId,original);
            AssertDirectoryAbsent(profile,"ClosedCreatorFinalizationProfileStoragePresent");
            return PublishReceipt(state,job,approval.WorkerId,progress.AttemptSHA256,progress.ProfileSHA256);
        }
        finally{foreach(var fence in fences)fence.Dispose();}
    }

    private static string PublishReceipt(ProtectedState state,OwnedJobIntent job,string workerId,string attempt,string profile)
    {
        var result=state.WriteNew(ReceiptLeaf(job.JobId),JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,state.InstallationId,job.JobId,WorkerId=workerId,AttemptSHA256=attempt,ProfileSHA256=profile,Status=Disposition
        }));
        if(!ReadRecovered(state,job))throw WfpNative.Contract("ClosedCreatorRecoveryReceiptReadbackMissing");
        return result;
    }

    private static Original ReadOriginal(ProtectedState state,OwnedJobIntent job)
    {
        var id=job.JobId;
        if(job.CreatorServiceSid is null || job.Release!=Release || job.ManifestSHA256!=Manifest || OwnedJobIntent.Read(state,id)!=job)
            throw WfpNative.Contract("ClosedCreatorRecoveryOriginalScopeMismatch");
        foreach(var prefix in new[]{"admission-before-resume-","creator-service-removed-","creator-service-startup-failed-",
            "creator-profile-created-","creator-profile-closed-","creator-workspace-cleanup-","creator-workspace-closed-"})
            if(state.ReadOptional(prefix+id+".json") is not null)throw WfpNative.Contract("ClosedCreatorRecoveryOriginalHistoryConflict");
        if(AtomicJobCompletion.ReadClosed(state,job) is null)throw WfpNative.Contract("ClosedCreatorRecoveryOriginalJobNotClosed");
        var completion=state.Read("job-completed-"+id+".json",8192);
        var jobIntent=state.Read(OwnedJobIntent.Leaf(id),8192);
        var created=state.Read("job-creator-confirmed-"+id+".json",4096);
        using(var doc=Read(created))OwnedKernelJob.ValidateCreatorProof(doc.RootElement,jobIntent.SHA256);
        var service=state.Read(SessionZeroCreatorRegistration.IntentPrefix+id+".json",4096);
        using(var doc=Read(service))
        {
            var r=doc.RootElement;
            SessionZeroCreatorRegistration.ValidateIntent(r,job.InstallationId,id);
            if(StrictJson.Text(r,"Release")!=Release || StrictJson.Text(r,"ManifestHash")!=Manifest)
                throw WfpNative.Contract("ClosedCreatorRecoveryOriginalServiceVersionMismatch");
        }
        var start=state.Read("creator-service-start-"+id+".json",4096);
        SessionZeroCreatorRegistration.ValidateStartProof(start.Bytes,service.SHA256);
        var workspaceIntent=state.Read("creator-workspace-intent-"+id+".json",4096);
        var workspaceCreated=state.Read("creator-workspace-created-"+id+".json",4096);
        using var wi=Read(workspaceIntent);using var wc=Read(workspaceCreated);
        StrictJson.Fields(wi.RootElement,"SchemaVersion","InstallationId","JobId","CreatorSid","PackageSid","ParentIdentity");
        StrictJson.Fields(wc.RootElement,"SchemaVersion","InstallationId","JobId","WorkspaceIdentity");
        AssertBinding(wi.RootElement,job);AssertBinding(wc.RootElement,job);
        using var package=InstallationPackageSid.FromInstallationId(state.InstallationId);
        if(StrictJson.Text(wi.RootElement,"CreatorSid")!=job.CreatorServiceSid || StrictJson.Text(wi.RootElement,"PackageSid")!=package.Value)
            throw WfpNative.Contract("ClosedCreatorRecoveryWorkspaceAudienceMismatch");
        var failed=state.Read("independent-offline-console-after-"+id+".json",8192);
        ValidateFailedRun(failed.Bytes,job);
        return new(jobIntent.SHA256,created.SHA256,completion.SHA256,service.SHA256,start.SHA256,workspaceIntent.SHA256,workspaceCreated.SHA256,failed.SHA256,
            Identifiers.ObjectIdentity(StrictJson.Text(wi.RootElement,"ParentIdentity")),
            Identifiers.ObjectIdentity(StrictJson.Text(wc.RootElement,"WorkspaceIdentity")),package.Value);
    }

    internal static void ValidateFailedRun(byte[] bytes,OwnedJobIntent job)
    {
        using var doc=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=6});
        var r=doc.RootElement;
        StrictJson.Fields(r,"SchemaVersion","Scope","InstallationId","JobId","Release","ManifestHash","Status","LastStage","ProcessResumed",
            "ChildExit","OriginalJobClosed","ProfileClosed","WorkspaceClosed","ServiceRemoved","StartupFailureRegistrationRemoved","FilesMatched",
            "StreamsMatched","HostIdentityObservation","HostAccountSidDiffers","HostIdentityQualified","Output","Error","ChildFailure","EnvironmentProjection",
            "StopObservation","Failures","GatewayOpened","NetworkQualified","LaunchAuthorized","FormalAdmissionIssued","ClaudeLaunched");
        AssertBinding(r,job);
        if(StrictJson.Text(r,"Scope")!="INSTALLED_FIXED_INDEPENDENT_OFFLINE_CONSOLE" ||
            StrictJson.Text(r,"Status")!="INDEPENDENT_OFFLINE_CONSOLE_NOT_CONFIRMED" || StrictJson.Text(r,"LastStage")!="CloseCreatorProfile" ||
            StrictJson.Text(r,"Release")!=job.Release || StrictJson.Text(r,"ManifestHash")!=job.ManifestSHA256 ||
            r.GetProperty("OriginalJobClosed").ValueKind!=JsonValueKind.True)
            throw WfpNative.Contract("ClosedCreatorRecoveryFailedRunMismatch");
        foreach(var field in new[]{"ProcessResumed","ProfileClosed","WorkspaceClosed","ServiceRemoved","StartupFailureRegistrationRemoved",
            "FilesMatched","StreamsMatched","HostAccountSidDiffers","HostIdentityQualified","GatewayOpened","NetworkQualified",
            "LaunchAuthorized","FormalAdmissionIssued","ClaudeLaunched"})
            if(r.GetProperty(field).ValueKind!=JsonValueKind.False)throw WfpNative.Contract("ClosedCreatorRecoveryFailedRunConflictingFlag");
        foreach(var field in new[]{"ChildExit","HostIdentityObservation","Output","Error","ChildFailure","EnvironmentProjection","StopObservation"})
            if(r.GetProperty(field).ValueKind!=JsonValueKind.Null)throw WfpNative.Contract("ClosedCreatorRecoveryFailedRunConflictingObservation");
        var failures=r.GetProperty("Failures");
        if(failures.GetArrayLength()!=2)throw WfpNative.Contract("ClosedCreatorRecoveryFailedRunFailureCount");
        AssertFailure(failures[0],"Win32Exception",5,"AtomicOpenCreatedToken");
        AssertFailure(failures[1],"InvalidDataException",0x80131501,"CreatorProfileCleanupChannelUnavailable");

        static void AssertFailure(JsonElement value,string type,uint code,string stage)
        {
            StrictJson.Fields(value,"Type","Code","Stage");
            if(StrictJson.Text(value,"Type")!=type || value.GetProperty("Code").GetUInt32()!=code || StrictJson.Text(value,"Stage")!=stage)
                throw WfpNative.Contract("ClosedCreatorRecoveryFailedRunFailureMismatch");
        }
    }

    private static void AssertTerminal(ProtectedState state,OwnedJobIntent job,string workerId,Original original)
    {
        state.AssertHeld();
        OwnedKernelJob.AssertCreatorNameAbsent(job);
        SessionZeroCreatorRegistration.AssertRecoveryRegistrationAbsent(job.JobId);
        SessionZeroCreatorRegistration.AssertRecoveryRegistrationAbsent(workerId);
        var programFiles=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        using var parent=WindowsPathSeal.LockDirectory(programFiles,PathPolicy.CreationParent);
        if(parent.ObjectIdentity()!=original.WorkspaceParentIdentity)
            throw WfpNative.Contract("ClosedCreatorRecoveryWorkspaceParentChanged");
        AssertDirectoryAbsent(SessionTaskWorkspace.PathFor(job.JobId,programFiles),"ClosedCreatorRecoveryWorkspaceStillPresent");
    }

    private static void AssertDirectoryAbsent(string path,string failure)
    {
        try{using var present=WindowsPathSeal.Open(path,true,false);throw WfpNative.Contract(failure);}
        catch(ExactPathAbsentException error)when(string.Equals(error.FailedPath,path,StringComparison.OrdinalIgnoreCase)){}
    }

    private static void AssertBinding(JsonElement r,OwnedJobIntent job)
    {
        if(r.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(r,"InstallationId")!=job.InstallationId ||
            StrictJson.Text(r,"JobId")!=job.JobId)throw WfpNative.Contract("ClosedCreatorRecoveryRecordMismatch");
    }

    private static byte[] ReadFrame(Stream stream,int size,CancellationToken cancel)
    {
        var frame=new byte[size];
        stream.ReadExactlyAsync(frame.AsMemory(),cancel).AsTask().GetAwaiter().GetResult();
        return frame;
    }
    private static void Send(Stream stream,byte[] frame,CancellationToken cancel)=>
        stream.WriteAsync(frame.AsMemory(),cancel).AsTask().GetAwaiter().GetResult();
    private static JsonDocument Read(BoundBytes raw)=>JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=4});

    [System.Runtime.InteropServices.DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]
    [return:System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool ProcessIdToSessionId(uint pid,out uint session);
}
