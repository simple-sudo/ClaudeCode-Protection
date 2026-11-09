using System.Text.Json;

namespace ProtectionLifecycle;

// Recovery of the reviewed predecessor that registered its Job and workspace
// before it could establish the creator process. Keep this proof distinct from
// the completion of a Job that actually received admission authority.
internal static class SessionZeroCreatorRecovery
{
    internal const string Release="7df61706780c433f9dc5e7ddf5bc6f28";
    internal const string Manifest="F56348EC6A43DF01D6E79C8F019D08798B7F98B11D961D9FE58BF5690A41232B";
    private const string Disposition="LEGACY_CREATOR_RETIRED_WITHOUT_ADMISSION";
    private const string Planned="LEGACY_CREATOR_RECOVERY_STARTED";

    internal sealed record Evidence(string JobIntentSHA256,string JobCreatedSHA256,string ServiceIntentSHA256,string ServiceStartSHA256,
        string WorkspaceIntentSHA256,string WorkspaceCreatedSHA256,string FailedRunSHA256);
    internal sealed record Original(Evidence Evidence,string ParentIdentity,string WorkspaceIdentity,string PackageSid);
    internal sealed record Approval(string InstallationId,string JobId,string FailedRunSHA256,DateTimeOffset ExpiresUtc)
    {
        internal static Approval Read(Stream stream)
        {
            if(stream.Length is <1 or >4096)throw WfpNative.Contract("LegacyCreatorRecoveryApprovalSize");
            using var doc=JsonDocument.Parse(stream,new JsonDocumentOptions{MaxDepth=2});
            var r=doc.RootElement;
            StrictJson.Fields(r,"SchemaVersion","InstallationId","JobId","FailedRunSHA256","ExpiresUtc");
            var expires=r.GetProperty("ExpiresUtc").GetDateTimeOffset();
            if(r.GetProperty("SchemaVersion").GetInt32()!=1 || expires.Offset!=TimeSpan.Zero || expires<=DateTimeOffset.UtcNow)
                throw WfpNative.Contract("LegacyCreatorRecoveryApprovalExpiredOrInvalid");
            return new(Identifiers.Hex32(StrictJson.Text(r,"InstallationId")),Identifiers.Hex32(StrictJson.Text(r,"JobId")),
                Identifiers.Hash(StrictJson.Text(r,"FailedRunSHA256")),expires);
        }
    }

    internal static string ReceiptLeaf(string id)=>"creator-never-admitted-retired-"+Identifiers.Hex32(id)+".json";
    private static string AttemptLeaf(string id)=>"creator-never-admitted-attempt-"+Identifiers.Hex32(id)+".json";

    internal static string Recover(ProtectedState state,VerifiedVersion prior,Approval approval,Action<string> reportStage)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();prior.AssertHeld(state);
        if(state.InstallationId!=approval.InstallationId || prior.Package.Release!=Release || prior.Package.ManifestHash!=Manifest)
            throw WfpNative.Contract("LegacyCreatorRecoveryRequiresExactInactiveInstallation");
        var pointer=state.Read("current.json",4096);
        var current=CurrentPointer.Parse(pointer,state.InstallationId);
        if(current.Release!=Release || current.ManifestSHA256!=Manifest)
            throw WfpNative.Contract("LegacyCreatorRecoveryRequiresExactInactiveInstallation");
        var job=OwnedJobIntent.Read(state,approval.JobId);
        reportStage("READ_ORIGINAL_LEDGERS");
        var original=ReadOriginal(state,job);
        if(original.Evidence.FailedRunSHA256!=approval.FailedRunSHA256 || state.ReadOptional(AttemptLeaf(job.JobId)) is not null ||
            state.ReadOptional(ReceiptLeaf(job.JobId)) is not null)
            throw WfpNative.Contract("LegacyCreatorRecoveryOutsideFreshApproval");
        LifecycleRecovery.AssertNoPending(state,recoveringCreator:job);
        InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var other in OwnedJobIntent.ReadAll(state))
            if(other.JobId!=job.JobId && !IsAdmissionResolved(state,other))throw WfpNative.Contract("LegacyCreatorOtherAdmissionUnresolved");
        var plans=FencePlan.ReadAll(state);
        if(plans.Count==0)throw WfpNative.Contract("LegacyCreatorRecoveryRequiresQuarantine");
        var fences=new List<PersistentFence>();
        try
        {
            foreach(var plan in plans)fences.Add(PersistentFence.OpenExisting(state,plan.Data.FenceId));
            var programFiles=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            using var parent=WindowsPathSeal.LockDirectory(programFiles,PathPolicy.CreationParent);
            var workspace=SessionTaskWorkspace.PathFor(job.JobId,programFiles);
            using var package=InstallationPackageSid.FromInstallationId(state.InstallationId);
            var view=OfflineConsoleStorage.Resolve(workspace,package.Name);
            var expectedDirectories=new HashSet<string>([view.Base,view.Packages,view.Package,view.LocalData,view.Temp],StringComparer.Ordinal);
            reportStage("HOLD_STOPPED_SERVICE");
            var layout=FixedLayout.FromWindows();
            using var service=SessionZeroCreatorRegistration.HoldForRecovery(job,WindowsPathSeal.Child(layout.Version(Release),"bin/admin/ProtectionBroker.exe"));
            string? attemptHash=null;
            void AssertBeforeMutation()
            {
                prior.AssertHeld(state);parent.AssertHeld();
                if(DateTimeOffset.UtcNow>=approval.ExpiresUtc || state.Read("current.json",4096).SHA256!=pointer.SHA256 ||
                    parent.ObjectIdentity()!=original.ParentIdentity || ReadOriginal(state,job)!=original ||
                    !FencePlan.ReadAll(state).Select(p=>p.Data.FenceId).SequenceEqual(plans.Select(p=>p.Data.FenceId)) ||
                    fences.Any(f=>!f.Observe().FullQuarantineObserved))
                    throw WfpNative.Contract("LegacyCreatorRecoveryAuthorityChanged");
                OwnedKernelJob.AssertCreatorNameAbsent(job);
                service.AssertStoppedWithoutStart();
                if(attemptHash is not null && state.Read(AttemptLeaf(job.JobId),8192).SHA256!=attemptHash)
                    throw WfpNative.Contract("LegacyCreatorRecoveryAttemptChanged");
            }
            AssertBeforeMutation();
            reportStage("VERIFY_WORKSPACE_INVENTORY");
            var removed=0;
            SessionTaskWorkspace.DeleteExactTree(state,workspace,original.WorkspaceIdentity,job.CreatorServiceSid!,original.PackageSid,()=>
            {
                AssertBeforeMutation();
                if(attemptHash is not null)return;
                attemptHash=state.WriteNew(AttemptLeaf(job.JobId),JsonSerializer.SerializeToUtf8Bytes(new {
                    SchemaVersion=1,state.InstallationId,job.JobId,Status=Planned,Original=original.Evidence
                }));
                reportStage("REMOVE_FIXED_EMPTY_WORKSPACE");
            },ref removed,allowAlreadyAbsent:false,expectedEmptyDirectories:expectedDirectories);
            if(attemptHash is null || removed!=expectedDirectories.Count+1)throw WfpNative.Contract("LegacyCreatorWorkspaceRemovalUnconfirmed");
            AssertBeforeMutation();
            reportStage("REMOVE_STOPPED_SERVICE");
            service.Remove();
            reportStage("VERIFY_ABSENCE_AND_RECORD_RETIREMENT");
            AssertAbsent(state,job,original);
            if(ReadOriginal(state,job)!=original || state.Read("current.json",4096).SHA256!=pointer.SHA256 ||
                state.Read(AttemptLeaf(job.JobId),8192).SHA256!=attemptHash || fences.Any(f=>!f.Observe().FullQuarantineObserved))
                throw WfpNative.Contract("LegacyCreatorRecoveryReadbackChanged");
            var receiptHash=state.WriteNew(ReceiptLeaf(job.JobId),JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,state.InstallationId,job.JobId,Status=Disposition,AttemptSHA256=attemptHash,Original=original.Evidence
            }));
            if(!ReadRetired(state,job))throw WfpNative.Contract("LegacyCreatorRetirementReadbackMissing");
            return receiptHash;
        }
        finally{foreach(var fence in fences)fence.Dispose();}
    }

    internal static Original ReadOriginal(ProtectedState state,OwnedJobIntent job)
    {
        state.AssertHeld();
        if(job.InstallationId!=state.InstallationId || job.CreatorServiceSid is null || job.Release!=Release || job.ManifestSHA256!=Manifest ||
            OwnedJobIntent.Read(state,job.JobId)!=job)
            throw WfpNative.Contract("LegacyCreatorRecoveryScopeMismatch");
        var id=job.JobId;
        foreach(var prefix in new[]{"job-admission-","job-completed-","admission-before-resume-","creator-service-removed-",
            "creator-service-startup-failed-","creator-workspace-cleanup-","creator-workspace-closed-"})
            if(state.ReadOptional(prefix+id+".json") is not null)throw WfpNative.Contract("LegacyCreatorConflictingHistory");

        var intent=state.Read(OwnedJobIntent.Leaf(id),8192);
        var jobCreated=state.Read("job-creator-confirmed-"+id+".json",4096);
        using(var doc=Read(jobCreated))OwnedKernelJob.ValidateCreatorProof(doc.RootElement,intent.SHA256);
        var serviceIntent=state.Read(SessionZeroCreatorRegistration.IntentPrefix+id+".json",4096);
        using(var doc=Read(serviceIntent))
        {
            SessionZeroCreatorRegistration.ValidateIntent(doc.RootElement,state.InstallationId,id);
            if(StrictJson.Text(doc.RootElement,"Release")!=Release || StrictJson.Text(doc.RootElement,"ManifestHash")!=Manifest)
                throw WfpNative.Contract("LegacyCreatorServiceReleaseMismatch");
        }
        var serviceStart=state.Read("creator-service-start-"+id+".json",4096);
        SessionZeroCreatorRegistration.ValidateStartProof(serviceStart.Bytes,serviceIntent.SHA256);

        var workspaceIntent=state.Read("creator-workspace-intent-"+id+".json",4096);
        var workspaceCreated=state.Read("creator-workspace-created-"+id+".json",4096);
        using var wi=Read(workspaceIntent);
        using var wc=Read(workspaceCreated);
        StrictJson.Fields(wi.RootElement,"SchemaVersion","InstallationId","JobId","CreatorSid","PackageSid","ParentIdentity");
        StrictJson.Fields(wc.RootElement,"SchemaVersion","InstallationId","JobId","WorkspaceIdentity");
        AssertBinding(wi.RootElement,job);
        AssertBinding(wc.RootElement,job);
        using var package=InstallationPackageSid.FromInstallationId(state.InstallationId);
        if(StrictJson.Text(wi.RootElement,"CreatorSid")!=job.CreatorServiceSid || StrictJson.Text(wi.RootElement,"PackageSid")!=package.Value)
            throw WfpNative.Contract("LegacyCreatorWorkspaceAudienceMismatch");
        var failedRun=state.Read("independent-offline-console-after-"+id+".json",8192);
        ValidateFailedRun(failedRun.Bytes,job);
        return new(new(intent.SHA256,jobCreated.SHA256,serviceIntent.SHA256,serviceStart.SHA256,workspaceIntent.SHA256,workspaceCreated.SHA256,
            failedRun.SHA256),Identifiers.ObjectIdentity(StrictJson.Text(wi.RootElement,"ParentIdentity")),
            Identifiers.ObjectIdentity(StrictJson.Text(wc.RootElement,"WorkspaceIdentity")),package.Value);
    }

    internal static void ValidateFailedRun(byte[] bytes,OwnedJobIntent job)
    {
        using var doc=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=6});
        var r=doc.RootElement;
        StrictJson.Fields(r,"SchemaVersion","Scope","InstallationId","JobId","Release","ManifestHash","Status","LastStage","ProcessResumed",
            "ChildExit","OriginalJobClosed","ProfileClosed","WorkspaceClosed","ServiceRemoved","FilesMatched","StreamsMatched",
            "HostIdentityObservation","HostAccountSidDiffers","HostIdentityQualified","Output","Error","ChildFailure","EnvironmentProjection",
            "StopObservation","Failures","GatewayOpened","NetworkQualified","LaunchAuthorized","FormalAdmissionIssued","ClaudeLaunched");
        AssertBinding(r,job);
        if(StrictJson.Text(r,"Scope")!="INSTALLED_FIXED_INDEPENDENT_OFFLINE_CONSOLE" ||
            StrictJson.Text(r,"Status")!="INDEPENDENT_OFFLINE_CONSOLE_NOT_CONFIRMED" || StrictJson.Text(r,"LastStage")!="StartCreator" ||
            StrictJson.Text(r,"Release")!=job.Release || StrictJson.Text(r,"ManifestHash")!=job.ManifestSHA256)
            throw WfpNative.Contract("LegacyCreatorFailedRunMismatch");
        foreach(var field in new[]{"ProcessResumed","OriginalJobClosed","ProfileClosed","WorkspaceClosed","ServiceRemoved","FilesMatched",
            "StreamsMatched","HostAccountSidDiffers","HostIdentityQualified","GatewayOpened","NetworkQualified","LaunchAuthorized",
            "FormalAdmissionIssued","ClaudeLaunched"})
            if(r.GetProperty(field).ValueKind!=JsonValueKind.False)throw WfpNative.Contract("LegacyCreatorFailedRunConflictingFlag");
        foreach(var field in new[]{"ChildExit","HostIdentityObservation","Output","Error","ChildFailure","EnvironmentProjection","StopObservation"})
            if(r.GetProperty(field).ValueKind!=JsonValueKind.Null)throw WfpNative.Contract("LegacyCreatorFailedRunConflictingObservation");
        var failures=r.GetProperty("Failures");
        if(failures.GetArrayLength()!=1)throw WfpNative.Contract("LegacyCreatorFailureCountMismatch");
        var failure=failures[0];
        StrictJson.Fields(failure,"Type","Code","Stage");
        if(StrictJson.Text(failure,"Type")!="Win32Exception" || failure.GetProperty("Code").GetUInt32()!=0x80131501u ||
            failure.GetProperty("Stage").ValueKind!=JsonValueKind.Null)
            throw WfpNative.Contract("LegacyCreatorFailureCodeMismatch");
    }

    internal static bool ReadRetired(ProtectedState state,OwnedJobIntent job)
    {
        var raw=state.ReadOptional(ReceiptLeaf(job.JobId));
        if(raw is null)return false;
        var original=ReadOriginal(state,job);
        using var doc=Read(raw);
        var record=doc.RootElement;
        StrictJson.Fields(record,"SchemaVersion","InstallationId","JobId","Status","Original","AttemptSHA256");
        AssertRecord(record,job,original.Evidence,Disposition);
        var attempt=state.Read(AttemptLeaf(job.JobId),8192);
        if(attempt.SHA256!=StrictJson.Text(record,"AttemptSHA256"))throw WfpNative.Contract("LegacyCreatorRetirementAttemptMismatch");
        using var attemptDoc=Read(attempt);
        StrictJson.Fields(attemptDoc.RootElement,"SchemaVersion","InstallationId","JobId","Status","Original");
        AssertRecord(attemptDoc.RootElement,job,original.Evidence,Planned);
        AssertAbsent(state,job,original);
        return true;
    }

    private static void AssertRecord(JsonElement record,OwnedJobIntent job,Evidence expected,string status)
    {
        AssertBinding(record,job);
        var evidence=record.GetProperty("Original");
        StrictJson.Fields(evidence,"JobIntentSHA256","JobCreatedSHA256","ServiceIntentSHA256","ServiceStartSHA256","WorkspaceIntentSHA256",
            "WorkspaceCreatedSHA256","FailedRunSHA256");
        if(StrictJson.Text(record,"Status")!=status || evidence.Deserialize<Evidence>()!=expected)
            throw WfpNative.Contract("LegacyCreatorRetirementReceiptMismatch");
    }

    internal static bool IsAdmissionResolved(ProtectedState state,OwnedJobIntent job)=>
        UnadmittedJobRetirement.Read(state,job) || ReadRetired(state,job) || AtomicJobCompletion.ReadClosed(state,job) is not null;

    internal static void AssertAbsent(ProtectedState state,OwnedJobIntent job,Original original)
    {
        state.AssertHeld();
        OwnedKernelJob.AssertCreatorNameAbsent(job);
        SessionZeroCreatorRegistration.AssertRecoveryRegistrationAbsent(job.JobId);
        var programFiles=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        using var parent=WindowsPathSeal.LockDirectory(programFiles,PathPolicy.CreationParent);
        if(parent.ObjectIdentity()!=original.ParentIdentity)throw WfpNative.Contract("LegacyCreatorWorkspaceParentChanged");
        var path=SessionTaskWorkspace.PathFor(job.JobId,programFiles);
        try{using var unexpected=WindowsPathSeal.Open(path,true,false);throw WfpNative.Contract("LegacyCreatorWorkspaceStillPresent");}
        catch(ExactPathAbsentException error)when(string.Equals(error.FailedPath,path,StringComparison.OrdinalIgnoreCase)){}
    }

    private static void AssertBinding(JsonElement record,OwnedJobIntent job)
    {
        if(record.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(record,"InstallationId")!=job.InstallationId ||
            StrictJson.Text(record,"JobId")!=job.JobId)throw WfpNative.Contract("LegacyCreatorRecoveryRecordMismatch");
    }

    private static JsonDocument Read(BoundBytes value)=>JsonDocument.Parse(value.Bytes,new JsonDocumentOptions{MaxDepth=3});
}
