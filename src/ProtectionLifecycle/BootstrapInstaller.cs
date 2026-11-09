using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

namespace ProtectionLifecycle;

// The version allowlist establishes eligibility. The embedded contract
// selects the only pair this bootstrap may update.
internal sealed record InactiveUpdateTransition(string PriorRelease,string PriorManifestSHA256,string NextRelease,string NextManifestSHA256)
{
    internal static InactiveUpdateTransition Read(Stream stream)
    {
        if(stream.Length is <1 or >4096)throw new InvalidDataException("Inactive transition approval bounds refused");
        using var json=JsonDocument.Parse(stream,new JsonDocumentOptions{MaxDepth=2});
        var root=json.RootElement;
        StrictJson.Fields(root,"SchemaVersion","PriorRelease","PriorManifestSHA256","NextRelease","NextManifestSHA256");
        if(root.GetProperty("SchemaVersion").GetInt32()!=1)throw new InvalidDataException("Inactive transition approval schema refused");
        var transition=new InactiveUpdateTransition(Identifiers.Hex32(StrictJson.Text(root,"PriorRelease")),
            Identifiers.Hash(StrictJson.Text(root,"PriorManifestSHA256")),Identifiers.Hex32(StrictJson.Text(root,"NextRelease")),
            Identifiers.Hash(StrictJson.Text(root,"NextManifestSHA256")));
        if(transition.PriorRelease==transition.NextRelease || transition.PriorManifestSHA256==transition.NextManifestSHA256)
            throw new InvalidDataException("Inactive transition approval must change the package");
        return transition;
    }
    internal void Require(string currentRelease,string currentManifest,string nextRelease,string nextManifest)
    {
        if(currentRelease!=PriorRelease || currentManifest!=PriorManifestSHA256 ||
            nextRelease!=NextRelease || nextManifest!=NextManifestSHA256)
            throw new InvalidDataException("Current and next packages differ from the embedded inactive transition");
    }
}

// Only a separately byte-pinned bootstrap staged by the human-approved UAC
// helper may enter this path. This check is defense in depth AFTER loading:
// protected placement alone is not initial code-authentication or AV clearance.
internal sealed class BootstrapApproval : IDisposable
{
    private readonly List<PathLease> directories=new();
    private readonly List<FileStream> files=new();
    private bool disposed;
    internal ReadOnlyMemory<byte> Manifest { get; private set; }
    internal string ManifestHash { get; private set; }="";
    internal string PayloadDirectory { get; private set; }="";
    private BootstrapApproval() { }
    internal static BootstrapApproval Open(bool inactiveUpdate=false)
    {
        ProtectedState.RequireAdministrator();
        var result=new BootstrapApproval();
        try
        {
            var entry=Assembly.GetEntryAssembly()??throw new InvalidOperationException("Bootstrap entry missing");
            if(entry.GetName().Name!="ProtectionBootstrap")throw new InvalidOperationException("Bootstrap entry name differs");
            using var resource=entry.GetManifestResourceStream("ProtectionBootstrap.ApprovedPackage.json")??throw new InvalidDataException("Embedded package approval missing");
            using var bytes=new MemoryStream();
            var buffer=new byte[4096];int read;
            while((read=resource.Read(buffer,0,buffer.Length))!=0)
            {
                if(bytes.Length+read>PackagePolicy.MaxManifestBytes)throw new InvalidDataException("Approval too large");
                bytes.Write(buffer,0,read);
            }
            result.Manifest=bytes.ToArray();
            result.ManifestHash=Convert.ToHexString(SHA256.HashData(result.Manifest.Span));
            var parsed=PackagePolicy.ParsePinned(result.Manifest,result.ManifestHash); // Reject placeholder before creating state.
            // Release comes ONLY from the bounded embedded approval, never the
            // command line, environment, sidecar or executing directory. This
            // retains one exact protected host per package without recompiling
            // the product for an experiment-specific staging directory name.
            var root=WindowsPathSeal.Canonical(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                inactiveUpdate?"ClaudeCodeProtection-Update-"+parsed.Release:"ClaudeCodeProtection-Bootstrap"));
            if(!Same(Environment.ProcessPath,Path.Combine(root,"ProtectionBootstrap.exe")) ||
                !Same(entry.Location,Path.Combine(root,"ProtectionBootstrap.dll")) ||
                !Same(typeof(BootstrapApproval).Assembly.Location,Path.Combine(root,"ProtectionLifecycle.dll")))
                throw new InvalidOperationException("Fixed protected bootstrap host required");
            result.HoldDirectory(root);
            foreach(var leaf in new[]{"ProtectionBootstrap.exe","ProtectionBootstrap.dll","ProtectionBootstrap.deps.json","ProtectionBootstrap.runtimeconfig.json","ProtectionLifecycle.dll"})
                result.HoldFile(root,leaf);
            result.PayloadDirectory=WindowsPathSeal.Child(root,"payload");
            var payload=result.HoldDirectory(result.PayloadDirectory);
            var manifest=ProtectedState.ReadBound(payload,"package.json",PackagePolicy.MaxManifestBytes,true);
            if(!manifest.Bytes.AsSpan().SequenceEqual(result.Manifest.Span))throw new InvalidDataException("Payload approval differs");
            result.HoldFile(payload.Path,"package.json");
            // Hold and verify every input before creating any production state.
            var lifecycle=parsed.Files.Single(f=>f.Asset.Id=="broker-lifecycle");
            if(result.files[4].Length!=lifecycle.Length || Convert.ToHexString(SHA256.HashData(result.files[4]))!=lifecycle.SHA256)
                throw new InvalidDataException("Bootstrap and payload lifecycle library differ");
            result.files[4].Position=0;
            foreach(var group in parsed.Files.GroupBy(f=>Path.GetDirectoryName(f.Asset.Path.Replace('/','\\'))!,StringComparer.Ordinal))
            {
                var parent=result.HoldDirectory(WindowsPathSeal.Child(payload.Path,group.Key));
                foreach(var file in group)
                {
                    var stream=result.HoldFile(parent.Path,Path.GetFileName(file.Asset.Path));
                    if(stream.Length!=file.Length || Convert.ToHexString(SHA256.HashData(stream))!=file.SHA256)
                        throw new InvalidDataException("Approved payload bytes differ");
                    stream.Position=0;
                }
            }
            result.AssertHeld();return result;
        }
        catch{result.Dispose();throw;}
    }
    private static bool Same(string? a,string b)=>a is not null && string.Equals(WindowsPathSeal.Canonical(a),WindowsPathSeal.Canonical(b),StringComparison.OrdinalIgnoreCase);
    internal InactiveUpdateTransition ReadInactiveTransition()
    {
        AssertHeld();
        using var resource=Assembly.GetEntryAssembly()?.GetManifestResourceStream("ProtectionBootstrap.InactiveUpdateTransition.json")
            ??throw new InvalidDataException("Embedded inactive transition missing");
        return InactiveUpdateTransition.Read(resource);
    }
    internal SessionZeroCreatorRecovery.Approval ReadCreatorRecoveryApproval()
    {
        AssertHeld();
        using var resource=Assembly.GetEntryAssembly()?.GetManifestResourceStream("ProtectionBootstrap.CreatorRecoveryApproval.json")
            ??throw new InvalidDataException("Embedded creator recovery approval missing");
        return SessionZeroCreatorRecovery.Approval.Read(resource);
    }
    private PathLease HoldDirectory(string path){var lease=WindowsPathSeal.LockDirectory(path,PathPolicy.Protected);directories.Add(lease);return lease;}
    private FileStream HoldFile(string parent,string leaf)
    {
        var handle=WindowsPathSeal.Open(WindowsPathSeal.Child(parent,leaf),false,true);
        try{WindowsPathSeal.AssertAcl(handle,true);var stream=new FileStream(handle,FileAccess.Read,65536,false);files.Add(stream);return stream;}
        catch{handle.Dispose();throw;}
    }
    internal void AssertHeld()
    {
        if(disposed)throw new ObjectDisposedException(nameof(BootstrapApproval));
        foreach(var directory in directories)directory.AssertHeld();
        foreach(var file in files){if(file.SafeFileHandle.IsClosed || file.SafeFileHandle.IsInvalid)throw new IOException("Bootstrap input lease lost");WindowsPathSeal.AssertAcl(file.SafeFileHandle,true);}
    }
    public void Dispose(){if(disposed)return;disposed=true;foreach(var file in files)file.Dispose();for(var i=directories.Count-1;i>=0;i--)directories[i].Dispose();}
}

public static class BootstrapInstaller
{
    // The currently installed bytes cannot restore the one observed Windows
    // normalization, and the pending lease correctly blocks normal update.
    // The same approved Bootstrap host can run this single recovery operation.
    public static (int ExitCode,string Report) RecoverReviewedTimeZoneReadAccess()
    {
        var stage="PACKAGE_APPROVAL";
        try
        {
            ProtectedState.RequireAdministrator();
            using var approval=BootstrapApproval.Open(true);
            stage="REVIEWED_INACTIVE_INSTALLATION";
            var layout=FixedLayout.FromWindows();
            using var state=ProtectedState.OpenExisting(layout);
            var raw=state.Read("current.json",4096);
            var current=CurrentPointer.Parse(raw,state.InstallationId);
            if(current.Release!=SessionTimeZoneReadAccess.ReviewedRecoveryRelease ||
                current.ManifestSHA256!=SessionTimeZoneReadAccess.ReviewedRecoveryManifest)
                throw WfpNative.Contract("ReviewedTimeZoneRecoveryVersionRefused");
            using var version=VerifiedVersion.Open(layout,state,current.Release);
            if(version.Package.ManifestHash!=current.ManifestSHA256)
                throw WfpNative.Contract("InstalledPointerManifestMismatch");
            stage="RECOVERY_PRECONDITIONS";
            LifecycleRecovery.AssertNoPending(state,forManifestAccessRecovery:true);
            SessionManifestReadAccess.AssertNoPending(state);
            SessionEtwProviderAccess.AssertNoPending(state);
            SessionWinsockReadAccess.AssertNoPending(state);
            approval.AssertHeld();version.AssertHeld(state);
            stage="REVIEWED_TIMEZONE_RECOVERY";
            var result=SessionTimeZoneReadAccess.Recover(state,reviewedIncidentOnly:true);
            stage="RECOVERY_READBACK";
            if(state.Read("current.json",4096).SHA256!=raw.SHA256)
                throw WfpNative.Contract("ReviewedTimeZoneRecoverySelectionDrift");
            version.AssertHeld(state);approval.AssertHeld();
            return result;
        }
        catch(Exception ex)
        {
            return(125,"Timezone recovery not confirmed: "+ex.GetType().Name+"; code="+ex.HResult+"; stage="+stage);
        }
    }

    public static (int ExitCode,string Report) RecoverReviewedLegacyCreator()
    {
        var stage="MAINTENANCE_IDENTITY";
        try
        {
            ProtectedState.RequireAdministrator();
            stage="RECOVERY_PACKAGE_APPROVAL";
            using var bootstrap=BootstrapApproval.Open(true);
            var approval=bootstrap.ReadCreatorRecoveryApproval();
            var next=ReviewedPackage.FromBootstrap(bootstrap);
            var layout=FixedLayout.FromWindows();
            stage="EXACT_INACTIVE_INSTALLATION";
            using var state=ProtectedState.OpenExisting(layout);
            var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
            bootstrap.ReadInactiveTransition().Require(current.Release,current.ManifestSHA256,next.Release,next.ManifestHash);
            using var prior=VerifiedVersion.Open(layout,state,current.Release);
            var receipt=SessionZeroCreatorRecovery.Recover(state,prior,approval,value=>{stage=value;bootstrap.AssertHeld();});
            return (0,JsonSerializer.Serialize(new {Status="LEGACY_CREATOR_RETIRED_WITHOUT_ADMISSION",ReceiptSHA256=receipt,
                JobZeroObserved=false,PointerChanged=false,WfpModified=false,ClaudeLaunched=false}));
        }
        catch(Exception error)
        {
            var details=WfpNative.Describe(error);
            return(125,JsonSerializer.Serialize(new {Status="LEGACY_CREATOR_RECOVERY_NOT_CONFIRMED",Stage=stage,Failures=details}));
        }
    }

    // Migration from pinned reviewed packages with no admission or completed
    // one-shot admissions. This is not a generic empty-job/runtime lease.
    public static (int ExitCode,string Report) UpdatePinnedInactive()=>UpdatePinnedInactive(null);

    public static (int ExitCode,string Report) UpdatePinnedInactiveWithFeedback()
    {
        // Only fixed owner stages and the existing type/code reach stderr.
        var stage="START";
        try{return UpdatePinnedInactive(value=>stage=value);}
        catch(Exception ex)
        {
            return(125,"Inactive update not confirmed: "+ex.GetType().Name+"; code="+ex.HResult+"; stage="+stage);
        }
    }

    private static (int ExitCode,string Report) UpdatePinnedInactive(Action<string>? observeStage)
    {
        // Inactive maintenance has its own narrower qualification boundary.
        // It does not execute a child, activate forwarding or clear the still
        // unqualified system/session entries. The exact bootstrap is reviewed
        // and pinned independently after compilation, before human UAC.
        observeStage?.Invoke("MAINTENANCE_IDENTITY");
        ProtectedState.RequireAdministrator();
        observeStage?.Invoke("PACKAGE_APPROVAL");
        using var approval=BootstrapApproval.Open(true);
        var package=ReviewedPackage.FromBootstrap(approval);
        var layout=FixedLayout.FromWindows();
        observeStage?.Invoke("INSTALLATION_STATE");
        using var state=ProtectedState.OpenExisting(layout);
        var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
        observeStage?.Invoke("EXACT_INACTIVE_TRANSITION");
        approval.ReadInactiveTransition().Require(current.Release,current.ManifestSHA256,package.Release,package.ManifestHash);
        observeStage?.Invoke("CURRENT_VERSION");
        using var prior=VerifiedVersion.Open(layout,state,current.Release);
        observeStage?.Invoke("PINNED_TRANSITION");
        using var runtime=new PinnedInactiveUpdateLease(state,approval,prior,package,observeStage);
        observeStage?.Invoke("UPDATE_PRECHECK");
        var operation=VersionLifecycle.InstallOrUpdate(layout,state,package,approval.PayloadDirectory,"update",runtime,observeStage);
        observeStage?.Invoke("INACTIVE_READBACK");
        using var verified=VerifiedVersion.Open(layout,state,package.Release);
        var after=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
        if(after.Release!=package.Release || after.ManifestSHA256!=package.ManifestHash || after.OperationId!=operation)
            throw new InvalidDataException("Updated inactive selection differs");
        runtime.AssertNoOwnedProcesses();verified.AssertHeld(state);
        return (0,JsonSerializer.Serialize(new {SchemaVersion=1,Status="PINNED_INACTIVE_UPDATE_COMPLETED",state.InstallationId,
            PriorRelease=current.Release,package.Release,package.ManifestHash,OperationId=operation,Activation="INACTIVE",
            RuntimeLeaseScope=runtime.LeaseScope,WfpModified=false,JobCreated=false,
            ClaudeLaunched=false,UserConfigurationModified=false,ProtectionQualified=false}));
    }

    private sealed class PinnedInactiveUpdateLease : ILifecycleRuntimeLease
    {
        internal string LeaseScope {get;private set;}="PINNED_NO_ADMISSION_OR_CLOSED_ONE_SHOT_JOBS_AND_ABSENT_OR_QUARANTINED_FENCE";
        private static readonly string[] NoAdmissionManifests={
            "1D83FA034A65DC58D1FFEB9C4F3A54EA52F1C3B7AF6156A54C752FA5D8801BAC",
            "BB0A619C10B53ECF4AC4E79578C9DF4A058E1758B3B111836A5172F46488E9FD",
            "D21A7D9F39A93E82087062EAD14F49329E7DBDD2743B2DC12DE98CAB6DC691F1"
        }; // Exact reviewed packages expose no launch/admission command.
        private static readonly string[] OneShotAdmissionManifests={
            // Exact 4d186bcb recorded original Job zero and workspace
            // recovery after the host identity comparison.
            "C872C2D14DABD028421DE4057CF5B1150B18FD492A60E299CAEC20174059DA22",
            // Exact e2309d71 closed its original Job and recovered the task
            // tree after verifying the projected directory and temporary file.
            "1DA0A7253D3B9AAB57492A12BECE4CD21412B29318B56A5F6FEEE3B6AD8D9211",
            // Exact 49c54e70 passed and closed its fixed offline console
            // qualification under the original owner.
            "12C1FA802B2C92CA6AC325F0216400F7BA8BEF5F056A04317A03CF85060FFF91",
            // Exact ae721f11 closed its Job and recovered its workspace after
            // privately recording the Windows projection mismatch.
            "FD7141C1CF4B5E5FFFB722B0C2D3D07C020A8E56C855E7293000E0F0D52509E5",
            // Exact b27432ac held its AppContainer folders and closed its Job
            // and workspace after the restricted TEMP comparison failed.
            "6AE8DDB45D6034B6A39597676D9E46BF5BFD4833C4FFBCEA88AF045BFA8B3A71",
            // Exact aa0123db confirmed ordered closure and task recovery
            // after the restricted worker refused its TEMP mapping.
            "DD3A8C57B1E55B8230BFD0D38A10B424E9052E5BF7BDF8C97F8EE82A69C98D5A",
            // Exact 1805e4fb closed its one-shot Job and recovered its task
            // directory after the console worker rejected its environment.
            "8AD9D29957202ABFDA1DCFC0A40713DAEA3E78D6A186F22A04925474738F17A6",
            // Exact 5f2cc24f recorded ordered closure and workspace recovery
            // after the fixed offline console worker failed its workload.
            "F6F42E5D3DFBF0192AB4C655D91DB226113FEA175154F8D612B0B9207DC54628",
            // Exact 2ac3cb39 closed the local management-boundary session and
            // restored its leases. The update still rechecks all live gates.
            "F4E20BC2B7C3703017A283B479074FFCF2E33A4CEE60389CDA1A389938C83AC6",
            // Exact 3bd091e1 observed a target 403 with trailing bytes
            // and restored the closed original session and its leases.
            "ED20BA5A45C5B27B0A1E182CA24D22DBB24FA61E0DFF6AE00279C1FFD0F3A7BB",
            // Exact a8d6e45c closed and restored the session after the
            // fixed HEAD rejected bytes beyond the final response header.
            "1E9893FD015B8EA5B7A12C022523737DCD0BF8B6E7A4D4696B86EF45097FAD00",
            // Exact f91e0538 closed and restored the session after the
            // DNS freshness gate rejected a short-lived answer.
            "F5C221D98A181FDBE08E640199695F84BE9FE163764DE11E285786C9F0EE497F",
            // Exact a2f84433 authenticated the target TLS peer and closed
            // the session after the application exchange failed.
            "16487610E4C34A06F3823890983A9F8577B6857FE9A637CA3B005AA9B41F796C",
            // Exact be7f2a49 proved resolver TLS and restored all leases
            // after the target tunnel stopped.
            "C98E38A232633827A51AA0FABD1DBF0F6D0F0969327C46874EA12C708A10B925",
            // Exact 5aef9d7d closed and restored the session after the
            // resolver rejected the unproven offline revocation status.
            "527B5693314BC84A0E0A05B6EC89BC848A58D53621BBCC75435FB3535C97620A",
            // Exact 91d7aa4c closed the session and restored its Winsock lease
            // after the resolver TLS failure.
            "1EE4F2D4FE70E21C451E60238CF4A9DD18B8B2A39BA30C6D6D17E26BA04BD521",
            // Exact afb95ad1 closed its successful offline Job.
            "EEE8E79F82E09C405911523E935DA3537E137446433590D835B55FB8C47F3B2D",
            // Exact 8ad9a646 closed the offline Job after native RNG failure.
            "F5AE7357F63A1D1D77F35F8975A02EEAE3693179F76A341EACF0BCCCFE1186DC",
            // Exact d7fc0bbf closed the offline Job after the fixture failed.
            "EB3181E3C655524E8A1A03562D82D8B0ABF4DA463912C629FA2089869393CB4D",
            // Exact d8be9fe7 produced a closed offline Job with an
            // unsuccessful module check. This never qualifies TLS.
            "9A8B7310B33E1DC3CF81CC75D0E460B9C9DB8ED0FD8B74C9B34E74F403E487CB",
            // Exact 68a0d109 closed offline diagnostic. Live job, fence and
            // recovery gates are still required for any inactive update.
            "7011F015638626416B00B222C817AE1749A258C9C7EA5EDB3D91DFCC6104DCF2",
            // The exact 34543d35 predecessor reported a closed one-shot
            // diagnostic. The inactive update still proves each live gate.
            "6975AF499A5FBF4FA557050EBAE169AFC6BA06D74AFE9B554E12FC37B6057471",
            // Exact 41fb predecessor. The TLS workload and outer audit
            // failed. The original stop receipt is not live authority:
            // every admission, Job, loopback, quarantine and recovery gate
            // must still be proved by this inactive update owner.
            "1B092FE1579CE80ABBECE8DE26D846DDE271E4D58E6926730608CDCC3DDCD17F",
            // Exact c526 predecessor. Both original comparison owners reported
            // ordered closure and resource restoration, but the outer helper's
            // final self-audit FAILED. Never infer live maintenance eligibility
            // from those receipts: all original live gates still apply.
            "D35710928355BDDF12C4E07153A73A58FDB29E53F2533EE27D7DCE41EBC7F300",
            // Exact 610b inactive predecessor. This adds no migration bypass:
            // current/owned manifest, all historical admissions/Job-zero,
            // loopback history and quarantine must still pass live checks.
            "2ACC0397D4585791A7C6F258DB8C7A626E10D990B9D17FF04B43564055BA4C5D",
            "92111D9F9D4DC6199788BD561CBDE744F3DD1CFA8C47700B22B8B3531764DDAE", // fa8d exact inactive package; early host failure had no bound Job receipt. No closure inferred: every live closed-admission/quarantine/recovery gate must pass.
            "C5D1B76E4CDC050033411625AEE119A6994BFE6A4235AA5F83EA440539FC7151", // 4588 exact inactive package; original failed host admission durably closed/zero. Every live update/recovery gate remains mandatory.
            "EFFDC3506DD376AA2601BE6C62505586C9C154E76EC4B838D007F73491069BE5", // 9bbbb exact inactive package; failed host reference's original atomic admission durably closed/zero. All live gates still mandatory.
            "E6F10C4174CE36061EE19EAE4A6F9155560DF2C9582A6552404A1534E915F1F8", // f6ab exact installed inactive package; every live closure/quarantine/recovery check remains mandatory.
            "849A2BFC1D9F08D1B581BD5C79EDBF1575048F5D20B3145D6297B10E1CF80C8F", // 3e2 exact installed public package; all live admission/Job/quarantine/recovery gates still required. Not an execution approval.
            "6CDC07DC3CEDEC82D6CCA5B2F705471DC79C9EE99CCB519BB89FBFEDCCF04053", // 0f1 socket10022; original Job closed/zero and all28 registry objects independently restored; live gates remain.
            "F5754A429380192B3A77D4F90B95D19F1A49DA51D5FBDBAE8436895D200DA605", // d00 socket10022; original Job closed/zero and all28 registry objects restored; live gates remain.
            "F0F03EDE10E1247B788F298BC877A1B8EAF7EFF9773B8D667F93EEC30EB940EC", // a149 socket creation refused; original Job closed/zero and all25 registry objects restored; live gates remain.
            "88B0AA52D63C4614B6431327AB3735172332454DF039DBBC9C9214B3938F29B4", // d9da original offline development/stop closed; all live inactive maintenance gates remain.
            "FE4B5F9E2F9186AF2693DB1CBBC85296C5049BC927F395F65E31920E03C7293B", // 6800 original offline compiler probes closed and exported; live inactive guards remain.
            "3CE38FBC1D5ECB5FB8292B1107992C4E3BC4DE487AB7BF45AE4B37DCA64489D1", // 979c socket-creation refusal; original ordered closure/quarantine/Job zero observed; live maintenance gates remain.
            "BC53B2C0BA82C668A9D3C2CC4B234EA90FF8E1A51E2DD9BEE6EC6373D0FB5093", // 8aee fixed socket failure; original ordered admission closure/quarantine/Job zero observed; live gates remain.
            "208A02B4EFFC63A45BC30587969A0CF6B933E7DA466CD818DCF59F23FBE6BCDA", // 7aa public-cache refusal; original closed admission, quarantine and Job zero observed; live maintenance gates remain.
            "2FD84A6DF06A8ADA40E0A67032D111E73FEE7A7EFB3AC7537E54ECDA75B45608", // 8389 selected-definition refusal; original Job closure and exact two-key restoration observed; live gates remain.
            "18C038EBC7125FA705EE50443044C087100627956CF323D9BB3473014D3B86E6", // 1c fixed definition-read refusal; original Job closure and exact two-key restoration observed; live gates remain.
            "3BF2F145C1C4C763D8F071C70A537CFB04952C1AC66D4DCA28B366928BB65789", // da7 fixed timezone-registry refusal; original Job closure and exact two-key restoration observed; live gates remain.
            "5A7B7704B74782A065F3A9F7641E65897E8E7D93B735F4FCA0758E12B851BBC0", // d550 TLS policy refusal; original Job closure and two-key timezone restoration observed; all live gates remain.
            "4E5ECAB1FC1D7455B7DF6EFE5678039E7C11EB92C71FC585F4A634CF277B0D4C", // d423 suspended gateway attempt; exact timezone recovery observed, all live closure/resource gates remain.
            "1A7AD8E8C6935CD75EEC54D7ADC2143224ECE3052B6FCEE51DA98B52525F9719", // a9de TLS policy refusal; original durable closed-Job/quarantine guards remain.
            "7710162354EE832B530059D4BCAD36AC650BE6511742E3432E9DB272519BE965", // 8ddc HTTPS initialization failure with bound feedback; original closure guards remain.
            "0E3FC10A86DB6D61F6CB774AE4D74CBF4D9CEE9E147393F020F59A55ACF97C5B", // 40d7 fixed gateway root resumed/125, original closed admission/quarantine/zero guards remain.
            "ADC8BEE33E205CF4F0411492D1F3A54A5A63FEF7F7E27DC95FE11C05C3D233A2", // 92e3 fixed gateway creation failed; original closed-Job guards remain.
            "8E09CB551E27BFD89C5F31F375DDC0D1D13E5F3DCB5E0547FE9E5344D6C3B86D", // 401e inactive gateway guard baseline; no activation grant.
            "3209392BE51C01C3D84254D1177182A414813BBB3FF9B7AA0F8C9D21177F42F4", // 7535 reset-compatible fixed task; original inactive guards remain.
            "62ED7BE063B28D63F34EDA0BF5267343FF4C386506B367901C552EB23C81AD2D", // 8932aff8 task editing; inactive closure guards remain.
            "4EAB9E8E35D4CD1D58344EB3EC824769308D48005156BBC33349BE55361C362E", // d51b3807 shared maintenance gate; all closure checks remain.
            "732A198283CD62847079A75847891ECAE549D3C96363180FE33A7C8B74D31FCF", // 225b7214 inactive GUI cancel package; all closure checks remain.
            "F68329165AAAD7BF5C8CBB4B44111B715439395B850F9653C80D687843A006FA",
            "9A3AFFC424CCB1D05691891A0F5EA99BFFECE30EDA801594825076C2DBB9E32F",
            "978CE60499B05D76E2820F7ADD214727E3F417716A2EABD1EA34EB90FC14C5B4",
            "D1B1982E41107A988E719BC8779CE66F62BE7FD1C9F28D8673557BC416B3EF87",
            "9AE1DBF15E05AC67E5E4EE73E216BFDB36FE1819ABC49E4A7C4FC5D060C37E10",
            "49B57CE036DBE8391D9967875BE1A7CB4505EB0F92407040DB88EE4CF7CB6CBE",
            "B832A15F4A52CEE50B09707C032BB9199296A69A79A735BC84BAFA56A142A94B",
            "A31A246BFE3A021B3E443138906119BDAFD8518EBDC0B8CB349D87E0BFFBE2BD",
            "7EC62DE8F572CBED678616FF2E1F1A815C520463BD172E998A546CA975A7593C",
            "3B2DBEDD06AF0B8230E3527CEC2790159CCEA9A36F8A2E3CF4213BC0CC25D9B3",
            // Preserved member-diagnostic package present at the 0x1E event.
            // Allowing closed inactive migration does not clear that incident.
            "3EB4F1A88CAC2B3CFB6A561B357E65600745F6B989D8D9A7916A7FA0537FC7BD",
            "B58EDC15D9C21C17565A57ACCA08B39B1AC1992E59429CB4F719E4FD3EAB7962",
            "1FD3A0A5A5A9AF2468ADD39E90E9BB1C8AE489D4128A4D1CDD8342C8D2E0607F",
            "87886CBBAACF0FCEE55D8AA6C4A8AF93D9E4730D798458BA7C75FBE424860417",
            "FAA5CAA7DD05933D0448CE12D28CA0D1C6E1F8E62E9A059C8AC0A54019C21391",
            "107DC814102BC96922DECFE7E9C97CD0C342F70384468C5E6AEAFA9E93E1A128",
            "32D20BF3646356B71FEECA9875192C631A9503A497B2480C074B245FC577373C",
            "F08F03CC26DC811301CE4E67DA0783D8C17996450B3A9B8915DE9532A225F2B8",
            "F1606AE91333F20001FC781861B92FF5B8A5DB83EE6858FB77183A487EFD77FC",
            "1C2D5F29BB27A0ED4A003F67210C12286956FE2AD9F9547ECA34865C8BB8D2FB",
            "D6B820AE866AD68317099AFA7FF1608F9651F5F1D7289973935287BAA385A346",
            "9373F33796B44BCDFC932DFF4CB5B826CC5CF82C600A3851355389B592335AD7",
            "66DBD24CB8A296BC0023A24E806B755973344DC95B387E3E8A21F2EDFE367EE5",
            // Current fc2d7c8b fixed offline Git package; all admissions still
            // require durable closure/Job-zero before this inactive update.
            "2F23479431360CC5BE0B0E84DFB821FBF2FFD8D04BE3A100EC0F7677B0EDB20B",
            "CB5515C9CED7D08248EA903F7EA2817B2F47D5EA952D366B31ABB775520C4264", // 659d76df closed offline project-transfer package.
            // Exact package installed at the second crash. This permits only
            // the existing inactive-update checks, not adoption/recovery of
            // an interrupted session or an exception to durable Job closure.
            "851701939666F35F4E0C4323C408E00690B4CFB96165C81F5C6092AF5D8238C6",
            // Installed names-only repair; two read-only paths returned.
            // Migration still requires the same durable closed admissions,
            // Job-zero and quarantine checks; original workload stays unproven.
            "048E974CD4611B4DB7B577B64DAA5842C5CA02FE08D63298382BBC001FBBEC37",
            // Installed daily pipe candidate. The first roundtrip was refused;
            // the existing closed-admission/Job/quarantine checks still decide
            // whether any inactive migration is safe, never this digest alone.
            "429D76D9B3245DF335D879F27F8CDCC12AF954E79685B8D40BBDC9F50BDFB5FF",
            // Current daily data roundtrip repair. Closed Job, exact cleanup
            // and final quarantine were required before its result export.
            "DE88460A1F31721FC69F151B528718DC2FE89ABE66BAEA551E3AD3D8AD8815C4",
            // LPAC first runtime: pre-resume identity passed, child exited125;
            // exact readback established closed/zero Job and full quarantine.
            // Original lifecycle checks remain mandatory for inactive update.
            "3C0471F484A193EF5EFF77A259602BAB8DFF13313B8440C08BF2459DA7D86D18",
            // Startup diagnostic revision: exact receipt confirms full
            // quarantine and closed/zero Job after resource-input failure.
            "0337CB5D80ECEB760AC8BF96E49FD699B51A0E9E77ED2284BE4206662EFA549F",
            // Current LPAC data chain: root denial qualified, tool start5;
            // exact receipt confirms full quarantine and closed/zero Job.
            "1F79C28F55857F788023802635F7A0A62DACEEA4BE5CD6BD45035E4A78E42681",
            // Reviewed diagnostic package. Its actual CreateProcess denial is
            // preserved; all original closure/fence checks still apply here.
            "599852489D7049C8944C3C41712AC1ACE5217F2E437AB2AB5D3035D2E880A02A",
            // Explicit inherited creation still returned5. Prior admission and
            // quarantine must be closed by the unchanged update guards.
            "8ACABDD78FEF52314B664CCE1F2B5D710EE1F665004177F75D9DB888D0F6DFAF",
            // Native own-token access was already10; no DACL mutation occurred.
            // Exact receipt confirms original Job closed/zero and quarantine.
            "449AF6BA7B320FBC50E5B27F77D1C36FF902A0123CE02CBD0A074BDCC3C855B9",
            // Cwd inheritance did not repair CreateProcess5. Exact Job3498721f
            // receipt confirms closed/zero members, full quarantine, no stop errors.
            "2A5D02303A96DDDFF17423C7EDAEC67BD94FD5290318E41F77F1BE1B8ED4996C",
            // Installed v3 diagnostic package. Profile interruption is not
            // closure evidence: the unchanged all-Job/quarantine gates below
            // still decide whether any inactive update is admissible.
            "2896E57A537D998D877170C5D7EE98F3B842DAA899E8CD1688F04E767911A68E",
            "F1418ECBB01AED35559B440E60BAF37C4E79C3D6133A62F331BB9B40EF062B01",
            "850D193EFB259C819B215333A5F7D60D49BFE5C8456957587C84424EEFB81C69",
            "06C8F6F2DE0E6A289527D3B3B6166780BB92684ECFD7CA7DC68C0CDD25A44108",
            "164AD85F444447B6683370309FA2EDCE2A5D000A62037FD39B1CB5FE227D04C4",
            "9239BB32E9822030B19E70E8B983CC28D89B987115EF028E733F921B56101247",
            "D2CABD45BCF2965F8BC982669C0478958B80CD5F22807CCB76134DE8B0626AE8",
            "6AAE651E3AFA2D592E02F70A8097048EFA7106F563FD96A766AD1A5208F2E0DA",
            // Installed trial: exact ETW restore and closed-zero Job verified;
            // tool compatibility failed. Existing all-Job/fence gates remain.
            "B23DDA0D2833F427A042CB5081A345DEA8EBBDAABFDD5E0FAA0DA155794B96AD",
            // Actual installed Git DATA package. The later numeric ETW trace
            // failed, but its original Job closed/zero. This exact pin never
            // replaces the live all-admission, Job-zero and quarantine checks.
            "B692EEF8753B737E126924E0FC6EA764F39C4BB5BDA4BBFC472A3F45701C45E8",
            // Actual corrected update and held-token comparison package.
            // Runtime admission/Job/quarantine checks remain mandatory.
            "B5CFD0EDFEECB4CF91011D886A99961DE6762595D27048A547EB2BDDF10B9C7E",
            "656D8690F56C5A085E1379B923692D2AC409F4B83E11BD18DE929033DC8C06E1",
            "F415392FE03AA198F1712A58AAAF0E4D197E81A850275CB027764A7356DF3A61",
            // Actual paired named-resource project package; exact prior only.
            "60EC905689CFB91D6D8BC4A4020B250B135FB910D2C2C7A7FDC9AF1AC7A8292F",
            // Actual v6 caller package with original-owner pre-code sealing.
            // This exact prior pin never substitutes for live closed admissions,
            // zero-member Job, quarantine and pending-resource checks.
            "917202DE05F414EAA62803811D673CDD1A9071A3F7F08B0B188E358E57057399",
            // Recorded 35a INACTIVE GUI package. Only its exact manifest is
            // eligible for selection; live closure, quarantine, ownership and
            // pending-resource checks still run before an authorized update.
            "58E8D97CE58C48EFA4C6FFFC86B236CB10DE7CFC50BB424CDDF4034136AAFCFB",
            // e6bd task-authoring package installed with human-controlled UAC.
            // This pin only selects the known prior manifest; every original
            // live inactive-maintenance check remains required.
            "61A02E2662DF4A7F5417F25777249BD3BC1D681D13B177FF5A249F64D391ACE5",
            // a3b6 paired owner-control gate package. The fixed project closed
            // successfully; a pin is still not live Job/quarantine authority.
            "C2BCCC13A5296971D0DE1B77BB7CC158A9FA0EDA36FCCF3B21BDDED7CF210AD2",
            // 77a1 explicit-data package, with closed fixed data-report task.
            // All live original inactive-update guards remain mandatory.
            "A5CC9F74FBCCEF743A301419BA2095C05964591468883067B612E4440CE43D75",
        // 3cfd expected compiler-failure task returned original closed/isolated/Job-zero observations.
        // This exact inactive predecessor remains subject to every live resource/update guard.
        "1F541F21AA2989A56A36DB620A087190235BE2B7998B6AB1DD26433145E1C63E",
        // 00ac fixed compiler-failure task returned bounded diagnosis and original public closed/isolated/Job-zero observations.
        // Exact predecessor pin only; all live update/resource gates remain.
        "75EC1ECA5678EAB168987BCD38BAC34EB40C2A1FFABD2CBD8268873378FD907B",
        // 8a22 fixed control-file/data-report task completed through the original owner.
        // Select only this exact predecessor; every live inactive-update guard remains.
        "ACF8094509362411545F87C772A53E1D7EE7CA716DBF3BF8760EB84E34D20DFB",
        // Exact ecbcd4e0 continuation GUI package. All original live inactive
        // maintenance, admission, Job/quarantine and ownership checks still apply.
        "699ED89C53E60A706081DF6651D0AFD19FADAC71687E54DB0BD30D7BCC5899BC",
        // Exact 9dd26020 multi-edit GUI package; every live inactive-owner
        // resource, admission, Job/quarantine and ownership guard is retained.
        "3D7B72E0873AED73A10D6B9D016FEF66ACDA0AF840B0AEE16A3946A93E07717C",
        // Exact e249 caller-lifetime package. Its fixed caller-loss stop is
        // recorded; all live closed-admission/Job/quarantine guards remain.
        "ACA706F6DD31F625A0D800DDA56582D46B13BB0D16A6C817AAC35E9840B0F993"
        };
        private readonly ProtectedState state;
        private readonly BootstrapApproval approval;
        private readonly VerifiedVersion prior;
        private readonly ReviewedPackage next;
        private readonly Action<string>? reportFailureStage;
        private bool disposed;
        internal PinnedInactiveUpdateLease(ProtectedState state,BootstrapApproval approval,VerifiedVersion prior,ReviewedPackage next,Action<string>? reportFailureStage)
        {
            this.state=state;this.approval=approval;this.prior=prior;this.next=next;this.reportFailureStage=reportFailureStage;
            var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
            RequirePinnedTransition(current.Release,current.ManifestSHA256,prior.Package.Release,prior.Package.ManifestHash,next.Release,next.ManifestHash);
            AssertNoOwnedProcesses();
        }
        // Pure selection check used by the actual constructor and ordinary
        // qualification before any new package is proposed for human UAC.
        // Acceptance here says nothing about live closure or maintenance gates.
        internal static void RequirePinnedTransition(string currentRelease,string currentManifest,string priorRelease,string priorManifest,string nextRelease,string nextManifest)
        {
            var creatorPrior=(priorRelease==SessionZeroCreatorRecovery.Release && priorManifest==SessionZeroCreatorRecovery.Manifest) ||
                (priorRelease=="51039f75b3bd4629b6ab3ea840e9f36a" &&
                    priorManifest=="ADB71B6FCF3656780010B57A3567C5E9E6DA47A37E4EDFDCC3A91F043D11256E");
            if(currentRelease!=priorRelease || currentManifest!=priorManifest ||
                !(creatorPrior || NoAdmissionManifests.Contains(priorManifest,StringComparer.Ordinal) || OneShotAdmissionManifests.Contains(priorManifest,StringComparer.Ordinal)) ||
                nextRelease==priorRelease || nextManifest==priorManifest)
                throw new InvalidOperationException("Only pinned reviewed inactive packages can migrate");
        }
        public void AssertLaunchAdmissionClosed()
        {
            if(disposed)throw new ObjectDisposedException(nameof(PinnedInactiveUpdateLease));
            state.AssertHeld();approval.AssertHeld();prior.AssertHeld(state);
            // Pinned packages have no launch command or one-shot admission
            // with mandatory closed-admission completion. Every installed
            // admission/mutation owner must hold this same exclusive lock.
            // New payload stays INACTIVE throughout this one update operation.
            var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
            if(!((current.Release==prior.Package.Release && current.ManifestSHA256==prior.Package.ManifestHash) ||
                (current.Release==next.Release && current.ManifestSHA256==next.ManifestHash)))
                throw new InvalidDataException("Current pointer escaped the bound inactive migration");
        }
        public void AssertNoOwnedProcesses()
        {
            var stage="ADMISSION_BINDING";
            try
            {
                AssertLaunchAdmissionClosed();
                stage="LOOPBACK_HISTORY";
                InstallationLoopbackLease.AssertClosedHistory(state);
                stage="JOB_CLOSURE";
                var jobs=OwnedJobIntent.ReadAll(state);
                if(NoAdmissionManifests.Contains(prior.Package.ManifestHash,StringComparer.Ordinal) && jobs.Count!=0)
                    throw new InvalidOperationException("Job history is outside the pinned no-admission package");
                var retired=false;
                foreach(var job in jobs)
                {
                    if(SessionZeroCreatorRecovery.ReadRetired(state,job)){retired=true;continue;}
                    if(AtomicJobCompletion.ReadClosed(state,job) is null)
                        throw new InvalidOperationException("Every Job needs a closed admission or a verified retirement without admission");
                }
                if(retired)LeaseScope="PINNED_CLOSED_OR_RETIRED_NEVER_ADMITTED_JOBS_AND_ABSENT_OR_QUARANTINED_FENCE";
                // A failed intent is not absence. Every exact plan must be absent
                // or fully quarantined; no resource is removed during this update.
                stage="FENCE_QUARANTINE";
                foreach(var plan in FencePlan.ReadAll(state))
                {
                    using var fence=PersistentFence.OpenExisting(state,plan.Data.FenceId);
                    var observed=fence.Observe();
                    if(!observed.AllAbsent && !observed.FullQuarantineObserved)throw new InvalidOperationException("Partial or changed fence resources require the full runtime maintenance owner");
                }
            }
            catch{reportFailureStage?.Invoke(stage);throw;}
        }
        public void StopAndVerifyOwnedProcesses()=>AssertNoOwnedProcesses();
        public void RemoveAndVerifyExactOwnedResources(string installationId)=>throw new InvalidOperationException("Inactive migration cannot remove resources");
        public void AssertNoOwnedResources(string installationId)=>throw new InvalidOperationException("Inactive migration cannot authorize resource cleanup");
        public void Dispose(){disposed=true;}
    }

    // Fixed fresh install only. No path, digest, activation, process, network,
    // update, adoption or uninstall parameter crosses this public boundary.
    public static (int ExitCode,string Report) InstallFresh()
    {
        ProtectedSession.AssertSystemTestingAllowed();
        ProtectedState.RequireAdministrator();
        using var approval=BootstrapApproval.Open();
        var package=ReviewedPackage.FromBootstrap(approval);
        var layout=FixedLayout.FromWindows();
        // Foreign/partial code roots must be resolved explicitly, never adopted.
        try{using var existing=WindowsPathSeal.LockDirectory(layout.CodeRoot,PathPolicy.Source);throw new InvalidOperationException("Fresh install requires absent code root");}
        catch(ExactPathAbsentException ex) when(string.Equals(ex.FailedPath,layout.CodeRoot,StringComparison.OrdinalIgnoreCase)) { }
        using var state=ProtectedState.CreateFresh(layout,package);
        using var runtime=new FreshInactiveLease(state,approval);
        var operation=VersionLifecycle.InstallOrUpdate(layout,state,package,approval.PayloadDirectory,"install",runtime);
        using var verified=VerifiedVersion.Open(layout,state,package.Release);
        var pointer=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
        if(pointer.Release!=package.Release || pointer.ManifestSHA256!=package.ManifestHash || pointer.OperationId!=operation)
            throw new InvalidDataException("Installed selection differs");
        verified.AssertHeld(state);runtime.AssertNoOwnedProcesses();
        return (0,JsonSerializer.Serialize(new {SchemaVersion=1,Status="FRESH_INACTIVE_INSTALL_COMPLETED",state.InstallationId,package.Release,package.ManifestHash,
            OperationId=operation,Activation="INACTIVE",AssetCount=package.Files.Count,RuntimeLeaseScope="NEW_INSTALLATION_NEVER_ADMITTED_SESSION",
            WfpModified=false,JobCreated=false,ClaudeLaunched=false,UserConfigurationModified=false,ProtectionQualified=false}));
    }
    private sealed class FreshInactiveLease : ILifecycleRuntimeLease
    {
        private readonly ProtectedState state;
        private readonly BootstrapApproval approval;
        private bool disposed;
        internal FreshInactiveLease(ProtectedState state,BootstrapApproval approval)
        {
            this.state=state;this.approval=approval;
            state.AssertFreshEmpty();
            AssertNoOwnedProcesses();
        }
        public void AssertLaunchAdmissionClosed()
        {
            if(disposed || !state.CreatedInThisProcess)throw new InvalidOperationException("Fresh installation lease lost");
            state.AssertHeld();approval.AssertHeld();
            var pointer=state.ReadOptional("current.json");
            if(pointer is not null)_=CurrentPointer.Parse(pointer,state.InstallationId); // Must remain INACTIVE.
        }
        public void AssertNoOwnedProcesses()
        {
            AssertLaunchAdmissionClosed();
            // This newly random installation ID has never exposed admission.
            // No empty Job snapshot is promoted to general process ownership.
            if(state.ListLeaves("job-intent-").Length!=0 || state.ListLeaves("fence-intent-").Length!=0)
                throw new InvalidOperationException("Runtime registration is outside fresh-install authority");
        }
        public void StopAndVerifyOwnedProcesses()=>AssertNoOwnedProcesses();
        public void RemoveAndVerifyExactOwnedResources(string installationId)=>throw new InvalidOperationException("Fresh lease cannot remove resources");
        public void AssertNoOwnedResources(string installationId)=>throw new InvalidOperationException("Fresh lease cannot qualify resource removal");
        public void Dispose(){disposed=true;}
    }
}
