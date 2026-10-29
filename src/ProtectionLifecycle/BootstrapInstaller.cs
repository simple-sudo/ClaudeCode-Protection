using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

namespace ProtectionLifecycle;

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
    // Migration from pinned reviewed packages with no admission or completed
    // one-shot admissions. This is not a generic empty-job/runtime lease.
    public static (int ExitCode,string Report) UpdatePinnedInactive()
    {
        // Inactive maintenance has its own narrower qualification boundary.
        // It does not execute a child, activate forwarding or clear the still
        // unqualified system/session entries. The exact bootstrap is reviewed
        // and pinned independently after compilation, before human UAC.
        ProtectedState.RequireAdministrator();
        using var approval=BootstrapApproval.Open(true);
        var package=ReviewedPackage.FromBootstrap(approval);
        var layout=FixedLayout.FromWindows();
        using var state=ProtectedState.OpenExisting(layout);
        var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
        using var prior=VerifiedVersion.Open(layout,state,current.Release);
        using var runtime=new PinnedInactiveUpdateLease(state,approval,prior,package);
        var operation=VersionLifecycle.InstallOrUpdate(layout,state,package,approval.PayloadDirectory,"update",runtime);
        using var verified=VerifiedVersion.Open(layout,state,package.Release);
        var after=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
        if(after.Release!=package.Release || after.ManifestSHA256!=package.ManifestHash || after.OperationId!=operation)
            throw new InvalidDataException("Updated inactive selection differs");
        runtime.AssertNoOwnedProcesses();verified.AssertHeld(state);
        return (0,JsonSerializer.Serialize(new {SchemaVersion=1,Status="PINNED_INACTIVE_UPDATE_COMPLETED",state.InstallationId,
            PriorRelease=current.Release,package.Release,package.ManifestHash,OperationId=operation,Activation="INACTIVE",
            RuntimeLeaseScope="PINNED_NO_ADMISSION_OR_CLOSED_ONE_SHOT_JOBS_AND_ABSENT_OR_QUARANTINED_FENCE",WfpModified=false,JobCreated=false,
            ClaudeLaunched=false,UserConfigurationModified=false,ProtectionQualified=false}));
    }

    private sealed class PinnedInactiveUpdateLease : ILifecycleRuntimeLease
    {
        private static readonly string[] NoAdmissionManifests={
            "1D83FA034A65DC58D1FFEB9C4F3A54EA52F1C3B7AF6156A54C752FA5D8801BAC",
            "BB0A619C10B53ECF4AC4E79578C9DF4A058E1758B3B111836A5172F46488E9FD",
            "D21A7D9F39A93E82087062EAD14F49329E7DBDD2743B2DC12DE98CAB6DC691F1"
        }; // Exact reviewed packages expose no launch/admission command.
        private static readonly string[] OneShotAdmissionManifests={
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
            "CB5515C9CED7D08248EA903F7EA2817B2F47D5EA952D366B31ABB775520C4264" // 659d76df closed offline project-transfer package.
        };
        private readonly ProtectedState state;
        private readonly BootstrapApproval approval;
        private readonly VerifiedVersion prior;
        private readonly ReviewedPackage next;
        private bool disposed;
        internal PinnedInactiveUpdateLease(ProtectedState state,BootstrapApproval approval,VerifiedVersion prior,ReviewedPackage next)
        {
            this.state=state;this.approval=approval;this.prior=prior;this.next=next;
            var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
            if(current.Release!=prior.Package.Release || current.ManifestSHA256!=prior.Package.ManifestHash ||
                !(NoAdmissionManifests.Contains(prior.Package.ManifestHash,StringComparer.Ordinal) || OneShotAdmissionManifests.Contains(prior.Package.ManifestHash,StringComparer.Ordinal)) ||
                next.Release==prior.Package.Release || next.ManifestHash==prior.Package.ManifestHash)
                throw new InvalidOperationException("Only pinned reviewed inactive packages can migrate");
            AssertNoOwnedProcesses();
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
            AssertLaunchAdmissionClosed();
            InstallationLoopbackLease.AssertClosedHistory(state);
            var jobs=OwnedJobIntent.ReadAll(state);
            if(NoAdmissionManifests.Contains(prior.Package.ManifestHash,StringComparer.Ordinal) && jobs.Count!=0)
                throw new InvalidOperationException("Job history is outside the pinned no-admission package");
            foreach(var job in jobs)if(AtomicJobCompletion.ReadClosed(state,job) is null)
                throw new InvalidOperationException("Every one-shot Job needs a closed admission and zero-members proof");
            // A failed intent is not absence. Every exact plan must be absent
            // or fully quarantined; no resource is removed during this update.
            foreach(var plan in FencePlan.ReadAll(state))
            {
                using var fence=PersistentFence.OpenExisting(state,plan.Data.FenceId);
                var observed=fence.Observe();
                if(!observed.AllAbsent && !observed.FullQuarantineObserved)throw new InvalidOperationException("Partial or changed fence resources require the full runtime maintenance owner");
            }
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
