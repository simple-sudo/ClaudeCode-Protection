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
            var root=WindowsPathSeal.Canonical(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),inactiveUpdate?"ClaudeCodeProtection-Update-20261027":"ClaudeCodeProtection-Bootstrap"));
            var entry=Assembly.GetEntryAssembly()??throw new InvalidOperationException("Bootstrap entry missing");
            if(entry.GetName().Name!="ProtectionBootstrap" ||
                !Same(Environment.ProcessPath,Path.Combine(root,"ProtectionBootstrap.exe")) ||
                !Same(entry.Location,Path.Combine(root,"ProtectionBootstrap.dll")) ||
                !Same(typeof(BootstrapApproval).Assembly.Location,Path.Combine(root,"ProtectionLifecycle.dll")))
                throw new InvalidOperationException("Fixed protected bootstrap host required");
            result.HoldDirectory(root);
            foreach(var leaf in new[]{"ProtectionBootstrap.exe","ProtectionBootstrap.dll","ProtectionBootstrap.deps.json","ProtectionBootstrap.runtimeconfig.json","ProtectionLifecycle.dll"})
                result.HoldFile(root,leaf);
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
            _=PackagePolicy.ParsePinned(result.Manifest,result.ManifestHash); // Reject placeholder before creating state.
            result.PayloadDirectory=WindowsPathSeal.Child(root,"payload");
            var payload=result.HoldDirectory(result.PayloadDirectory);
            var manifest=ProtectedState.ReadBound(payload,"package.json",PackagePolicy.MaxManifestBytes,true);
            if(!manifest.Bytes.AsSpan().SequenceEqual(result.Manifest.Span))throw new InvalidDataException("Payload approval differs");
            result.HoldFile(payload.Path,"package.json");
            // Hold and verify every input before creating any production state.
            var parsed=PackagePolicy.ParsePinned(result.Manifest,result.ManifestHash);
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
    // One migration from the independently verified original no-admission
    // package. This is not an active-runtime update or generic empty-job lease.
    public static (int ExitCode,string Report) UpdateNeverAdmitted()
    {
        ProtectedState.RequireAdministrator();
        using var approval=BootstrapApproval.Open(true);
        var package=ReviewedPackage.FromBootstrap(approval);
        var layout=FixedLayout.FromWindows();
        using var state=ProtectedState.OpenExisting(layout);
        var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
        using var prior=VerifiedVersion.Open(layout,state,current.Release);
        using var runtime=new NeverAdmittedUpdateLease(state,approval,prior,package);
        var operation=VersionLifecycle.InstallOrUpdate(layout,state,package,approval.PayloadDirectory,"update",runtime);
        using var verified=VerifiedVersion.Open(layout,state,package.Release);
        var after=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
        if(after.Release!=package.Release || after.ManifestSHA256!=package.ManifestHash || after.OperationId!=operation)
            throw new InvalidDataException("Updated inactive selection differs");
        runtime.AssertNoOwnedProcesses();verified.AssertHeld(state);
        return (0,JsonSerializer.Serialize(new {SchemaVersion=1,Status="NEVER_ADMITTED_INACTIVE_UPDATE_COMPLETED",state.InstallationId,
            PriorRelease=current.Release,package.Release,package.ManifestHash,OperationId=operation,Activation="INACTIVE",
            RuntimeLeaseScope="PINNED_ORIGINAL_NO_ADMISSION_PACKAGE_AND_ABSENT_FENCE_OBJECTS",WfpModified=false,JobCreated=false,
            ClaudeLaunched=false,UserConfigurationModified=false,ProtectionQualified=false}));
    }

    private sealed class NeverAdmittedUpdateLease : ILifecycleRuntimeLease
    {
        private const string OriginalManifest="1D83FA034A65DC58D1FFEB9C4F3A54EA52F1C3B7AF6156A54C752FA5D8801BAC";
        private readonly ProtectedState state;
        private readonly BootstrapApproval approval;
        private readonly VerifiedVersion prior;
        private readonly ReviewedPackage next;
        private bool disposed;
        internal NeverAdmittedUpdateLease(ProtectedState state,BootstrapApproval approval,VerifiedVersion prior,ReviewedPackage next)
        {
            this.state=state;this.approval=approval;this.prior=prior;this.next=next;
            var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
            if(current.Release!=prior.Package.Release || current.ManifestSHA256!=OriginalManifest || prior.Package.ManifestHash!=OriginalManifest ||
                next.Release==prior.Package.Release || next.ManifestHash==OriginalManifest)
                throw new InvalidOperationException("Only the pinned original no-admission package can migrate");
            AssertNoOwnedProcesses();
        }
        public void AssertLaunchAdmissionClosed()
        {
            if(disposed)throw new ObjectDisposedException(nameof(NeverAdmittedUpdateLease));
            state.AssertHeld();approval.AssertHeld();prior.AssertHeld(state);
            // The original package has no launch command. Every installed
            // admission/mutation owner must hold this same exclusive lock.
            // New payload stays INACTIVE throughout this one update operation.
            var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
            if(!((current.Release==prior.Package.Release && current.ManifestSHA256==OriginalManifest) ||
                (current.Release==next.Release && current.ManifestSHA256==next.ManifestHash)))
                throw new InvalidDataException("Current pointer escaped the bound inactive migration");
        }
        public void AssertNoOwnedProcesses()
        {
            AssertLaunchAdmissionClosed();
            if(state.ListLeaves("job-intent-").Length!=0)throw new InvalidOperationException("Job history is outside never-admitted update authority");
            // A failed quarantine intent is not absence. Check every exact
            // owned plan against BFE; inaccessible/foreign/present objects fail.
            foreach(var plan in FencePlan.ReadAll(state))
            {
                using var fence=PersistentFence.OpenExisting(state,plan.Data.FenceId);
                if(!fence.Observe().AllAbsent)throw new InvalidOperationException("Existing fence resources require the full runtime maintenance owner");
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
