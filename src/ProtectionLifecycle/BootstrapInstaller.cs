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
    internal static BootstrapApproval Open()
    {
        ProtectedState.RequireAdministrator();
        var result=new BootstrapApproval();
        try
        {
            var root=WindowsPathSeal.Canonical(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ClaudeCodeProtection-Bootstrap"));
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
            if(result.files.Count!=5 || result.files[4].Length!=lifecycle.Length || Convert.ToHexString(SHA256.HashData(result.files[4]))!=lifecycle.SHA256)
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
