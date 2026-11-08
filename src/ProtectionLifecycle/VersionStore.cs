using System.Security.Cryptography;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record OwnedReleaseReceipt(int SchemaVersion,string InstallationId,string Release,string ManifestSHA256,string StagedByOperation,string Status)
{
    internal static OwnedReleaseReceipt Read(ProtectedState state,string release)
    {
        release=Identifiers.Hex32(release);
        var raw=state.Read("release-"+release+".json");
        using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=4});
        var root=doc.RootElement;
        StrictJson.Fields(root,"SchemaVersion","InstallationId","Release","ManifestSHA256","StagedByOperation","Status");
        if(root.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(root,"InstallationId")!=state.InstallationId ||
            StrictJson.Text(root,"Release")!=release || StrictJson.Text(root,"Status")!="VERIFIED_PAYLOAD")
            throw new InvalidDataException("Release was not verified by this installation");
        return new(1,state.InstallationId,release,Identifiers.Hash(StrictJson.Text(root,"ManifestSHA256")),
            Identifiers.Hex32(StrictJson.Text(root,"StagedByOperation")),"VERIFIED_PAYLOAD");
    }
}

internal sealed record CurrentPointer(int SchemaVersion,string InstallationId,string Release,string ManifestSHA256,string OperationId,string Activation)
{
    internal static CurrentPointer Parse(BoundBytes raw,string installationId)
    {
        if(raw.Bytes.Length is <1 or >4096 || Convert.ToHexString(SHA256.HashData(raw.Bytes))!=raw.SHA256)
            throw new InvalidDataException("Pointer snapshot differs");
        using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=4});
        var root=doc.RootElement;
        StrictJson.Fields(root,"SchemaVersion","InstallationId","Release","ManifestSHA256","OperationId","Activation");
        if(root.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(root,"InstallationId")!=installationId ||
            StrictJson.Text(root,"Activation")!="INACTIVE") throw new InvalidDataException("Pointer ownership/activation differs");
        return new(1,installationId,Identifiers.Hex32(StrictJson.Text(root,"Release")),Identifiers.Hash(StrictJson.Text(root,"ManifestSHA256")),
            Identifiers.Hex32(StrictJson.Text(root,"OperationId")),"INACTIVE");
    }
}

internal sealed class VerifiedVersion : IDisposable
{
    private readonly ProtectedState owner;
    private readonly List<PathLease> directories;
    private readonly Dictionary<AssetSpec,FileStream> streams;
    private bool disposed;
    internal ReviewedPackage Package { get; }
    private VerifiedVersion(ProtectedState owner,ReviewedPackage package,List<PathLease> directories,Dictionary<AssetSpec,FileStream> streams)
    {this.owner=owner;Package=package;this.directories=directories;this.streams=streams;}

    internal static VerifiedVersion Open(FixedLayout layout,ProtectedState state,string release)
    {
        state.AssertHeld();release=Identifiers.Hex32(release);
        var directories=new List<PathLease>();var streams=new Dictionary<AssetSpec,FileStream>();
        PathLease Hold(string path){var lease=WindowsPathSeal.LockDirectory(path,PathPolicy.Protected);directories.Add(lease);return lease;}
        try
        {
            var code=Hold(layout.CodeRoot);
            CreationIdentity.AssertRoot(code,state,CreationRole.CodeRoot);
            using(var marker=WindowsPathSeal.Open(WindowsPathSeal.Child(code.Path,"installation.json"),false,true))CreationIdentity.AssertFileScope(state,marker,CreationRole.CodeMarker,null);
            var identity=ProtectedState.ReadBound(code,"installation.json",4096,true);
            using(var doc=JsonDocument.Parse(identity.Bytes))
            {
                StrictJson.Fields(doc.RootElement,"SchemaVersion","InstallationId");
                if(doc.RootElement.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(doc.RootElement,"InstallationId")!=state.InstallationId)
                    throw new InvalidDataException("Foreign code root");
            }
            ExactChildren(code,new[]{"installation.json","versions"});
            var versions=Hold(layout.Versions);CreationIdentity.AssertDirectory(versions,state,"versions",null);
            var version=Hold(layout.Version(release));
            CreationIdentity.AssertDirectory(version,state,"release",release);
            ExactChildren(version,new[]{"version.json","package.json","bin"});
            var manifest=ProtectedState.ReadBound(version,"package.json",PackagePolicy.MaxManifestBytes,true);
            using(var file=WindowsPathSeal.Open(WindowsPathSeal.Child(version.Path,"package.json"),false,true))CreationIdentity.AssertFileScope(state,file,CreationRole.PackageManifest,release);
            var package=ReviewedPackage.FromOwnedState(state,release,manifest.Bytes);
            var receipt=ProtectedState.ReadBound(version,"version.json",4096,true);
            using(var file=WindowsPathSeal.Open(WindowsPathSeal.Child(version.Path,"version.json"),false,true))CreationIdentity.AssertFileScope(state,file,CreationRole.VersionMarker,release);
            using(var doc=JsonDocument.Parse(receipt.Bytes))
            {
                var root=doc.RootElement;StrictJson.Fields(root,"SchemaVersion","InstallationId","Release","ManifestSHA256");
                if(root.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(root,"InstallationId")!=state.InstallationId ||
                    StrictJson.Text(root,"Release")!=release || StrictJson.Text(root,"ManifestSHA256")!=package.ManifestHash)
                    throw new InvalidDataException("Foreign/changed version marker");
            }
            var bin=Hold(WindowsPathSeal.Child(version.Path,"bin"));CreationIdentity.AssertDirectory(bin,state,"bin",release);
            ExactChildren(bin,PackageAssetCatalog.BinRoles(package.Files.Select(f=>f.Asset)));
            foreach(var group in package.Files.GroupBy(f=>f.Asset.BinRole,StringComparer.Ordinal))
            {
                var parent=Hold(WindowsPathSeal.Child(bin.Path,group.Key));
                CreationIdentity.AssertDirectory(parent,state,group.Key,release);
                ExactChildren(parent,group.Select(f=>Path.GetFileName(f.Asset.Path)));
                foreach(var file in group)
                {
                    var handle=WindowsPathSeal.Open(WindowsPathSeal.Child(parent.Path,Path.GetFileName(file.Asset.Path)),false,true);
                    try
                    {
                        WindowsPathSeal.AssertAcl(handle,true);
                        CreationIdentity.AssertFileScope(state,handle,CreationTag.AssetRole(file.Asset.Id),release);
                        var stream=new FileStream(handle,FileAccess.Read,65536,false);streams.Add(file.Asset,stream);
                        if(stream.Length!=file.Length || Convert.ToHexString(SHA256.HashData(stream))!=file.SHA256)
                            throw new InvalidDataException("Installed payload differs");
                    }
                    catch{handle.Dispose();throw;}
                }
            }
            return new(state,package,directories,streams);
        }
        catch{foreach(var stream in streams.Values)stream.Dispose();for(var i=directories.Count-1;i>=0;i--)directories[i].Dispose();throw;}
    }
    private static void ExactChildren(PathLease parent,IEnumerable<string> expected)
    {
        parent.AssertHeld();
        var known=new HashSet<string>(expected,StringComparer.OrdinalIgnoreCase);
        var actual=WindowsPathSeal.EnumerateNames(parent);
        if(actual.Length!=known.Count || actual.Any(n=>n is null || !known.Remove(n)) || known.Count!=0)
            throw new InvalidDataException("Unexpected/missing file in protected version layout");
    }
    internal void AssertHeld(ProtectedState state)
    {
        if(disposed || !ReferenceEquals(state,owner)) throw new InvalidOperationException("Version verification lease lost");
        state.AssertHeld();foreach(var directory in directories)directory.AssertHeld();
        foreach(var (asset,stream) in streams)
        {
            if(stream.SafeFileHandle.IsClosed || stream.SafeFileHandle.IsInvalid)throw new IOException("Payload lock lost");
            if(asset==PackageAssetCatalog.OfficialClaudeImage)
            {
                if(WindowsPathSeal.ReadCreationTag(stream.SafeFileHandle).Role!=CreationRole.OfficialClaudeExe ||
                    directories.Single(d=>Path.GetFileName(d.Path)==asset.BinRole).ReadCreationTag().Role!=CreationRole.OfficialClaudeDirectory)
                    throw new IOException("Official image staging ownership lost");
            }
            else WindowsPathSeal.AssertAcl(stream.SafeFileHandle,true);
        }
    }
    public void Dispose()
    {
        if(disposed)return;disposed=true;
        foreach(var stream in streams.Values)stream.Dispose();for(var i=directories.Count-1;i>=0;i--)directories[i].Dispose();
    }
}

internal sealed record SelectionReceipt(int SchemaVersion,string InstallationId,string Release,string ManifestSHA256,string OperationId,string PointerSHA256,string Activation);

internal static class VersionSelector
{
    internal static string SwitchInactive(ProtectedState state,VerifiedVersion version,LifecycleTransaction transaction,ILifecycleRuntimeLease runtime)
    {
        transaction.AssertSwitchAllowed(state,runtime);version.AssertHeld(state);
        if(transaction.Target!=version.Package.Release || transaction.Operation is not ("install" or "update" or "rollback"))
            throw new InvalidOperationException("Version is outside transaction scope");
        var pointer=new CurrentPointer(1,state.InstallationId,version.Package.Release,version.Package.ManifestHash,transaction.Id,"INACTIVE");
        var bytes=JsonSerializer.SerializeToUtf8Bytes(pointer);
        // Prior bytes/hash were frozen before any staging or switching.
        var hash=state.ReplacePointer("current.json",transaction.PriorPointer?.SHA256,bytes);
        var raw=state.Read("current.json",4096);var readback=CurrentPointer.Parse(raw,state.InstallationId);
        if(raw.SHA256!=hash || readback!=pointer)throw new IOException("Current pointer readback differs");
        RecordSelection(state,readback,raw.SHA256);
        return hash;
    }
    internal static void RecordSelection(ProtectedState state,CurrentPointer pointer,string pointerHash)
    {
        if(pointer.InstallationId!=state.InstallationId)throw new InvalidDataException("Foreign selection");
        var leaf="selection-"+pointer.Release+"-"+pointer.OperationId+".json";
        var receipt=new SelectionReceipt(1,state.InstallationId,pointer.Release,pointer.ManifestSHA256,pointer.OperationId,Identifiers.Hash(pointerHash),"INACTIVE");
        var bytes=JsonSerializer.SerializeToUtf8Bytes(receipt);
        var existing=state.ReadOptional(leaf);
        if(existing is null)state.WriteNew(leaf,bytes);
        else if(existing.SHA256!=Convert.ToHexString(SHA256.HashData(bytes)))throw new InvalidDataException("Selection history differs");
    }
    internal static bool WasSelected(ProtectedState state,string release)
    {
        release=Identifiers.Hex32(release);
        var expectedManifest=OwnedReleaseReceipt.Read(state,release).ManifestSHA256;
        foreach(var leaf in state.ListLeaves("selection-").Where(n=>n.StartsWith("selection-"+release+"-",StringComparison.Ordinal)))
        {
            var raw=state.Read(leaf,4096);using var doc=JsonDocument.Parse(raw.Bytes);var root=doc.RootElement;
            StrictJson.Fields(root,"SchemaVersion","InstallationId","Release","ManifestSHA256","OperationId","PointerSHA256","Activation");
            var operationId=Identifiers.Hex32(StrictJson.Text(root,"OperationId"));
            if(root.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(root,"InstallationId")!=state.InstallationId ||
                StrictJson.Text(root,"Release")!=release || StrictJson.Text(root,"ManifestSHA256")!=expectedManifest ||
                StrictJson.Text(root,"Activation")!="INACTIVE" || leaf!="selection-"+release+"-"+operationId+".json")
                throw new InvalidDataException("Selection record identity differs");
            _=Identifiers.Hash(StrictJson.Text(root,"ManifestSHA256"));_=Identifiers.Hash(StrictJson.Text(root,"PointerSHA256"));
            return true;
        }
        return false;
    }
    internal static string ReadSelectionHash(ProtectedState state,string release,string operationId)
    {
        release=Identifiers.Hex32(release);operationId=Identifiers.Hex32(operationId);
        var raw=state.Read("selection-"+release+"-"+operationId+".json",4096);
        using var doc=JsonDocument.Parse(raw.Bytes);var root=doc.RootElement;
        StrictJson.Fields(root,"SchemaVersion","InstallationId","Release","ManifestSHA256","OperationId","PointerSHA256","Activation");
        var expected=OwnedReleaseReceipt.Read(state,release);
        if(root.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(root,"InstallationId")!=state.InstallationId ||
            StrictJson.Text(root,"Release")!=release || StrictJson.Text(root,"OperationId")!=operationId ||
            StrictJson.Text(root,"ManifestSHA256")!=expected.ManifestSHA256 || StrictJson.Text(root,"Activation")!="INACTIVE")
            throw new InvalidDataException("Selected version identity differs");
        return Identifiers.Hash(StrictJson.Text(root,"PointerSHA256"));
    }
}

// Concrete inactive version handlers. They still require the real broker's
// admission/process lease; no fake adapter or automatic production entry exists.
internal static class VersionLifecycle
{
    internal static string InstallOrUpdate(FixedLayout layout,ProtectedState state,ReviewedPackage package,string sourceDirectory,
        string operation,ILifecycleRuntimeLease runtime,Action<string>? observeStage=null)
    {
        if(operation is not ("install" or "update"))throw new InvalidDataException("Invalid staging operation");
        state.AssertHeld();runtime.AssertLaunchAdmissionClosed();runtime.AssertNoOwnedProcesses();
        using var prior=operation=="update"?OpenCurrent(layout,state):null;
        observeStage?.Invoke("LIFECYCLE_BEGIN");
        var tx=new LifecycleTransaction(state,operation,package.Release,runtime);
        observeStage?.Invoke("STAGE_PAYLOAD");
        VersionStager.Stage(layout,state,package,sourceDirectory,runtime,tx);
        tx.ObserveAndAdvance("stage",package.ManifestHash);
        observeStage?.Invoke("VERIFY_PAYLOAD");
        using var version=VerifiedVersion.Open(layout,state,package.Release);
        tx.ObserveAndAdvance("verify",version.Package.ManifestHash);
        observeStage?.Invoke("SWITCH_INACTIVE");
        var hash=VersionSelector.SwitchInactive(state,version,tx,runtime);tx.ObserveAndAdvance("switch",hash);
        observeStage?.Invoke("FINISH_UPDATE");
        Finish(state,version,tx,runtime,hash);return tx.Id;
    }
    internal static string Rollback(FixedLayout layout,ProtectedState state,string release,ILifecycleRuntimeLease runtime)
    {
        state.AssertHeld();runtime.AssertLaunchAdmissionClosed();runtime.AssertNoOwnedProcesses();release=Identifiers.Hex32(release);
        using var prior=OpenCurrent(layout,state);
        if(prior.Package.Release==release || !VersionSelector.WasSelected(state,release))throw new InvalidOperationException("Rollback requires another previously selected owned version");
        var tx=new LifecycleTransaction(state,"rollback",release,runtime);
        using var version=VerifiedVersion.Open(layout,state,release);tx.ObserveAndAdvance("verify",version.Package.ManifestHash);
        var hash=VersionSelector.SwitchInactive(state,version,tx,runtime);tx.ObserveAndAdvance("switch",hash);
        Finish(state,version,tx,runtime,hash);return tx.Id;
    }
    private static VerifiedVersion OpenCurrent(FixedLayout layout,ProtectedState state)
    {
        var raw=state.Read("current.json",4096);var pointer=CurrentPointer.Parse(raw,state.InstallationId);
        var version=VerifiedVersion.Open(layout,state,pointer.Release);
        if(version.Package.ManifestHash==pointer.ManifestSHA256)return version;
        version.Dispose();throw new InvalidDataException("Current pointer and version differ");
    }
    private static void Finish(ProtectedState state,VerifiedVersion version,LifecycleTransaction tx,ILifecycleRuntimeLease runtime,string pointerHash)
    {
        tx.AssertAuthority(state,runtime);version.AssertHeld(state);
        var raw=state.Read("current.json",4096);var current=CurrentPointer.Parse(raw,state.InstallationId);
        if(raw.SHA256!=pointerHash || current.Release!=version.Package.Release || current.OperationId!=tx.Id || current.ManifestSHA256!=version.Package.ManifestHash)
            throw new InvalidDataException("Final current pointer differs");
        tx.ObserveAndAdvance("finish",raw.SHA256);
    }
}
