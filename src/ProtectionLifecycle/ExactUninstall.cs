using System.ComponentModel;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record RemovalDirectory(string Role,string Identity,string CreationTag);
internal sealed record RemovalFile(string Role,string Identity,long Length,string SHA256,string CreationTag,string ByteState);
internal sealed record RemovalPage(int SchemaVersion,string InstallationId,string OperationId,string Release,string IntentSHA256,RemovalDirectory[] Directories,RemovalFile[] Files);
internal sealed record RemovalPageLink(string Release,string SHA256);
internal sealed record RemovalRoot(int SchemaVersion,string InstallationId,string OperationId,RemovalDirectory? Code,RemovalFile? Marker,RemovalDirectory? Versions,RemovalPageLink[] Pages);

// The saved intent authorizes only fixed catalog entries, never arbitrary paths.
internal sealed class CleanupIntent
{
    internal string Release { get; }
    internal string ManifestSHA256 { get; }
    private readonly HashSet<string> evidence=new(StringComparer.Ordinal);
    internal string SHA256 => evidence.OrderBy(h=>h,StringComparer.Ordinal).First();
    internal bool MatchesEvidence(string hash)=>evidence.Contains(hash);
    internal IReadOnlyList<PayloadFile> Files { get; }
    private CleanupIntent(string release,string manifest,string hash,IReadOnlyList<PayloadFile> files)
    {Release=release;ManifestSHA256=manifest;evidence.Add(hash);Files=files;}
    internal static Dictionary<string,CleanupIntent> ReadAll(ProtectedState state)
    {
        var result=new Dictionary<string,CleanupIntent>(StringComparer.Ordinal);
        foreach(var leaf in state.ListLeaves("stage-intent-"))
        {
            if(leaf.Length!=50)throw new InvalidDataException("Unexpected stage intent name");
            var operation=Identifiers.Hex32(leaf.Substring(13,32));
            var scope=CreationIdentity.ReadScope(state,operation);
            var intent=new CleanupIntent(scope.Release,scope.ManifestSHA256,scope.IntentSHA256,scope.Files);
            if(!result.TryAdd(scope.Release,intent))
            {
                var prior=result[scope.Release];
                if(prior.ManifestSHA256!=intent.ManifestSHA256 || prior.Files.Count!=intent.Files.Count ||
                    prior.Files.Any(f=>!intent.Files.Contains(f)))
                    throw new InvalidDataException("Conflicting release intents refused");
                // A failed repeat of CREATE_NEW can leave an identical intent.
                // Agreeing scopes may share cleanup authority; choose a stable
                // digest without inventing which operation created the object.
                prior.evidence.Add(intent.SHA256);
            }
        }
        return result;
    }
}

internal static class ExactUninstall
{
    internal static string Start(FixedLayout layout,ProtectedState state,ILifecycleRuntimeLease runtime)
    {
        RejectSelfHostedRemoval(layout);
        state.AssertHeld();runtime.AssertLaunchAdmissionClosed();var tx=new LifecycleTransaction(state,"uninstall",null,runtime);
        runtime.StopAndVerifyOwnedProcesses();EnsureRuntime(state,runtime);
        var inventory=RemovalInventory.CaptureOrRead(layout,state,tx,runtime);
        Continue(layout,state,runtime,tx,inventory);return tx.Id;
    }
    internal static string Resume(FixedLayout layout,ProtectedState state,string operationId,ILifecycleRuntimeLease runtime)
    {
        RejectSelfHostedRemoval(layout);
        state.AssertHeld();runtime.AssertLaunchAdmissionClosed();
        var preview=LifecycleJournal.Read(state,Identifiers.Hex32(operationId));
        if(preview.Operation!="uninstall")throw new InvalidDataException("Requested recovery is not an uninstall");
        LifecycleRecovery.AssertNoPending(state,preview.OperationId);
        var current=state.ReadOptional("current.json");
        if(current is not null && current.SHA256!=preview.PriorPointer?.SHA256)throw new InvalidDataException("Recovery would affect a different current version");
        runtime.StopAndVerifyOwnedProcesses();EnsureRuntime(state,runtime);var tx=LifecycleTransaction.ResumeUninstall(state,operationId,runtime);
        var inventory=tx.Phase=="planned"?RemovalInventory.CaptureOrRead(layout,state,tx,runtime):RemovalInventory.Read(state,tx.Id);
        state.WriteNew("uninstall-resume-"+tx.Id+"-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,InstallationId=state.InstallationId,OperationId=tx.Id,ResumedFrom=tx.Phase,InventorySHA256=inventory.SHA256,AtUtc=DateTime.UtcNow.ToString("o")
        }));
        Continue(layout,state,runtime,tx,inventory);return tx.Id;
    }
    private static void Continue(FixedLayout layout,ProtectedState state,ILifecycleRuntimeLease runtime,LifecycleTransaction tx,RemovalInventory inventory)
    {
        tx.AssertAuthority(state,runtime);inventory.Preflight(layout);
        if(tx.Phase=="planned")
        {EnsureRuntime(state,runtime);tx.ObserveAndAdvance("quiesce",inventory.SHA256);}
        if(tx.Phase=="quiescent")
        {
            EnsureRuntime(state,runtime);runtime.RemoveAndVerifyExactOwnedResources(state.InstallationId);
            runtime.AssertNoOwnedResources(state.InstallationId);tx.ObserveAndAdvance("clear-resources",inventory.SHA256);
        }
        if(tx.Phase=="resources-cleared")
        {
            EnsureRuntime(state,runtime);runtime.AssertNoOwnedResources(state.InstallationId);
            state.RemoveCurrent(tx.PriorPointer?.SHA256);tx.ObserveAndAdvance("remove-pointer",inventory.SHA256);
        }
        if(tx.Phase=="pointer-removed")
        {
            AssertPointerAbsent(state);EnsureRuntime(state,runtime);runtime.AssertNoOwnedResources(state.InstallationId);
            inventory.Remove(layout,()=>{EnsureRuntime(state,runtime);runtime.AssertNoOwnedResources(state.InstallationId);AssertPointerAbsent(state);});
            tx.ObserveAndAdvance("remove-payload",inventory.SHA256);
        }
        if(tx.Phase=="payload-removed")
        {
            AssertRemoved(layout,state,runtime,inventory);
            tx.ObserveAndAdvance("finish",inventory.SHA256);
        }
        if(tx.Phase!="completed-removed")throw new InvalidOperationException("Uninstall did not reach its terminal state");
        // Even a completed ledger must be rechecked against current OS state.
        AssertRemoved(layout,state,runtime,inventory);
        state.WriteNew("uninstall-final-"+tx.Id+"-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,InstallationId=state.InstallationId,OperationId=tx.Id,InventorySHA256=inventory.SHA256,
            CodeRootObservedAbsent=true,CurrentPointerObservedAbsent=true,OwnedProcessesObservedZero=true,OwnedResourcesObservedAbsent=true,
            UserConfigRemoved=false,EvidenceRemoved=false,AtUtc=DateTime.UtcNow.ToString("o")
        }));
    }
    private static void EnsureRuntime(ProtectedState state,ILifecycleRuntimeLease runtime)
    {state.AssertHeld();runtime.AssertLaunchAdmissionClosed();runtime.AssertNoOwnedProcesses();}
    private static void AssertPointerAbsent(ProtectedState state)
    {if(state.ReadOptional("current.json") is not null)throw new InvalidOperationException("Current pointer still present during exact removal");}
    private static void AssertRemoved(FixedLayout layout,ProtectedState state,ILifecycleRuntimeLease runtime,RemovalInventory inventory)
    {EnsureRuntime(state,runtime);runtime.AssertNoOwnedResources(state.InstallationId);AssertPointerAbsent(state);inventory.AssertAbsent(layout);}
    private static void RejectSelfHostedRemoval(FixedLayout layout)
    {
        var process=Environment.ProcessPath??throw new InvalidOperationException("Maintenance host path unavailable");
        var own=typeof(ExactUninstall).Assembly.Location;
        if(string.IsNullOrEmpty(own))throw new InvalidOperationException("A separately verified file-backed maintenance host is required");
        bool Inside(string path)=>WindowsPathSeal.Canonical(path).StartsWith(layout.CodeRoot+"\\",StringComparison.OrdinalIgnoreCase);
        if(Inside(process) || Inside(own) || AppDomain.CurrentDomain.GetAssemblies().Where(a=>!a.IsDynamic).Any(a=>!string.IsNullOrEmpty(a.Location) && Inside(a.Location)))
            throw new InvalidOperationException("Refusing to remove a code tree loaded by this maintenance host");
        // Being outside the payload is only a self-removal precondition. The
        // bootstrap and every dependency still need independent trust approval.
    }
}

// Paged, immutable administrator inventory. No absolute/relative path is accepted
// from the JSON. All paths are reconstructed from FixedLayout, release and role.
internal sealed class RemovalInventory
{
    private readonly ProtectedState state;
    private readonly RemovalRoot root;
    private readonly IReadOnlyList<RemovalPage> pages;
    internal string SHA256 { get; }
    internal string OperationId => root.OperationId;
    private RemovalInventory(ProtectedState state,RemovalRoot root,IReadOnlyList<RemovalPage> pages,string hash)
    {this.state=state;this.root=root;this.pages=pages;SHA256=hash;}
    internal static string Leaf(string id)=>"removal-"+Identifiers.Hex32(id)+".json";
    private static string PageLeaf(string id,string release)=>"removal-part-"+Identifiers.Hex32(id)+"-"+Identifiers.Hex32(release)+".json";
    internal static RemovalInventory CaptureOrRead(FixedLayout layout,ProtectedState state,LifecycleTransaction tx,ILifecycleRuntimeLease runtime)
    {
        tx.AssertAuthority(state,runtime);
        if(tx.Operation!="uninstall" || tx.Phase!="planned")throw new InvalidOperationException("Inventory requires planned uninstall");
        var old=state.ReadOptional(Leaf(tx.Id));if(old is not null)return Read(state,tx.Id);
        var intents=CleanupIntent.ReadAll(state);var pages=new List<RemovalPage>();var links=new List<RemovalPageLink>();
        RemovalDirectory? codeEntry=null,versionsEntry=null;RemovalFile? markerEntry=null;
        using(var code=TryDirectory(layout.CodeRoot))
        {
            if(code is not null)
            {
                codeEntry=CaptureDirectory(code,state,"code",null);
                CheckChildren(code,new[]{"installation.json","versions"});
                var marker=TryReadFile(state,code,"root-marker","installation.json",null);
                if(marker is not null)
                {
                    markerEntry=marker;
                }
                using(var versions=TryDirectory(layout.Versions))
                {
                    if(versions is not null)
                    {
                        versionsEntry=CaptureDirectory(versions,state,"versions",null);
                        var releases=WindowsPathSeal.EnumerateNames(versions).Select(Identifiers.Hex32).OrderBy(p=>p,StringComparer.Ordinal).ToArray();
                        if(releases.Length>RemovalPolicy.MaximumVersions)throw new InvalidDataException("Removal master capacity exceeded; no cleanup started");
                        foreach(var release in releases)
                        {
                            if(!intents.TryGetValue(release,out var intent))throw new InvalidDataException("Unowned version directory refused");
                            var page=CapturePage(layout,state,tx.Id,intent);var bytes=JsonSerializer.SerializeToUtf8Bytes(page);
                            var leaf=PageLeaf(tx.Id,release);var previous=state.ReadOptional(leaf);string hash;
                            if(previous is null)hash=state.WriteNew(leaf,bytes);
                            else {hash=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));if(previous.SHA256!=hash)throw new InvalidDataException("Interrupted removal inventory changed");}
                            pages.Add(page);links.Add(new(release,hash));
                        }
                    }
                }
            }
        }
        var master=new RemovalRoot(3,state.InstallationId,tx.Id,codeEntry,markerEntry,versionsEntry,links.ToArray());
        var masterHash=state.WriteNew(Leaf(tx.Id),JsonSerializer.SerializeToUtf8Bytes(master));
        return new(state,master,pages.AsReadOnly(),masterHash);
    }
    private static RemovalPage CapturePage(FixedLayout layout,ProtectedState state,string operation,CleanupIntent intent)
    {
        var directories=new List<RemovalDirectory>();var files=new List<RemovalFile>();
        using var version=WindowsPathSeal.LockDirectory(layout.Version(intent.Release),PathPolicy.Protected);
        directories.Add(CaptureDirectory(version,state,"release",intent.Release));CheckChildren(version,new[]{"version.json","package.json","bin"});
        var marker=TryReadFile(state,version,"version-marker","version.json",intent.Release);
        if(marker is not null)
        {
            files.Add(marker);
        }
        var manifest=TryReadFile(state,version,"package-manifest","package.json",intent.Release);
        if(manifest is not null)files.Add(manifest);
        using var bin=TryDirectory(WindowsPathSeal.Child(version.Path,"bin"));
        if(bin is not null)
        {
            var groups=intent.Files.GroupBy(f=>f.Asset.BinRole,StringComparer.Ordinal).ToArray();
            directories.Add(CaptureDirectory(bin,state,"bin",intent.Release));CheckChildren(bin,groups.Select(g=>g.Key));
            foreach(var group in groups)
            {
                var role=group.Key;
                using var parent=TryDirectory(WindowsPathSeal.Child(bin.Path,role));if(parent is null)continue;
                directories.Add(CaptureDirectory(parent,state,role,intent.Release));
                CheckChildren(parent,group.Select(f=>Path.GetFileName(f.Asset.Path)));
                foreach(var file in group)
                {
                    var observed=TryReadFile(state,parent,file.Asset.Id,Path.GetFileName(file.Asset.Path),intent.Release);
                    if(observed is null)continue;
                    files.Add(observed);
                }
            }
        }
        return new(3,state.InstallationId,operation,intent.Release,intent.SHA256,directories.ToArray(),files.ToArray());
    }
    internal static RemovalInventory Read(ProtectedState state,string operation)
    {
        operation=Identifiers.Hex32(operation);var raw=state.Read(Leaf(operation));using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=8});var r=doc.RootElement;
        StrictJson.Fields(r,"SchemaVersion","InstallationId","OperationId","Code","Marker","Versions","Pages");AssertHeader(r,state,operation);
        var code=ReadDirectory(r.GetProperty("Code"),new[]{"code"});var marker=ReadEntry(r.GetProperty("Marker"),new[]{"root-marker"});var versions=ReadDirectory(r.GetProperty("Versions"),new[]{"versions"});
        var array=r.GetProperty("Pages");if(array.GetArrayLength()>RemovalPolicy.MaximumVersions)throw new InvalidDataException("Unbounded removal master");
        var links=new List<RemovalPageLink>();var pages=new List<RemovalPage>();var seen=new HashSet<string>(StringComparer.Ordinal);var intents=CleanupIntent.ReadAll(state);
        foreach(var entry in array.EnumerateArray())
        {
            StrictJson.Fields(entry,"Release","SHA256");var release=Identifiers.Hex32(StrictJson.Text(entry,"Release"));var hash=Identifiers.Hash(StrictJson.Text(entry,"SHA256"));
            if(!seen.Add(release) || !intents.TryGetValue(release,out var intent))throw new InvalidDataException("Unowned/duplicate removal page");
            var part=state.Read(PageLeaf(operation,release),32768);if(part.SHA256!=hash)throw new InvalidDataException("Removal page changed");
            using var pd=JsonDocument.Parse(part.Bytes);var p=pd.RootElement;StrictJson.Fields(p,"SchemaVersion","InstallationId","OperationId","Release","IntentSHA256","Directories","Files");AssertHeader(p,state,operation);
            var intentHash=Identifiers.Hash(StrictJson.Text(p,"IntentSHA256"));
            if(StrictJson.Text(p,"Release")!=release || !intent.MatchesEvidence(intentHash))throw new InvalidDataException("Removal page intent differs");
            var dirRoles=new[]{"release","bin"}.Concat(PackageAssetCatalog.BinRoles(intent.Files.Select(f=>f.Asset))).ToArray();
            var dirs=p.GetProperty("Directories").EnumerateArray().Select(n=>ReadDirectory(n,dirRoles)??throw new InvalidDataException()).ToArray();
            var roles=intent.Files.Select(f=>f.Asset.Id).Concat(new[]{"version-marker","package-manifest"}).ToArray();
            var files=p.GetProperty("Files").EnumerateArray().Select(n=>ReadEntry(n,roles)??throw new InvalidDataException()).ToArray();
            if(dirs.Length>dirRoles.Length || files.Length>roles.Length || dirs.Select(d=>d.Role).Distinct(StringComparer.Ordinal).Count()!=dirs.Length || files.Select(f=>f.Role).Distinct(StringComparer.Ordinal).Count()!=files.Length ||
                !dirs.Any(d=>d.Role=="release"))throw new InvalidDataException("Removal page structure differs");
            if(dirs.Any(d=>IsBinChild(d.Role)) && !dirs.Any(d=>d.Role=="bin"))throw new InvalidDataException("Missing captured parent directory");
            foreach(var file in files)
            {
                var expected=intent.Files.SingleOrDefault(f=>f.Asset.Id==file.Role);
                if(expected is not null)
                {
                    var parent=expected.Asset.BinRole;
                    if(!dirs.Any(d=>d.Role==parent) || (file.ByteState==PendingFileAuthority.ExpectedBytes && (file.Length!=expected.Length || file.SHA256!=expected.SHA256)))throw new InvalidDataException("Removal asset differs from authorized intent");
                }
                else if(file.Role=="package-manifest" && file.ByteState==PendingFileAuthority.ExpectedBytes && file.SHA256!=intent.ManifestSHA256)throw new InvalidDataException("Removal manifest differs from intent");
                PendingFileAuthority.ValidateSaved(state,file,release);
            }
            foreach(var dir in dirs)ValidateDirectoryTag(state,dir,release);
            links.Add(new(release,hash));pages.Add(new(3,state.InstallationId,operation,release,intentHash,dirs,files));
        }
        if((code is null && (marker is not null || versions is not null || pages.Count!=0)) || (versions is null && pages.Count!=0))throw new InvalidDataException("Removal root structure differs");
        if(code is not null)ValidateDirectoryTag(state,code,null);if(versions is not null)ValidateDirectoryTag(state,versions,null);
        if(marker is not null)PendingFileAuthority.ValidateSaved(state,marker,null);
        return new(state,new(3,state.InstallationId,operation,code,marker,versions,links.ToArray()),pages.AsReadOnly(),raw.SHA256);
    }
    private static void AssertHeader(JsonElement r,ProtectedState state,string operation)
    {if(r.GetProperty("SchemaVersion").GetInt32()!=3 || StrictJson.Text(r,"InstallationId")!=state.InstallationId || StrictJson.Text(r,"OperationId")!=operation)throw new InvalidDataException("Foreign/legacy removal inventory");}
    private static RemovalDirectory? ReadDirectory(JsonElement n,string[] roles)
    {if(n.ValueKind==JsonValueKind.Null)return null;StrictJson.Fields(n,"Role","Identity","CreationTag");var role=StrictJson.Text(n,"Role");var tag=StrictJson.Text(n,"CreationTag");if(!roles.Contains(role,StringComparer.Ordinal) || CreationTag.TryParse(tag) is null)throw new InvalidDataException("Unknown removal directory role/tag");return new(role,Identifiers.ObjectIdentity(StrictJson.Text(n,"Identity")),tag);}
    private static RemovalFile? ReadEntry(JsonElement n,string[] roles)
    {
        if(n.ValueKind==JsonValueKind.Null)return null;StrictJson.Fields(n,"Role","Identity","Length","SHA256","CreationTag","ByteState");var role=StrictJson.Text(n,"Role");var length=n.GetProperty("Length").GetInt64();
        var tag=StrictJson.Text(n,"CreationTag");var byteState=StrictJson.Text(n,"ByteState");
        if(!roles.Contains(role,StringComparer.Ordinal) || length<0 || CreationTag.TryParse(tag) is null ||
            byteState is not (PendingFileAuthority.ExpectedBytes or PendingFileAuthority.OwnedPending))throw new InvalidDataException("Unknown/invalid removal file");
        return new(role,Identifiers.ObjectIdentity(StrictJson.Text(n,"Identity")),length,Identifiers.Hash(StrictJson.Text(n,"SHA256")),tag,byteState);
    }
    internal void Preflight(FixedLayout layout)
    {
        state.AssertHeld();using var code=TryDirectory(layout.CodeRoot);if(code is null)return;
        MatchDirectory(code,root.Code);CheckChildren(code,(root.Marker is null?Array.Empty<string>():new[]{"installation.json"}).Concat(root.Versions is null?Array.Empty<string>():new[]{"versions"}));
        if(root.Marker is not null)MatchFile(state,code,root.Marker,"installation.json",null);
        using var versions=TryDirectory(layout.Versions);if(versions is null)return;
        MatchDirectory(versions,root.Versions);CheckChildren(versions,root.Pages.Select(p=>p.Release));
        foreach(var page in pages)
        {
            using var version=TryDirectory(layout.Version(page.Release));if(version is null)continue;MatchDirectory(version,page.Directories.Single(d=>d.Role=="release"));
            CheckChildren(version,page.Files.Where(f=>f.Role is "version-marker" or "package-manifest").Select(f=>f.Role=="version-marker"?"version.json":"package.json").Concat(page.Directories.Any(d=>d.Role=="bin")?new[]{"bin"}:Array.Empty<string>()));
            foreach(var file in page.Files.Where(f=>f.Role is "version-marker" or "package-manifest"))MatchFile(state,version,file,file.Role=="version-marker"?"version.json":"package.json",page.Release);
            using var bin=TryDirectory(WindowsPathSeal.Child(version.Path,"bin"));if(bin is null)continue;MatchDirectory(bin,page.Directories.SingleOrDefault(d=>d.Role=="bin"));
            var children=page.Directories.Where(d=>IsBinChild(d.Role)).ToArray();
            CheckChildren(bin,children.Select(d=>d.Role));
            foreach(var child in children)
            {
                using var parent=TryDirectory(WindowsPathSeal.Child(bin.Path,child.Role));if(parent is null)continue;MatchDirectory(parent,child);
                var files=page.Files.Where(f=>FileRelative(f.Role).StartsWith("bin/"+child.Role+"/",StringComparison.Ordinal)).ToArray();
                CheckChildren(parent,files.Select(f=>Path.GetFileName(FileRelative(f.Role))));
                foreach(var file in files)MatchFile(state,parent,file,Path.GetFileName(FileRelative(file.Role)),page.Release);
            }
        }
    }
    internal void Remove(FixedLayout layout,Action assertRuntimeSafe)
    {
        Preflight(layout);assertRuntimeSafe();
        foreach(var page in pages)
        {
            foreach(var file in page.Files)
            {
                var relative=FileRelative(file.Role);var parent=Path.GetDirectoryName(WindowsPathSeal.Child(layout.Version(page.Release),relative))!;
                DeleteFile(parent,Path.GetFileName(relative),file,page.Release,assertRuntimeSafe);
            }
        }
        if(root.Marker is not null)DeleteFile(layout.CodeRoot,"installation.json",root.Marker,null,assertRuntimeSafe);
        foreach(var page in pages)
        {
            foreach(var dir in page.Directories.OrderByDescending(d=>DirRelative(d.Role).Count(c=>c=='/')).ThenByDescending(d=>DirRelative(d.Role).Length))
            {
                var path=dir.Role=="release"?layout.Version(page.Release):WindowsPathSeal.Child(layout.Version(page.Release),DirRelative(dir.Role));
                DeleteDirectory(path,dir,page.Release,PathPolicy.Protected,assertRuntimeSafe);
            }
        }
        if(root.Versions is not null)DeleteDirectory(layout.Versions,root.Versions,null,PathPolicy.Protected,assertRuntimeSafe);
        if(root.Code is not null)DeleteDirectory(layout.CodeRoot,root.Code,null,PathPolicy.TrustedAncestor,assertRuntimeSafe);
        AssertAbsent(layout);
    }
    internal void AssertAbsent(FixedLayout layout)
    {state.AssertHeld();using var code=TryDirectory(layout.CodeRoot);if(code is not null)throw new IOException("Owned code root not verified absent");}
    private void DeleteFile(string parentPath,string leaf,RemovalFile expected,string? release,Action assertRuntimeSafe)
    {
        using var parent=TryDirectory(parentPath);if(parent is null)return;
        var path=WindowsPathSeal.Child(parent.Path,leaf);var attempt=Guid.NewGuid().ToString("N");
        try
        {
            using(var handle=TryDeleteHandle(path,false))
            {
                if(handle is null)return;using var stream=new FileStream(handle,FileAccess.Read,65536,false);
                var actual=PendingFileAuthority.Observe(state,stream,expected.Role,release);
                var identitySame=actual.Identity==expected.Identity && actual.CreationTag==expected.CreationTag;
                var contentSame=actual.Length==expected.Length && actual.SHA256==expected.SHA256 && actual.ByteState==expected.ByteState;
                RemovalPolicy.DemandFile(identitySame,contentSame);
                assertRuntimeSafe();RecordAttempt(attempt,release,expected.Role,"BEFORE_DELETE",null);WindowsPathSeal.MarkDelete(handle);
            }
            using var remaining=TryDeleteHandle(path,false);if(remaining is not null)throw new IOException("Deleted file still present");
            RecordAttempt(attempt,release,expected.Role,"ABSENT_VERIFIED",null);
        }
        catch(Exception ex){try{RecordAttempt(attempt,release,expected.Role,"FAILED",ex.GetType().Name,ex is Win32Exception native?native.NativeErrorCode:ex.HResult);}catch(Exception log){throw new AggregateException("Deletion and failure recording both failed",ex,log);}throw;}
    }
    private void DeleteDirectory(string path,RemovalDirectory expected,string? release,PathPolicy parentPolicy,Action assertRuntimeSafe)
    {
        using var parent=TryDirectory(Path.GetDirectoryName(path)!,parentPolicy);if(parent is null)return;var attempt=Guid.NewGuid().ToString("N");
        try
        {
            using(var handle=TryDeleteHandle(path,true))
            {
                if(handle is null)return;RemovalPolicy.DemandDirectory(WindowsPathSeal.Identity(handle)==expected.Identity && WindowsPathSeal.ReadCreationTag(handle).Sid==expected.CreationTag,WindowsPathSeal.EnumerateNames(handle,path,1).Length==0);
                assertRuntimeSafe();RecordAttempt(attempt,release,expected.Role,"BEFORE_DELETE",null);WindowsPathSeal.MarkDelete(handle);
            }
            using var remaining=TryDeleteHandle(path,true);if(remaining is not null)throw new IOException("Deleted directory still present");
            RecordAttempt(attempt,release,expected.Role,"ABSENT_VERIFIED",null);
        }
        catch(Exception ex){try{RecordAttempt(attempt,release,expected.Role,"FAILED",ex.GetType().Name,ex is Win32Exception native?native.NativeErrorCode:ex.HResult);}catch(Exception log){throw new AggregateException("Deletion and failure recording both failed",ex,log);}throw;}
    }
    private void RecordAttempt(string attempt,string? release,string role,string status,string? failure,int? code=null)
    {state.WriteNew("remove-step-"+root.OperationId+"-"+attempt+"-"+status.ToLowerInvariant().Replace('_','-')+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,InstallationId=state.InstallationId,OperationId=root.OperationId,InventorySHA256=SHA256,Release=release,Role=role,Status=status,FailureType=failure,FailureCode=code,AtUtc=DateTime.UtcNow.ToString("o")}));}
    private static string FileRelative(string role)=>role=="version-marker"?"version.json":role=="package-manifest"?"package.json":PackageAssetCatalog.KnownAssets.Single(a=>a.Id==role).Path;
    private static bool IsBinChild(string role)=>role is not ("release" or "bin");
    private static string DirRelative(string role)=>role switch {
        "release"=>"","bin"=>"bin",
        "current" or "center" or "admin" or PackageAssetCatalog.OfficialClaudeBinRole=>"bin/"+role,
        _=>throw new InvalidDataException("Unknown directory role")
    };
    private static void MatchDirectory(PathLease actual,RemovalDirectory? expected)
    {if(expected is null || actual.ObjectIdentity()!=expected.Identity || actual.ReadCreationTag().Sid!=expected.CreationTag)throw new InvalidDataException("New/replaced/retagged directory refused");}
    private static void MatchFile(ProtectedState state,PathLease parent,RemovalFile expected,string leaf,string? release)
    {
        var actual=TryReadFile(state,parent,expected.Role,leaf,release);
        if(actual is not null && actual!=expected)throw new InvalidDataException("New/replaced/drifted file refused");
    }
    private static void CheckChildren(PathLease parent,IEnumerable<string> allowed)
    {parent.AssertHeld();var names=new HashSet<string>(allowed,StringComparer.OrdinalIgnoreCase);foreach(var name in WindowsPathSeal.EnumerateNames(parent))if(!names.Remove(name))throw new InvalidDataException("Unexpected/duplicate child retained");}
    private static PathLease? TryDirectory(string path,PathPolicy policy=PathPolicy.Protected)
    {
        try{return WindowsPathSeal.LockDirectory(path,policy);}
        catch(ExactPathAbsentException ex)when(IsOwnedMissingPath(ex.FailedPath)){return null;}
    }
    private static bool IsOwnedMissingPath(string failed)
    {var root=FixedLayout.FromWindows().CodeRoot;return string.Equals(failed,root,StringComparison.OrdinalIgnoreCase) || failed.StartsWith(root+"\\",StringComparison.OrdinalIgnoreCase);}
    private static Microsoft.Win32.SafeHandles.SafeFileHandle? TryDeleteHandle(string path,bool directory)
    {try{return WindowsPathSeal.OpenForDelete(path,directory);}catch(ExactPathAbsentException ex)when(IsOwnedMissingPath(ex.FailedPath)){return null;}}
    private static RemovalFile? TryReadFile(ProtectedState state,PathLease parent,string role,string leaf,string? release)
    {try{return ReadFile(state,parent,role,leaf,release);}catch(ExactPathAbsentException ex)when(IsOwnedMissingPath(ex.FailedPath)){return null;}}
    private static RemovalDirectory CaptureDirectory(PathLease directory,ProtectedState state,string role,string? release)
    {
        if(role=="code")CreationIdentity.AssertRoot(directory,state,CreationRole.CodeRoot);else CreationIdentity.AssertDirectory(directory,state,role,release);
        return new(role,directory.ObjectIdentity(),directory.ReadCreationTag().Sid);
    }
    private static void ValidateDirectoryTag(ProtectedState state,RemovalDirectory directory,string? release)
    {
        var tag=CreationTag.TryParse(directory.CreationTag)??throw new InvalidDataException("Missing directory creation proof");
        if(directory.Role=="code"){if(tag.Sid!=CreationTag.For(CreationRole.CodeRoot,state.InstallationId).Sid)throw new InvalidDataException("Foreign root creation proof");}
        else _=CreationIdentity.AssertStageTag(state,tag,CreationTag.DirectoryRole(directory.Role),release);
    }
    private static RemovalFile ReadFile(ProtectedState state,PathLease parent,string role,string leaf,string? release)
    {
        parent.AssertHeld();using var handle=WindowsPathSeal.Open(WindowsPathSeal.Child(parent.Path,leaf),false,true);WindowsPathSeal.AssertAcl(handle,true);
        using var stream=new FileStream(handle,FileAccess.Read,65536,false);
        return PendingFileAuthority.Observe(state,stream,role,release);
    }
}
