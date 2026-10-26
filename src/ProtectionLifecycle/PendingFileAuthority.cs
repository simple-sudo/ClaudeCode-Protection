using System.Security.Cryptography;
using System.Text.Json;

namespace ProtectionLifecycle;

// Cleanup authority only. EXPECTED_BYTES is a byte comparison, never package
// approval, activation, runtime health, or evidence that the source was executed.
internal static class PendingFileAuthority
{
    internal const string ExpectedBytes="EXPECTED_BYTES",OwnedPending="OWNED_PENDING";
    internal static CreationRole Role(string role)=>role=="root-marker"?CreationRole.CodeMarker:
        role=="version-marker"?CreationRole.VersionMarker:role=="package-manifest"?CreationRole.PackageManifest:CreationTag.AssetRole(role);

    internal static RemovalFile Observe(ProtectedState state,FileStream stream,string role,string? release)
    {
        state.AssertHeld();var handle=stream.SafeFileHandle;
        WindowsPathSeal.AssertAcl(handle,true);CreationIdentity.AssertFileScope(state,handle,Role(role),release);
        var tag=WindowsPathSeal.ReadCreationTag(handle);var scope=CreationIdentity.AssertStageTag(state,tag,Role(role),release);
        var expected=Expected(state,scope,tag.Role);
        if(stream.Length<0 || stream.Length>expected.Maximum)throw new InvalidDataException("Created file exceeds its fixed cleanup bound");
        stream.Position=0;var hash=Convert.ToHexString(SHA256.HashData(stream));
        var entry=new RemovalFile(role,WindowsPathSeal.Identity(handle),stream.Length,hash,tag.Sid,
            IsExpected(stream.Length,hash,expected)?ExpectedBytes:OwnedPending);
        ValidateSaved(state,entry,release);return entry;
    }

    internal static void ValidateSaved(ProtectedState state,RemovalFile entry,string? release)
    {
        state.AssertHeld();var tag=CreationTag.TryParse(entry.CreationTag)??throw new InvalidDataException("Missing file creation proof");
        var scope=CreationIdentity.AssertStageTag(state,tag,Role(entry.Role),release);
        var expected=Expected(state,scope,tag.Role);
        if(entry.Length<0 || entry.Length>expected.Maximum)throw new InvalidDataException("Saved file exceeds its creation bound");
        _=Identifiers.ObjectIdentity(entry.Identity);_=Identifiers.Hash(entry.SHA256);
        var complete=state.ReadOptional(CreationIdentity.CompletionLeaf(tag));
        if(complete is not null)
        {
            // Corruption, unreadability and a conflicting receipt are failures;
            // they cannot be treated as a missing completion receipt.
            CompletionReceipts.AssertMatches(state,tag,complete,new(entry.CreationTag,entry.Identity,entry.Length,entry.SHA256));
        }
        if(entry.ByteState==ExpectedBytes)
        {
            if(!IsExpected(entry.Length,entry.SHA256,expected))throw new InvalidDataException("Saved expected-byte claim differs");
            return;
        }
        if(entry.ByteState!=OwnedPending || complete is not null || IsExpected(entry.Length,entry.SHA256,expected) || scope.Phase!="planned")
            throw new InvalidDataException("Saved pending-write claim differs");
        AssertUnpublished(state,scope.Release,tag.Role==CreationRole.CodeMarker);
    }

    private sealed record ExpectedFile(string SHA256,long? Length,long Maximum);
    private static ExpectedFile Expected(ProtectedState state,CreationScope scope,CreationRole role)
    {
        if(role==CreationRole.PackageManifest)return new(scope.ManifestSHA256,null,PackagePolicy.MaxManifestBytes);
        if(role is CreationRole.CodeMarker or CreationRole.VersionMarker)
        {
            var bytes=role==CreationRole.CodeMarker?JsonSerializer.SerializeToUtf8Bytes(new StateIdentity(1,state.InstallationId)):
                JsonSerializer.SerializeToUtf8Bytes(new VersionReceipt(1,state.InstallationId,scope.Release,scope.ManifestSHA256));
            return new(Convert.ToHexString(SHA256.HashData(bytes)),bytes.Length,bytes.Length);
        }
        var file=scope.Files.Single(f=>CreationTag.AssetRole(f.Asset.Id)==role);return new(file.SHA256,file.Length,file.Length);
    }
    private static bool IsExpected(long length,string hash,ExpectedFile expected)=>
        length>0 && length<=expected.Maximum && (expected.Length is null || length==expected.Length) && hash==expected.SHA256;

    private static void AssertUnpublished(ProtectedState state,string release,bool rootMarker)
    {
        var current=state.ReadOptional("current.json");
        if(current is not null)
        {
            var pointer=CurrentPointer.Parse(current,state.InstallationId);
            if(rootMarker || pointer.Release==release)throw new InvalidDataException("Selected files cannot be downgraded to pending writes");
        }
        foreach(var prefix in new[]{"release-","restage-","selection-"})
        {
            var leaves=state.ListLeaves(prefix);if(leaves.Length>8192)throw new InvalidDataException("Publication inventory capacity exceeded; no cleanup allowed");
            foreach(var leaf in leaves)
            {
                using var doc=JsonDocument.Parse(state.Read(leaf,8192).Bytes,new JsonDocumentOptions{MaxDepth=4});var r=doc.RootElement;
                var publishedRelease=Identifiers.Hex32(StrictJson.Text(r,"Release"));
                if(prefix=="selection-")
                {
                    StrictJson.Fields(r,"SchemaVersion","InstallationId","Release","ManifestSHA256","OperationId","PointerSHA256","Activation");
                    var operation=Identifiers.Hex32(StrictJson.Text(r,"OperationId"));_=Identifiers.Hash(StrictJson.Text(r,"PointerSHA256"));
                    if(leaf!="selection-"+publishedRelease+"-"+operation+".json" || StrictJson.Text(r,"Activation")!="INACTIVE")throw new InvalidDataException("Selection record differs");
                }
                else
                {
                    StrictJson.Fields(r,"SchemaVersion","InstallationId","Release","ManifestSHA256","StagedByOperation","Status");
                    var operation=Identifiers.Hex32(StrictJson.Text(r,"StagedByOperation"));
                    var expectedLeaf=prefix=="release-"?"release-"+publishedRelease+".json":"restage-"+operation+".json";
                    if(leaf!=expectedLeaf || StrictJson.Text(r,"Status")!="VERIFIED_PAYLOAD")throw new InvalidDataException("Publication record differs");
                }
                if(r.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(r,"InstallationId")!=state.InstallationId)throw new InvalidDataException("Foreign publication record");
                _=Identifiers.Hash(StrictJson.Text(r,"ManifestSHA256"));
                if(rootMarker || publishedRelease==release)throw new InvalidDataException("Published objects cannot be downgraded to pending writes");
            }
        }
    }
}
