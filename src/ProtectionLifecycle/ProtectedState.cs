using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed record StateIdentity(int SchemaVersion, string InstallationId);
internal sealed record BoundBytes(byte[] Bytes, string SHA256);

// Administrator state is never read from the project, a caller-supplied path,
// or a probe's unprivileged journal. No automatic adoption/ACL repair exists.
internal sealed class ProtectedState : IDisposable
{
    private readonly PathLease directory;
    private readonly SafeFileHandle mutex;
    private bool disposed;
    internal string InstallationId { get; }
    internal bool CreatedInThisProcess { get; }
    private ProtectedState(PathLease directory, SafeFileHandle mutex, string installationId,bool createdInThisProcess=false)
    { this.directory = directory; this.mutex = mutex; InstallationId = Identifiers.Hex32(installationId);CreatedInThisProcess=createdInThisProcess; }

    internal static ProtectedState OpenExisting(FixedLayout layout)
    {
        RequireAdministrator();
        using var trustedParent=WindowsPathSeal.LockDirectory(Path.GetDirectoryName(layout.StateRoot)!,PathPolicy.CreationParent);
        var directory = WindowsPathSeal.LockDirectory(layout.StateRoot, PathPolicy.Protected);
        SafeFileHandle? mutex = null;
        try
        {
            var rootTag=directory.ReadCreationTag();
            if(rootTag.Role!=CreationRole.StateRoot)throw new InvalidDataException("State-root creation role differs");
            // An existing nonempty installation must already own its lock file.
            // Missing/corrupt identity or lock means explicit recovery is needed.
            mutex = WindowsPathSeal.Open(WindowsPathSeal.Child(directory.Path, "operation-lock.json"), false, true, true);
            WindowsPathSeal.AssertAcl(mutex, true);
            var identity = ReadBound(directory, "installation.json", 4096, true);
            using var doc = JsonDocument.Parse(identity.Bytes, new JsonDocumentOptions { MaxDepth = 4 });
            StrictJson.Fields(doc.RootElement, "SchemaVersion", "InstallationId");
            if (doc.RootElement.GetProperty("SchemaVersion").GetInt32() != 1) throw new InvalidDataException("Unknown installation identity schema");
            var installationId=Identifiers.Hex32(StrictJson.Text(doc.RootElement,"InstallationId"));
            if(installationId!=rootTag.Id)throw new InvalidDataException("State identity differs from root creation tag");
            using(var handle=WindowsPathSeal.Open(WindowsPathSeal.Child(directory.Path,"installation.json"),false,true))
                if(WindowsPathSeal.ReadCreationTag(handle).Sid!=CreationTag.For(CreationRole.StateIdentity,installationId).Sid)throw new InvalidDataException("State marker creation tag differs");
            return new(directory,mutex,installationId);
        }
        catch { mutex?.Dispose(); directory.Dispose(); throw; }
    }

    // Called only AFTER protected BootstrapApproval by a reviewed bootstrap. This
    // library has no executable entry and no elevation or startup mechanism.
    internal static ProtectedState CreateFresh(FixedLayout layout, ReviewedPackage package)
    {
        RequireAdministrator();
        // ReviewedPackage has a private constructor and is created only after
        // checking the manifest against the bootstrap's embedded approval pin.
        _ = Identifiers.Hash(package.ManifestHash);
        using var parent=WindowsPathSeal.LockDirectory(Path.GetDirectoryName(layout.StateRoot)!,PathPolicy.CreationParent);
        var installationId=Guid.NewGuid().ToString("N");
        var directory=WindowsPathSeal.CreateProtectedDirectory(parent,"ClaudeCodeProtection-State",false,CreationTag.For(CreationRole.StateRoot,installationId));
        SafeFileHandle? mutex = null;
        try
        {
            mutex = WindowsPathSeal.CreateProtectedFile(directory, "operation-lock.json", false);
            WriteBound(directory,"installation.json",JsonSerializer.SerializeToUtf8Bytes(new StateIdentity(1,installationId)),false,CreationTag.For(CreationRole.StateIdentity,installationId));
            return new(directory, mutex, installationId,true);
        }
        catch { mutex?.Dispose(); directory.Dispose(); throw; } // Preserve incomplete owned state, never erase evidence.
    }

    // Explicit, fixed-location metadata recovery, not a package/install approval.
    // Only a root created with this namespace's initial protected tag is eligible.
    // Existing directories are never tagged or adopted by this operation.
    internal static ProtectedState RecoverInitialization(FixedLayout layout)
    {
        RequireAdministrator();using var trustedParent=WindowsPathSeal.LockDirectory(Path.GetDirectoryName(layout.StateRoot)!,PathPolicy.CreationParent);
        var directory=WindowsPathSeal.LockDirectory(layout.StateRoot,PathPolicy.Protected);
        SafeFileHandle? mutex=null;ProtectedState? state=null;
        try
        {
            var rootTag=directory.ReadCreationTag();if(rootTag.Role!=CreationRole.StateRoot)throw new InvalidDataException("Unowned initialization root");
            var installationId=rootTag.Id;
            try{mutex=WindowsPathSeal.Open(WindowsPathSeal.Child(directory.Path,"operation-lock.json"),false,true,true);WindowsPathSeal.AssertAcl(mutex,true);}
            catch(ExactPathAbsentException){mutex=WindowsPathSeal.CreateProtectedFile(directory,"operation-lock.json",false);}
            state=new(directory,mutex,installationId);
            var tag=CreationTag.For(CreationRole.StateIdentity,installationId);SafeFileHandle marker;var missing=false;
            try
            {
                marker=WindowsPathSeal.Open(WindowsPathSeal.Child(directory.Path,"installation.json"),false,true,true);
                try{WindowsPathSeal.AssertAcl(marker,true);}catch{marker.Dispose();throw;}
            }
            catch(ExactPathAbsentException)
            {
                missing=true;
                state.WriteNew("initialization-intent-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,InstallationId=installationId,StateRootIdentity=directory.ObjectIdentity(),Action="CREATE_MISSING_IDENTITY",AtUtc=DateTime.UtcNow.ToString("o")}));
                marker=WindowsPathSeal.CreateProtectedFile(directory,"installation.json",false,tag);
            }
            using(marker)
            using(var stream=new FileStream(marker,FileAccess.ReadWrite,4096,false))
            {
                if(WindowsPathSeal.ReadCreationTag(marker).Sid!=tag.Sid || stream.Length>4096)throw new InvalidDataException("Unowned or oversized initialization marker");
                var original=new byte[checked((int)stream.Length)];stream.ReadExactly(original);var malformed=false;
                if(original.Length==0)malformed=true;
                else
                {
                    try
                    {
                        using var doc=JsonDocument.Parse(original);StrictJson.Fields(doc.RootElement,"SchemaVersion","InstallationId");
                        if(doc.RootElement.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(doc.RootElement,"InstallationId")!=installationId)
                            throw new InvalidDataException("Conflicting complete state identity is retained");
                    }
                    catch(JsonException){malformed=true;}
                }
                if(malformed)
                {
                    var expected=JsonSerializer.SerializeToUtf8Bytes(new StateIdentity(1,installationId));
                    state.WriteNew("initialization-before-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                        SchemaVersion=1,InstallationId=installationId,MarkerWasMissing=missing,Tag=tag.Sid,ObjectIdentity=WindowsPathSeal.Identity(marker),
                        OriginalSHA256=Convert.ToHexString(SHA256.HashData(original)),OriginalBytesBase64=Convert.ToBase64String(original),AtUtc=DateTime.UtcNow.ToString("o")
                    }));
                    stream.Position=0;stream.SetLength(0);stream.Write(expected);stream.Flush(true);stream.Position=0;
                    if(Convert.ToHexString(SHA256.HashData(stream))!=Convert.ToHexString(SHA256.HashData(expected)))throw new IOException("Initialization marker repair differs");
                    state.WriteNew("initialization-after-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                        SchemaVersion=1,InstallationId=installationId,Tag=tag.Sid,ObjectIdentity=WindowsPathSeal.Identity(marker),Status="IDENTITY_METADATA_REPAIRED_ONLY",AtUtc=DateTime.UtcNow.ToString("o")
                    }));
                }
            }
            return state;
        }
        catch{if(state is not null)state.Dispose();else{mutex?.Dispose();directory.Dispose();}throw;}
    }

    internal string WriteNew(string leaf, byte[] bytes)
    {
        AssertHeld();leaf=Identifiers.StateLeaf(leaf);
        if(leaf.StartsWith("pending-record-",StringComparison.Ordinal))throw new InvalidDataException("Reserved state staging prefix");
        // A process failure while writing may leave a private pending record,
        // but does not expose a half-written final ledger name. Retain pending
        // output on failure. This is not a power-loss durability qualification.
        var temporary="pending-record-"+Guid.NewGuid().ToString("N")+".json";
        var hash=WriteBound(directory,temporary,bytes,false);string identity;
        using(var handle=WindowsPathSeal.Open(WindowsPathSeal.Child(directory.Path,temporary),false,true))identity=WindowsPathSeal.Identity(handle);
        AssertHeld();File.Move(WindowsPathSeal.Child(directory.Path,temporary),WindowsPathSeal.Child(directory.Path,leaf),false);
        using(var handle=WindowsPathSeal.Open(WindowsPathSeal.Child(directory.Path,leaf),false,true))
            if(WindowsPathSeal.Identity(handle)!=identity)throw new IOException("Published state object identity differs");
        if(Read(leaf).SHA256!=hash)throw new IOException("Published state bytes differ");
        return hash;
    }
    internal FileStream? OpenCompletionForRepair(CreationTag tag)
    {
        AssertHeld();if((uint)tag.Role is <(uint)CreationRole.CodeMarker or >(uint)CreationRole.BrokerLifecycle)throw new InvalidDataException("Completion file role required");
        var path=WindowsPathSeal.Child(directory.Path,CreationIdentity.CompletionLeaf(tag));
        SafeFileHandle handle;
        try{handle=WindowsPathSeal.Open(path,false,true,true);}
        catch(ExactPathAbsentException ex)when(string.Equals(ex.FailedPath,path,StringComparison.OrdinalIgnoreCase)){return null;}
        try{WindowsPathSeal.AssertAcl(handle,true);return new FileStream(handle,FileAccess.ReadWrite,8192,false);}catch{handle.Dispose();throw;}
    }
    internal BoundBytes Read(string leaf, int maximum = 128 * 1024)
    { AssertHeld(); return ReadBound(directory, Identifiers.StateLeaf(leaf), maximum, true); }
    internal BoundBytes? ReadOptional(string leaf)
    {
        try { return Read(leaf); }
        catch(ExactPathAbsentException){return null;}
    }
    internal string[] ListLeaves(string fixedPrefix)
    {
        AssertHeld();
        if(fixedPrefix is not ("operation-" or "plan-" or "release-" or "restage-" or "recovery-" or "selection-" or "stage-intent-" or "job-intent-" or "fence-intent-" or "fence-migration-" or "loopback-intent-" or "profile-created-" or "profile-intent-")) throw new InvalidOperationException("Fixed inventory prefix required");
        // Enumeration locates names only. Each matched file must separately pass
        // the handle, ACL, strict JSON and identity checks before it is trusted.
        return Directory.EnumerateFiles(directory.Path,"*",SearchOption.TopDirectoryOnly)
            .Select(Path.GetFileName).Where(n=>n is not null && n.StartsWith(fixedPrefix,StringComparison.Ordinal))
            .Select(n=>Identifiers.StateLeaf(n!)).OrderBy(n=>n,StringComparer.Ordinal).ToArray();
    }
    internal void AssertFreshEmpty()
    {
        AssertHeld();
        if(!CreatedInThisProcess)throw new InvalidOperationException("Fresh state required");
        var names=Directory.EnumerateFileSystemEntries(directory.Path).Select(Path.GetFileName).OrderBy(n=>n,StringComparer.Ordinal).ToArray();
        if(!names.SequenceEqual(new[]{"installation.json","operation-lock.json"}))throw new InvalidOperationException("New state is no longer empty");
    }
    internal void RemoveCurrent(string? expectedHash)
    {
        AssertHeld();var raw=ReadOptional("current.json");
        if(raw is null)return; // Idempotent resume after an observed removal.
        if(expectedHash is null || raw.SHA256!=Identifiers.Hash(expectedHash))throw new InvalidOperationException("Foreign current pointer refused during uninstall");
        _=CurrentPointer.Parse(raw,InstallationId);
        var path=WindowsPathSeal.Child(directory.Path,"current.json");
        using(var handle=WindowsPathSeal.OpenForDelete(path,false))
        using(var stream=new FileStream(handle,FileAccess.Read,65536,false))
        {
            if(Convert.ToHexString(SHA256.HashData(stream))!=raw.SHA256)throw new InvalidOperationException("Pointer changed before exact removal");
            WindowsPathSeal.MarkDelete(handle);
        }
        if(ReadOptional("current.json") is not null)throw new IOException("Current pointer still present");
    }

    // The operation lock serializes cooperative administrative operations. It
    // does not defend against a malicious administrator changing the directory.
    // All temporary files are protected and retained on failure for recovery.
    internal string ReplacePointer(string leaf, string? expectedOldHash, byte[] bytes)
    {
        AssertHeld(); leaf = Identifiers.StateLeaf(leaf);
        var old = ReadOptional(leaf);
        if ((old is null) != (expectedOldHash is null) || (old is not null && old.SHA256 != Identifiers.Hash(expectedOldHash!)))
            throw new InvalidOperationException("Protected pointer changed; recovery required");
        var temporary = "pending-" + Guid.NewGuid().ToString("N") + ".json";
        var hash = WriteNew(temporary, bytes);
        AssertHeld();
        var source = WindowsPathSeal.Child(directory.Path, temporary);
        var destination = WindowsPathSeal.Child(directory.Path, leaf);
        if (old is null) File.Move(source, destination, false);
        else File.Replace(source, destination, null);
        var result = Read(leaf);
        if (result.SHA256 != hash) throw new IOException("Protected pointer verification failed");
        return hash;
    }

    internal static BoundBytes ReadBound(PathLease directory, string relative, int maximum, bool requireProtected)
    {
        directory.AssertHeld();
        if (Path.GetFileName(relative) != relative) throw new InvalidDataException("ReadBound requires an exact leaf and a held parent");
        if (requireProtected && directory.Policy != PathPolicy.Protected) throw new InvalidOperationException("Protected parent required");
        var path = WindowsPathSeal.Child(directory.Path, relative);
        using var handle = WindowsPathSeal.Open(path, false, true);
        if (requireProtected) WindowsPathSeal.AssertAcl(handle, true);
        using var stream = new FileStream(handle, FileAccess.Read, 65536, false);
        if (stream.Length < 1 || stream.Length > maximum) throw new InvalidDataException("Bounded nonempty state required");
        var bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new IOException("File changed while read-locked");
        return new(bytes, Convert.ToHexString(SHA256.HashData(bytes)));
    }

    internal static string WriteBound(PathLease directory,string leaf,byte[] bytes,bool publicRead,CreationTag? creation=null)
    {
        directory.AssertHeld();
        if (bytes.Length is < 1 or > 128 * 1024) throw new InvalidDataException("State write size refused");
        using (var handle=WindowsPathSeal.CreateProtectedFile(directory,Identifiers.StateLeaf(leaf),publicRead,creation))
        using (var stream = new FileStream(handle, FileAccess.Write, 65536, false))
        { stream.Write(bytes); stream.Flush(true); }
        var result = ReadBound(directory, leaf, 128 * 1024, true);
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), Convert.FromHexString(result.SHA256)))
            throw new IOException("New protected state differs");
        return result.SHA256;
    }

    internal void AssertHeld()
    {
        if (disposed || mutex.IsClosed || mutex.IsInvalid) throw new ObjectDisposedException(nameof(ProtectedState));
        directory.AssertHeld(); WindowsPathSeal.AssertAcl(mutex, true);
    }
    internal static void RequireAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("An existing elevated token is required; no automatic elevation");
    }
    public void Dispose() { if (disposed) return; disposed = true; mutex.Dispose(); directory.Dispose(); }
}
