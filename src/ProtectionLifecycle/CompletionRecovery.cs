using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace ProtectionLifecycle;

// Original completion and a new-time reobservation are distinct evidence.
// This reader never derives approval, activation, runtime health or old success.
internal static class CompletionReceipts
{
    internal static bool IsMalformed(byte[] bytes)
    {
        if(bytes.Length>8192)throw new InvalidDataException("Receipt syntax input too large");
        if(bytes.Length==0)return true;
        // The input is separately capped at8KiB. Do not confuse a valid deeply
        // nested foreign JSON value with a truncated JSON document.
        try{using var doc=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=8192});return false;}
        catch(JsonException){return true;}
    }
    internal static string BeforeLeaf(CreationTag tag,string recovery)=>"completion-before-"+tag.Id+"-"+Identifiers.Hex32(recovery)+".json";
    internal static void AssertMatches(ProtectedState state,CreationTag tag,BoundBytes raw,CompletionObservation observed)
    {
        if(raw.Bytes.Length is <1 or >8192 || Convert.ToHexString(SHA256.HashData(raw.Bytes))!=raw.SHA256)throw new InvalidDataException("Completion snapshot differs");
        using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=4});var r=doc.RootElement;
        var schema=r.GetProperty("SchemaVersion").GetInt32();
        if(schema==1)
        {
            StrictJson.Fields(r,"SchemaVersion","InstallationId","Tag","ObjectIdentity","Length","SHA256","Status");
            if(StrictJson.Text(r,"Status")!="BYTES_VERIFIED")throw new InvalidDataException("Original completion status differs");
        }
        else if(schema==2)
        {
            StrictJson.Fields(r,"SchemaVersion","InstallationId","Tag","ObjectIdentity","Length","SHA256","Status","RecoveryId","BeforeSHA256","ObservedAtUtc");
            if(StrictJson.Text(r,"Status")!="FRESH_BYTES_REOBSERVED")throw new InvalidDataException("Fresh completion status differs");
            var recovery=Identifiers.Hex32(StrictJson.Text(r,"RecoveryId"));var before=state.Read(BeforeLeaf(tag,recovery),32768);
            if(before.SHA256!=Identifiers.Hash(StrictJson.Text(r,"BeforeSHA256")))throw new InvalidDataException("Original damaged receipt evidence changed");
            using var bd=JsonDocument.Parse(before.Bytes,new JsonDocumentOptions{MaxDepth=4});var b=bd.RootElement;
            StrictJson.Fields(b,"SchemaVersion","InstallationId","OperationId","RecoveryId","Tag","ReceiptPresent","ReceiptIdentity","OriginalLength","OriginalSHA256","OriginalBytesBase64","ObservedObjectIdentity","ObservedLength","ObservedSHA256","AtUtc");
            var encoded=StrictJson.Text(b,"OriginalBytesBase64");if(encoded.Length>11000)throw new InvalidDataException("Original receipt evidence too large");
            var original=Convert.FromBase64String(encoded);var present=b.GetProperty("ReceiptPresent").GetBoolean();
            var identity=LifecycleJournal.NullableText(b,"ReceiptIdentity");
            if(present){if(identity is null || !IsMalformed(original))throw new InvalidDataException("A valid conflicting receipt cannot be repaired");_=Identifiers.ObjectIdentity(identity);}
            else if(identity is not null || original.Length!=0)throw new InvalidDataException("Missing receipt evidence differs");
            if(b.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(b,"InstallationId")!=state.InstallationId ||
                StrictJson.Text(b,"OperationId")!=tag.Id || StrictJson.Text(b,"RecoveryId")!=recovery || StrictJson.Text(b,"Tag")!=tag.Sid ||
                original.Length>8192 || b.GetProperty("OriginalLength").GetInt64()!=original.Length ||
                Identifiers.Hash(StrictJson.Text(b,"OriginalSHA256"))!=Convert.ToHexString(SHA256.HashData(original)) ||
                Identifiers.ObjectIdentity(StrictJson.Text(b,"ObservedObjectIdentity"))!=observed.ObjectIdentity || b.GetProperty("ObservedLength").GetInt64()!=observed.Length ||
                Identifiers.Hash(StrictJson.Text(b,"ObservedSHA256"))!=observed.SHA256 || StrictJson.Text(b,"AtUtc")!=StrictJson.Text(r,"ObservedAtUtc"))
                throw new InvalidDataException("Fresh completion provenance differs");
            if(!DateTime.TryParseExact(StrictJson.Text(r,"ObservedAtUtc"),"o",CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind,out var at) || at.Kind!=DateTimeKind.Utc)
                throw new InvalidDataException("Fresh observation time differs");
        }
        else throw new InvalidDataException("Unknown completion receipt schema");
        if(StrictJson.Text(r,"InstallationId")!=state.InstallationId || StrictJson.Text(r,"Tag")!=tag.Sid || observed.Tag!=tag.Sid ||
            Identifiers.ObjectIdentity(StrictJson.Text(r,"ObjectIdentity"))!=observed.ObjectIdentity || r.GetProperty("Length").GetInt64()!=observed.Length ||
            Identifiers.Hash(StrictJson.Text(r,"SHA256"))!=observed.SHA256)throw new InvalidDataException("Completion does not describe the same object and bytes");
    }
}

internal sealed record CompletionRecoveryItem(string Role,string Result);
internal static class CompletionReceiptRecovery
{
    // No arbitrary target path, role, hash or caller assertion is accepted.
    // A real maintenance owner must hold runtime quiescence throughout.
    internal static IReadOnlyList<CompletionRecoveryItem> ReobserveOperation(ProtectedState state,string operation,ILifecycleRuntimeLease runtime)
    {
        state.AssertHeld();runtime.AssertLaunchAdmissionClosed();runtime.AssertNoOwnedProcesses();
        operation=Identifiers.Hex32(operation);var scope=CreationIdentity.ReadScope(state,operation);
        var roles=new[]{CreationRole.CodeMarker,CreationRole.VersionMarker,CreationRole.PackageManifest}
            .Concat(scope.Files.Select(f=>CreationTag.AssetRole(f.Asset.Id))).ToArray();
        var results=new List<CompletionRecoveryItem>();
        var activeRole="not-started";
        try
        {
        foreach(var role in roles)
        {
            activeRole=role.ToString();
            var tag=CreationTag.For(role,operation);var path=CreationIdentity.ExpectedPath(state,tag);
            PathLease parent;
            try{parent=WindowsPathSeal.LockDirectory(Path.GetDirectoryName(path)!,PathPolicy.Protected);}
            catch(ExactPathAbsentException ex)when(OwnedCodePath(ex.FailedPath)){results.Add(new(role.ToString(),"SOURCE_ABSENT_NO_RECEIPT_CREATED"));continue;}
            using(parent)
            {
                Microsoft.Win32.SafeHandles.SafeFileHandle handle;
                try{handle=WindowsPathSeal.Open(path,false,true);}
                catch(ExactPathAbsentException ex)when(string.Equals(ex.FailedPath,path,StringComparison.OrdinalIgnoreCase)){results.Add(new(role.ToString(),"SOURCE_ABSENT_NO_RECEIPT_CREATED"));continue;}
                using(handle)
                using(var source=new FileStream(handle,FileAccess.Read,65536,false))
                {
                    WindowsPathSeal.AssertAcl(handle,true);
                    var actualTag=WindowsPathSeal.ReadCreationTag(handle);
                    if(actualTag.Sid!=tag.Sid)
                    {
                        CreationIdentity.AssertFileScope(state,handle,role,null);
                        results.Add(new(role.ToString(),"OTHER_OPERATION_UNTOUCHED"));continue;
                    }
                    var observed=CreationIdentity.ObserveComplete(state,source,tag);
                    results.Add(new(role.ToString(),RepairOne(state,tag,observed,runtime)));
                }
            }
        }
        state.WriteNew("completion-batch-"+operation+"-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,InstallationId=state.InstallationId,OperationId=operation,Items=results,HistoricalCompletionReconstructed=false,
            ReleasePublishedByThisOperation=false,LifecyclePhaseAdvancedByThisOperation=false,AtUtc=DateTime.UtcNow.ToString("o")
        }));
        return results.AsReadOnly(); // Per-item observations, not a release PASS.
        }
        catch(Exception ex)
        {
            try{state.WriteNew("completion-failure-"+operation+"-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,InstallationId=state.InstallationId,OperationId=operation,Role=activeRole,ItemsObservedBeforeFailure=results,
                FailureType=ex.GetType().Name,FailureCode=ex is System.ComponentModel.Win32Exception native?native.NativeErrorCode:ex.HResult,
                Status="INCOMPLETE_REOBSERVATION",HistoricalCompletionReconstructed=false,AtUtc=DateTime.UtcNow.ToString("o")
            }));}catch(Exception log){throw new AggregateException("Completion reobservation and failure recording both failed",ex,log);}throw;
        }
    }
    private static bool OwnedCodePath(string path)
    {var root=FixedLayout.FromWindows().CodeRoot;return string.Equals(root,path,StringComparison.OrdinalIgnoreCase) || path.StartsWith(root+"\\",StringComparison.OrdinalIgnoreCase);}
    private static string RepairOne(ProtectedState state,CreationTag tag,CompletionObservation observed,ILifecycleRuntimeLease runtime)
    {
        using var original=state.OpenCompletionForRepair(tag);
        byte[] bytes=Array.Empty<byte>();string? identity=null;
        if(original is not null)
        {
            if(original.Length>8192)throw new InvalidDataException("Oversized completion receipt retained");
            bytes=new byte[checked((int)original.Length)];original.ReadExactly(bytes);identity=WindowsPathSeal.Identity(original.SafeFileHandle);
            if(!CompletionReceipts.IsMalformed(bytes))
            {
                CompletionReceipts.AssertMatches(state,tag,new(bytes,Convert.ToHexString(SHA256.HashData(bytes))),observed);
                return "EXISTING_RECEIPT_MATCHES_UNCHANGED";
            }
        }
        var recovery=Guid.NewGuid().ToString("N");var at=DateTime.UtcNow.ToString("o");
        var before=JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,InstallationId=state.InstallationId,OperationId=tag.Id,RecoveryId=recovery,Tag=tag.Sid,
            ReceiptPresent=original is not null,ReceiptIdentity=identity,OriginalLength=bytes.Length,OriginalSHA256=Convert.ToHexString(SHA256.HashData(bytes)),OriginalBytesBase64=Convert.ToBase64String(bytes),
            ObservedObjectIdentity=observed.ObjectIdentity,ObservedLength=observed.Length,ObservedSHA256=observed.SHA256,AtUtc=at});
        var beforeHash=state.WriteNew(CompletionReceipts.BeforeLeaf(tag,recovery),before);
        var repaired=JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=2,InstallationId=state.InstallationId,Tag=tag.Sid,observed.ObjectIdentity,observed.Length,observed.SHA256,
            Status="FRESH_BYTES_REOBSERVED",RecoveryId=recovery,BeforeSHA256=beforeHash,ObservedAtUtc=at});
        state.AssertHeld();runtime.AssertLaunchAdmissionClosed();runtime.AssertNoOwnedProcesses();
        if(original is null)state.WriteNew(CreationIdentity.CompletionLeaf(tag),repaired);
        else
        {
            // Original raw bytes and identity are durable before this exact,
            // locked receipt is changed. Another interruption remains recoverable
            // as a new-time observation; it never invents an old completion.
            WindowsPathSeal.AssertAcl(original.SafeFileHandle,true);
            original.Position=0;original.SetLength(0);original.Write(repaired);original.Flush(true);original.Position=0;
            if(Convert.ToHexString(SHA256.HashData(original))!=Convert.ToHexString(SHA256.HashData(repaired)) || WindowsPathSeal.Identity(original.SafeFileHandle)!=identity)
                throw new IOException("Fresh completion receipt readback differs");
        }
        CompletionReceipts.AssertMatches(state,tag,new(repaired,Convert.ToHexString(SHA256.HashData(repaired))),observed);
        state.WriteNew("completion-after-"+tag.Id+"-"+recovery+".json",JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,InstallationId=state.InstallationId,OperationId=tag.Id,RecoveryId=recovery,Tag=tag.Sid,BeforeSHA256=beforeHash,
            ReceiptSHA256=Convert.ToHexString(SHA256.HashData(repaired)),Status="FRESH_OBSERVATION_ONLY",HistoricalCompletionReconstructed=false,AtUtc=DateTime.UtcNow.ToString("o")
        }));
        return "FRESH_BYTES_REOBSERVED_OLD_EVIDENCE_PRESERVED";
    }
}
