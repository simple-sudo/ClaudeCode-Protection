using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record LifecycleEdge(string Operation, string From, string Event, string To, string Proof);
internal sealed record LifecycleRecord(int SchemaVersion, string InstallationId, string OperationId,
    string Operation, string? Target, int Sequence, string Phase, string Event, string ProofKind, string ProofSHA256,
    string? PreviousRecordSHA256, string AtUtc);

// Actual OS observations must be supplied by the future installed broker's
// owners while it holds the session admission barrier. No CLI/JSON caller may
// manufacture one of these receipts. There is no production adapter yet.
internal interface ILifecycleRuntimeLease : IDisposable
{
    void AssertLaunchAdmissionClosed();
    void StopAndVerifyOwnedProcesses();
    void AssertNoOwnedProcesses();
    void RemoveAndVerifyExactOwnedResources(string installationId);
    void AssertNoOwnedResources(string installationId);
}

internal static class LifecycleProtocol
{
    internal static readonly IReadOnlyList<LifecycleEdge> Edges = Load();
    private static IReadOnlyList<LifecycleEdge> Load()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("ProtectionLifecycle.LifecycleProtocol.json")
            ?? throw new InvalidDataException("Embedded lifecycle protocol missing");
        using var doc = JsonDocument.Parse(stream, new JsonDocumentOptions { MaxDepth = 8 });
        var root = doc.RootElement;
        StrictJson.Fields(root, "SchemaVersion", "DefaultActivation", "PreserveUserConfig", "PreserveEvidence", "AllowedOperations", "Transitions");
        if (root.GetProperty("SchemaVersion").GetInt32() != 1 || StrictJson.Text(root,"DefaultActivation") != "INACTIVE" ||
            !root.GetProperty("PreserveUserConfig").GetBoolean() || !root.GetProperty("PreserveEvidence").GetBoolean())
            throw new InvalidDataException("Unsafe lifecycle policy");
        var operations = root.GetProperty("AllowedOperations").EnumerateArray().Select(n => n.GetString()).ToArray();
        if (!operations.SequenceEqual(new[] { "install", "update", "rollback", "uninstall" })) throw new InvalidDataException("Lifecycle operation scope differs");
        var edges = new List<LifecycleEdge>(); var seen = new HashSet<(string,string,string)>();
        foreach (var entry in root.GetProperty("Transitions").EnumerateArray())
        {
            StrictJson.Fields(entry, "Operation", "From", "Event", "To", "Proof");
            var edge = new LifecycleEdge(StrictJson.Text(entry,"Operation"), StrictJson.Text(entry,"From"), StrictJson.Text(entry,"Event"), StrictJson.Text(entry,"To"), StrictJson.Text(entry,"Proof"));
            if (!operations.Contains(edge.Operation) || !seen.Add((edge.Operation, edge.From, edge.Event))) throw new InvalidDataException("Unknown/ambiguous lifecycle edge");
            edges.Add(edge);
        }
        return edges.AsReadOnly();
    }
}

// A durable transition ledger, not an installer entry point. Completion requires
// a matching authoritative proof receipt already saved in administrator state.
// Exact uninstall has a bounded resume owner; version reconciliation remains
// non-destructive. Neither accepts an old PASS or supplied Boolean as live proof.
internal sealed class LifecycleTransaction
{
    private readonly ProtectedState state;
    private readonly string operation;
    private readonly string? target;
    private readonly ILifecycleRuntimeLease runtime;
    internal string Id { get; } = Guid.NewGuid().ToString("N");
    private int sequence;
    private string phase = "planned";
    private string? previous;
    internal string Operation => operation;
    internal string? Target => target;
    internal string Phase => phase;
    internal BoundBytes? PriorPointer { get; }
    internal void AssertAuthority(ProtectedState owner,ILifecycleRuntimeLease barrier)
    {
        if(!ReferenceEquals(state,owner) || !ReferenceEquals(runtime,barrier))throw new InvalidOperationException("Foreign lifecycle authority");
        state.AssertHeld();runtime.AssertLaunchAdmissionClosed();runtime.AssertNoOwnedProcesses();
    }
    internal void AssertSwitchAllowed(ProtectedState owner,ILifecycleRuntimeLease barrier)
    {AssertAuthority(owner,barrier);if(phase!="verified" || operation=="uninstall")throw new InvalidOperationException("Switch requires verified phase");}
    internal LifecycleTransaction(ProtectedState state, string operation, string? target, ILifecycleRuntimeLease runtime)
    {
        if (!LifecycleProtocol.Edges.Any(e => e.Operation == operation)) throw new InvalidDataException("Operation is outside lifecycle protocol");
        if(operation=="uninstall" ? target is not null : target is null) throw new InvalidDataException("Operation target mismatch");
        if(target is not null) _=Identifiers.Hex32(target);
        this.state=state; this.operation=operation; this.target=target; this.runtime=runtime;
        runtime.AssertLaunchAdmissionClosed(); state.AssertHeld();
        LifecycleRecovery.AssertNoPending(state);
        PriorPointer=state.ReadOptional("current.json");
        if(PriorPointer is not null) _=CurrentPointer.Parse(PriorPointer,state.InstallationId);
        if((operation=="install" && PriorPointer is not null) || ((operation is "update" or "rollback") && PriorPointer is null))
            throw new InvalidOperationException("Installation state does not permit this operation");
        var plan=JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,InstallationId=state.InstallationId,OperationId=Id,Operation=operation,Target=target,Activation="INACTIVE",
            PriorPointerSHA256=PriorPointer?.SHA256,PriorPointerBase64=PriorPointer is null?null:Convert.ToBase64String(PriorPointer.Bytes)});
        var planHash=state.WriteNew("plan-"+Id+".json",plan);
        previous=Write("begin", "operation-plan", planHash);
        sequence=1;
    }
    private LifecycleTransaction(ProtectedState state,JournalSnapshot snapshot,ILifecycleRuntimeLease runtime)
    {
        if(snapshot.Operation!="uninstall" || snapshot.Target is not null)throw new InvalidOperationException("Only exact uninstall can resume a ledger");
        this.state=state;operation=snapshot.Operation;target=null;this.runtime=runtime;Id=snapshot.OperationId;
        PriorPointer=snapshot.PriorPointer;phase=snapshot.Phase;sequence=snapshot.RecordCount;previous=snapshot.RecordCount==0?null:snapshot.LastRecordSHA256;
        AssertAuthority(state,runtime);
        var current=state.ReadOptional("current.json");
        if(current is not null && current.SHA256!=PriorPointer?.SHA256)throw new InvalidDataException("Current pointer is outside interrupted uninstall");
        if(sequence==0){previous=Write("begin","operation-plan",snapshot.PlanSHA256);sequence=1;}
    }
    internal static LifecycleTransaction ResumeUninstall(ProtectedState state,string operationId,ILifecycleRuntimeLease runtime)
    {
        var snapshot=LifecycleJournal.Read(state,Identifiers.Hex32(operationId));
        LifecycleRecovery.AssertNoPending(state,snapshot.OperationId);
        return new(state,snapshot,runtime);
    }
    internal void ObserveAndAdvance(string @event,string verifiedSubjectHash)
    {
        // Only called by installed lifecycle owners after actual observations;
        // no public request/CLI accepts events or proof data.
        var edge=LifecycleProtocol.Edges.SingleOrDefault(e=>e.Operation==operation && e.From==phase && e.Event==@event)
            ??throw new InvalidOperationException("Unexpected lifecycle observation");
        state.AssertHeld();runtime.AssertLaunchAdmissionClosed();
        if(operation!="uninstall")
        {
            var owned=OwnedReleaseReceipt.Read(state,target!);
            var expected=(@event is "stage" or "verify")?owned.ManifestSHA256:VersionSelector.ReadSelectionHash(state,target!,Id);
            if(expected!=Identifiers.Hash(verifiedSubjectHash))throw new InvalidDataException("Observation subject differs from transaction target");
        }
        else if(RemovalInventory.Read(state,Id).SHA256!=Identifiers.Hash(verifiedSubjectHash))throw new InvalidDataException("Uninstall observation belongs to another inventory");
        var leaf="proof-"+Id+"-"+sequence.ToString("D4",System.Globalization.CultureInfo.InvariantCulture)+".json";
        var proofBytes=JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,InstallationId=state.InstallationId,OperationId=Id,Target=target,
            Kind=edge.Proof,Status="VERIFIED",SubjectSHA256=Identifiers.Hash(verifiedSubjectHash)});
        var existing=state.ReadOptional(leaf);string hash;
        if(existing is null)hash=state.WriteNew(leaf,proofBytes);
        else
        {
            hash=Convert.ToHexString(SHA256.HashData(proofBytes));if(existing.SHA256!=hash)throw new InvalidDataException("Orphan proof differs from fresh observation");
            state.WriteNew("reobserve-"+Id+"-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,InstallationId=state.InstallationId,OperationId=Id,Phase=phase,Event=@event,PriorProofSHA256=hash,SubjectSHA256=verifiedSubjectHash,AtUtc=DateTime.UtcNow.ToString("o")
            }));
        }
        Advance(@event,leaf,hash);
    }
    internal void RecordStagingIntent(ProtectedState owner,ReviewedPackage package,ILifecycleRuntimeLease barrier)
    {
        if(!ReferenceEquals(state,owner) || !ReferenceEquals(runtime,barrier) || phase!="planned" || operation is not ("install" or "update") || package.Release!=target)
            throw new InvalidOperationException("Staging is not owned by this planned transaction");
        runtime.AssertLaunchAdmissionClosed();runtime.AssertNoOwnedProcesses();state.AssertHeld();
        state.WriteNew("stage-intent-"+Id+".json",JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,InstallationId=state.InstallationId,OperationId=Id,Release=package.Release,
            ManifestSHA256=package.ManifestHash,Assets=package.Files.Select(f=>new {f.Asset.Id,f.Length,f.SHA256})
        }));
    }
    internal void Advance(string @event, string proofLeaf, string expectedProofHash)
    {
        runtime.AssertLaunchAdmissionClosed();
        var edge = LifecycleProtocol.Edges.SingleOrDefault(e => e.Operation == operation && e.From == phase && e.Event == @event)
            ?? throw new InvalidOperationException("Lifecycle phase cannot be skipped");
        var proof = state.Read(Identifiers.StateLeaf(proofLeaf));
        if (proof.SHA256 != Identifiers.Hash(expectedProofHash)) throw new InvalidDataException("Proof receipt changed");
        using var doc = JsonDocument.Parse(proof.Bytes, new JsonDocumentOptions { MaxDepth = 6 });
        StrictJson.Fields(doc.RootElement, "SchemaVersion", "InstallationId", "OperationId", "Target", "Kind", "Status", "SubjectSHA256");
        if (doc.RootElement.GetProperty("SchemaVersion").GetInt32() != 1 ||
            StrictJson.Text(doc.RootElement,"InstallationId") != state.InstallationId ||
            StrictJson.Text(doc.RootElement,"OperationId") != Id ||
            StrictJson.Text(doc.RootElement,"Kind") != edge.Proof || StrictJson.Text(doc.RootElement,"Status") != "VERIFIED")
            throw new InvalidDataException("Foreign/unverified lifecycle proof");
        var proofTarget=doc.RootElement.GetProperty("Target");
        if(target is null ? proofTarget.ValueKind!=JsonValueKind.Null : proofTarget.ValueKind!=JsonValueKind.String || proofTarget.GetString()!=target)
            throw new InvalidDataException("Proof belongs to another lifecycle target");
        _=Identifiers.Hash(StrictJson.Text(doc.RootElement,"SubjectSHA256"));
        if (edge.Event is "switch" or "quiesce" or "remove-pointer" or "remove-payload" or "finish") runtime.AssertNoOwnedProcesses();
        // Commit the phase in memory only after its durable record succeeds.
        var next=Write(@event, edge.Proof, proof.SHA256, edge.To);
        previous=next; phase=edge.To; sequence++;
    }
    private string Write(string @event, string kind, string proof, string? nextPhase=null)
    {
        var bytes=JsonSerializer.SerializeToUtf8Bytes(new LifecycleRecord(1,state.InstallationId,Id,operation,target,sequence,nextPhase??phase,@event,kind,proof,previous,DateTime.UtcNow.ToString("o")));
        return state.WriteNew("operation-"+Id+"-"+sequence.ToString("D4", System.Globalization.CultureInfo.InvariantCulture)+".json", bytes);
    }
}

internal sealed record VersionReceipt(int SchemaVersion, string InstallationId, string Release, string ManifestSHA256);

internal static class VersionStager
{
    // Only copies data; never loads or executes a payload from the source tree.
    // Every input is hashed AND copied through the same non-write-share handle.
    // Failure preserves partial protected output and its operation ledger.
    internal static string Stage(FixedLayout layout, ProtectedState state, ReviewedPackage package,
        string sourceDirectory, ILifecycleRuntimeLease runtime,LifecycleTransaction transaction)
    {
        state.AssertHeld(); runtime.AssertLaunchAdmissionClosed(); runtime.AssertNoOwnedProcesses();
        transaction.RecordStagingIntent(state,package,runtime);
        using var source=WindowsPathSeal.LockDirectory(sourceDirectory, PathPolicy.Source);
        var manifest=ProtectedState.ReadBound(source,"package.json",PackagePolicy.MaxManifestBytes,false);
        var pinned=PackagePolicy.Authorize(manifest.Bytes);
        if (pinned.ManifestHash!=package.ManifestHash || pinned.Release!=package.Release) throw new InvalidDataException("Source package changed");
        using var code=OpenOrCreateOwnedCodeRoot(layout,state,transaction.Id);
        using var versions=OpenOrCreateChild(code,"versions",state,transaction.Id);
        // Reused release identifiers are refused, including partial earlier stages.
        using var release=CreationIdentity.CreateDirectory(versions,package.Release,true,state,transaction.Id,"release",package.Release);
        CreationIdentity.WriteMetadata(release,"version.json",state,transaction.Id,package.Release,CreationRole.VersionMarker,JsonSerializer.SerializeToUtf8Bytes(new VersionReceipt(1,state.InstallationId,package.Release,package.ManifestHash)));
        CreationIdentity.WriteMetadata(release,"package.json",state,transaction.Id,package.Release,CreationRole.PackageManifest,package.ManifestBytes.ToArray());
        using var bin=CreationIdentity.CreateDirectory(release,"bin",true,state,transaction.Id,"bin",package.Release);
        using var daily=CreationIdentity.CreateDirectory(bin,"current",true,state,transaction.Id,"current",package.Release);
        using var center=CreationIdentity.CreateDirectory(bin,"center",true,state,transaction.Id,"center",package.Release);
        using var admin=CreationIdentity.CreateDirectory(bin,"admin",true,state,transaction.Id,"admin",package.Release);
        foreach(var file in package.Files)
        {
            runtime.AssertLaunchAdmissionClosed(); runtime.AssertNoOwnedProcesses();
            var parentName=Path.GetDirectoryName(file.Asset.Path.Replace('/','\\'))!;
            using var sourceParent=WindowsPathSeal.LockDirectory(WindowsPathSeal.Child(source.Path,parentName),PathPolicy.Source);
            var destination=file.Asset.Path.StartsWith("bin/current/",StringComparison.Ordinal)?daily:
                file.Asset.Path.StartsWith("bin/center/",StringComparison.Ordinal)?center:admin;
            CopyVerified(sourceParent,destination,Path.GetFileName(file.Asset.Path),file,state,transaction.Id,package.Release);
        }
        var owned=new OwnedReleaseReceipt(1,state.InstallationId,package.Release,package.ManifestHash,transaction.Id,"VERIFIED_PAYLOAD");
        var releaseLeaf="release-"+package.Release+".json";
        if(state.ReadOptional(releaseLeaf) is null)state.WriteNew(releaseLeaf,JsonSerializer.SerializeToUtf8Bytes(owned));
        else
        {
            if(OwnedReleaseReceipt.Read(state,package.Release).ManifestSHA256!=package.ManifestHash)throw new InvalidDataException("Release identifier reused with different payload");
            state.WriteNew("restage-"+transaction.Id+".json",JsonSerializer.SerializeToUtf8Bytes(owned)); // Preserve original authorization history.
        }
        return WindowsPathSeal.Child(release.Path,"version.json"); // Stage != activation or lifecycle completion.
    }
    private static PathLease OpenOrCreateOwnedCodeRoot(FixedLayout layout,ProtectedState state,string operation)
    {
        PathLease code;
        try {code=WindowsPathSeal.LockDirectory(layout.CodeRoot,PathPolicy.Protected);}
        catch(ExactPathAbsentException ex) when(IsWithinCodeRoot(layout,ex.FailedPath))
        {
            using var parent=WindowsPathSeal.LockDirectory(Path.GetDirectoryName(layout.CodeRoot)!,PathPolicy.CreationParent);
            code=WindowsPathSeal.CreateProtectedDirectory(parent,"ClaudeCodeProtection",true,CreationTag.For(CreationRole.CodeRoot,state.InstallationId));
            try {CreationIdentity.WriteMetadata(code,"installation.json",state,operation,null,CreationRole.CodeMarker,JsonSerializer.SerializeToUtf8Bytes(new StateIdentity(1,state.InstallationId)));return code;}
            catch {code.Dispose();throw;}
        }
        try
        {
            CreationIdentity.AssertRoot(code,state,CreationRole.CodeRoot);
            using(var marker=WindowsPathSeal.Open(WindowsPathSeal.Child(code.Path,"installation.json"),false,true))
                CreationIdentity.AssertFileScope(state,marker,CreationRole.CodeMarker,null);
            var raw=ProtectedState.ReadBound(code,"installation.json",4096,true);
            using var doc=JsonDocument.Parse(raw.Bytes);StrictJson.Fields(doc.RootElement,"SchemaVersion","InstallationId");
            if(doc.RootElement.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(doc.RootElement,"InstallationId")!=state.InstallationId)
                throw new InvalidDataException("Code root does not belong to this installation");
            return code;
        }
        catch {code.Dispose();throw;}
    }
    private static PathLease OpenOrCreateChild(PathLease parent,string leaf,ProtectedState state,string operation)
    {
        parent.AssertHeld();
        try
        {
            var child=WindowsPathSeal.LockDirectory(WindowsPathSeal.Child(parent.Path,leaf),PathPolicy.Protected);
            try{CreationIdentity.AssertDirectory(child,state,leaf,null);return child;}catch{child.Dispose();throw;}
        }
        catch(ExactPathAbsentException ex) when(IsWithinCodeRoot(FixedLayout.FromWindows(),ex.FailedPath))
        {return CreationIdentity.CreateDirectory(parent,leaf,true,state,operation,leaf,null);}
    }
    private static bool IsWithinCodeRoot(FixedLayout layout,string path)=>string.Equals(path,layout.CodeRoot,StringComparison.OrdinalIgnoreCase) || path.StartsWith(layout.CodeRoot+"\\",StringComparison.OrdinalIgnoreCase);
    private static void CopyVerified(PathLease source,PathLease destination,string leaf,PayloadFile expected,ProtectedState state,string operation,string release)
    {
        source.AssertHeld();destination.AssertHeld();
        using var inputHandle=WindowsPathSeal.Open(WindowsPathSeal.Child(source.Path,leaf),false,true);
        using var input=new FileStream(inputHandle,FileAccess.Read,65536,false);
        if(input.Length!=expected.Length || input.Length>PackagePolicy.MaxAssetBytes) throw new InvalidDataException("Source payload length changed");
        var before=Convert.ToHexString(SHA256.HashData(input));
        if(before!=expected.SHA256) throw new InvalidDataException("Source payload digest changed");
        input.Position=0;
        using var outputHandle=CreationIdentity.CreateAsset(destination,leaf,state,operation,release,expected);
        using var output=new FileStream(outputHandle,FileAccess.ReadWrite,65536,false);
        input.CopyTo(output);output.Flush(true);output.Position=0;
        if(output.Length!=expected.Length || Convert.ToHexString(SHA256.HashData(output))!=expected.SHA256)
            throw new IOException("Staged payload verification failed");
        WindowsPathSeal.VerifyObject(outputHandle,WindowsPathSeal.Child(destination.Path,leaf),false);
        WindowsPathSeal.AssertAcl(outputHandle,true);
        CreationIdentity.RecordComplete(state,output,CreationTag.For(CreationTag.AssetRole(expected.Asset.Id),operation));
    }
}
