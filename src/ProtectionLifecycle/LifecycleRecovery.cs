using System.Globalization;
using System.Reflection;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record JournalSnapshot(string OperationId,string Operation,string? Target,BoundBytes? PriorPointer,
    string PlanSHA256,string LastRecordSHA256,string Phase,int RecordCount)
{
    internal bool Completed => Phase is "completed-inactive" or "completed-removed";
}

internal static class LifecycleJournal
{
    internal static JournalSnapshot Read(ProtectedState state,string id)
    {
        state.AssertHeld();id=Identifiers.Hex32(id);
        var plan=state.Read("plan-"+id+".json",16384);
        using var document=JsonDocument.Parse(plan.Bytes,new JsonDocumentOptions{MaxDepth=4});var root=document.RootElement;
        StrictJson.Fields(root,"SchemaVersion","InstallationId","OperationId","Operation","Target","Activation","PriorPointerSHA256","PriorPointerBase64");
        if(root.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(root,"InstallationId")!=state.InstallationId ||
            StrictJson.Text(root,"OperationId")!=id || StrictJson.Text(root,"Activation")!="INACTIVE")throw new InvalidDataException("Foreign operation plan");
        var operation=StrictJson.Text(root,"Operation");
        if(!LifecycleProtocol.Edges.Any(e=>e.Operation==operation))throw new InvalidDataException("Unknown planned operation");
        var target=NullableText(root,"Target");
        if(operation=="uninstall" ? target is not null : target is null)throw new InvalidDataException("Plan target mismatch");
        if(target is not null)_=Identifiers.Hex32(target);
        BoundBytes? prior=null;
        var priorHash=NullableText(root,"PriorPointerSHA256");var priorBase64=NullableText(root,"PriorPointerBase64");
        if((priorHash is null)!=(priorBase64 is null))throw new InvalidDataException("Incomplete pointer preimage");
        if(priorBase64 is not null)
        {
            if(priorBase64.Length>6000)throw new InvalidDataException("Pointer preimage too large");
            prior=new(Convert.FromBase64String(priorBase64),Identifiers.Hash(priorHash!));_=CurrentPointer.Parse(prior,state.InstallationId);
        }
        if((operation=="install" && prior is not null) || ((operation is "update" or "rollback") && prior is null))throw new InvalidDataException("Plan prior state mismatch");
        var leaves=state.ListLeaves("operation-").Where(n=>n.StartsWith("operation-"+id+"-",StringComparison.Ordinal)).ToArray();
        if(leaves.Length>32)throw new InvalidDataException("Unbounded operation ledger refused");
        var phase="planned";string? last=null;
        for(var sequence=0;sequence<leaves.Length;sequence++)
        {
            var suffix=sequence.ToString("D4",CultureInfo.InvariantCulture);
            if(leaves[sequence]!="operation-"+id+"-"+suffix+".json")throw new InvalidDataException("Operation ledger gap or unexpected name");
            var raw=state.Read(leaves[sequence],16384);using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=4});var row=doc.RootElement;
            StrictJson.Fields(row,"SchemaVersion","InstallationId","OperationId","Operation","Target","Sequence","Phase","Event","ProofKind","ProofSHA256","PreviousRecordSHA256","AtUtc");
            if(row.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(row,"InstallationId")!=state.InstallationId ||
                StrictJson.Text(row,"OperationId")!=id || StrictJson.Text(row,"Operation")!=operation || NullableText(row,"Target")!=target ||
                row.GetProperty("Sequence").GetInt32()!=sequence || NullableText(row,"PreviousRecordSHA256")!=last)
                throw new InvalidDataException("Operation chain identity differs");
            if(!DateTime.TryParseExact(StrictJson.Text(row,"AtUtc"),"o",CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind,out var at) || at.Kind!=DateTimeKind.Utc)
                throw new InvalidDataException("Operation timestamp format refused");
            var proofHash=Identifiers.Hash(StrictJson.Text(row,"ProofSHA256"));
            if(sequence==0)
            {
                if(StrictJson.Text(row,"Phase")!="planned" || StrictJson.Text(row,"Event")!="begin" || StrictJson.Text(row,"ProofKind")!="operation-plan" || proofHash!=plan.SHA256)
                    throw new InvalidDataException("Operation begin differs from frozen plan");
            }
            else
            {
                var edge=LifecycleProtocol.Edges.SingleOrDefault(e=>e.Operation==operation && e.From==phase && e.Event==StrictJson.Text(row,"Event"))
                    ??throw new InvalidDataException("Operation skips a lifecycle phase");
                if(StrictJson.Text(row,"Phase")!=edge.To || StrictJson.Text(row,"ProofKind")!=edge.Proof)throw new InvalidDataException("Operation edge proof differs");
                var proof=state.Read("proof-"+id+"-"+suffix+".json",8192);
                if(proof.SHA256!=proofHash)throw new InvalidDataException("Operation proof hash differs");
                using var pd=JsonDocument.Parse(proof.Bytes);var p=pd.RootElement;
                StrictJson.Fields(p,"SchemaVersion","InstallationId","OperationId","Target","Kind","Status","SubjectSHA256");
                if(p.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(p,"InstallationId")!=state.InstallationId ||
                    StrictJson.Text(p,"OperationId")!=id || NullableText(p,"Target")!=target || StrictJson.Text(p,"Kind")!=edge.Proof || StrictJson.Text(p,"Status")!="VERIFIED")
                    throw new InvalidDataException("Operation proof ownership differs");
                var subject=Identifiers.Hash(StrictJson.Text(p,"SubjectSHA256"));
                if(operation!="uninstall")
                {
                    var expected=(edge.Event is "stage" or "verify")?OwnedReleaseReceipt.Read(state,target!).ManifestSHA256:
                        VersionSelector.ReadSelectionHash(state,target!,id);
                    if(subject!=expected)throw new InvalidDataException("Journal proof refers to a different artifact");
                }
                else if(subject!=RemovalInventory.Read(state,id).SHA256)throw new InvalidDataException("Uninstall proof inventory differs");
                phase=edge.To;
            }
            last=raw.SHA256;
        }
        // A plan without a first record is an interrupted constructor, not a PASS.
        return new(id,operation,target,prior,plan.SHA256,last??plan.SHA256,phase,leaves.Length);
    }
    internal static string? NullableText(JsonElement root,string name)
    {var field=root.GetProperty(name);return field.ValueKind==JsonValueKind.Null?null:StrictJson.Text(root,name);}
}

internal sealed record RecoveryRule(string Ledger,string Pointer,string Payload,string Action);
internal static class RecoveryPolicy
{
    private static readonly IReadOnlyList<RecoveryRule> Rules=Load();
    private static IReadOnlyList<RecoveryRule> Load()
    {
        using var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("ProtectionLifecycle.RecoveryProtocol.json")??throw new InvalidDataException("Recovery policy missing");
        using var doc=JsonDocument.Parse(stream);var root=doc.RootElement;
        StrictJson.Fields(root,"SchemaVersion","DefaultAction","AllowedOperations","RequireRuntimeQuiescence","RetainOriginalLedger","MutatePointer","MutateNetwork","Rules");
        if(root.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(root,"DefaultAction")!="REFUSE" ||
            !root.GetProperty("RequireRuntimeQuiescence").GetBoolean() || !root.GetProperty("RetainOriginalLedger").GetBoolean() ||
            root.GetProperty("MutatePointer").GetBoolean() || root.GetProperty("MutateNetwork").GetBoolean())throw new InvalidDataException("Unsafe reconciliation policy");
        if(!root.GetProperty("AllowedOperations").EnumerateArray().Select(n=>n.GetString()).SequenceEqual(new[]{"install","update","rollback"}))
            throw new InvalidDataException("Recovery operation scope differs");
        var rules=new List<RecoveryRule>();var seen=new HashSet<(string,string,string)>();
        foreach(var entry in root.GetProperty("Rules").EnumerateArray())
        {
            StrictJson.Fields(entry,"Ledger","Pointer","Payload","Action");
            var rule=new RecoveryRule(StrictJson.Text(entry,"Ledger"),StrictJson.Text(entry,"Pointer"),StrictJson.Text(entry,"Payload"),StrictJson.Text(entry,"Action"));
            if(!seen.Add((rule.Ledger,rule.Pointer,rule.Payload)))throw new InvalidDataException("Ambiguous recovery rule");rules.Add(rule);
        }
        return rules.AsReadOnly();
    }
    internal static string Decide(string operation,string ledger,string pointer,string payload) =>
        operation is not ("install" or "update" or "rollback")?"REFUSE":
        Rules.SingleOrDefault(r=>r.Ledger==ledger && r.Pointer==pointer && r.Payload==payload)?.Action??"REFUSE";
    internal static bool IsResolution(string action)=>action is "RECONCILE_TARGET_INACTIVE" or "ABORT_PRIOR_UNCHANGED_RETAIN_PAYLOAD" or
        "ABORT_UNCOMMITTED_RETAIN_PAYLOAD" or "VERIFY_COMPLETED_CURRENT_INACTIVE";
}

internal sealed record RecoveryReceipt(int SchemaVersion,string InstallationId,string OperationId,string RecoveryId,string PlanSHA256,
    string LastRecordSHA256,string OriginalPhase,int OriginalRecordCount,string? CurrentPointerSHA256,string Action,
    string PayloadObservation,string? FailureType,bool OriginalLedgerRetained,string AtUtc);

internal static class LifecycleRecovery
{
    internal static RecoveryReceipt Reconcile(FixedLayout layout,ProtectedState state,string operationId,ILifecycleRuntimeLease runtime)
    {
        state.AssertHeld();runtime.AssertLaunchAdmissionClosed();runtime.AssertNoOwnedProcesses();
        var journal=LifecycleJournal.Read(state,operationId);
        if(journal.Operation=="uninstall")throw new InvalidOperationException("Use ExactUninstall.Resume with the resource and exact-file recovery owner");
        var current=state.ReadOptional("current.json");CurrentPointer? pointer=current is null?null:CurrentPointer.Parse(current,state.InstallationId);
        var relation=current is null?(journal.PriorPointer is null?"absent":"foreign"):
            journal.PriorPointer?.SHA256==current.SHA256?"prior":
            pointer!.OperationId==journal.OperationId && pointer.Release==journal.Target?"target":"foreign";
        var observation="not-applicable";string? failure=null;VerifiedVersion? verified=null;
        try
        {
            if(relation is "prior" or "target")
            {
                try
                {
                    verified=VerifiedVersion.Open(layout,state,pointer!.Release);
                    if(verified.Package.ManifestHash!=pointer.ManifestSHA256)throw new InvalidDataException("Observed pointer manifest differs");
                    verified.AssertHeld(state);observation="verified";
                }
                catch(Exception ex) when(ex is IOException or InvalidDataException or System.ComponentModel.Win32Exception or UnauthorizedAccessException or InvalidOperationException)
                {observation="not-verified";failure=ex.GetType().Name;}
            }
            var action=RecoveryPolicy.Decide(journal.Operation,journal.Completed?"completed":"incomplete",relation,observation);
            if(journal.RecordCount==0 && relation=="target")action="REFUSE"; // Our writer cannot switch before a begin record.
            runtime.AssertLaunchAdmissionClosed();runtime.AssertNoOwnedProcesses();state.AssertHeld();
            verified?.AssertHeld(state);
            if(state.ReadOptional("current.json")?.SHA256!=current?.SHA256)throw new InvalidOperationException("Pointer changed during reconciliation");
            if(action is "RECONCILE_TARGET_INACTIVE" or "VERIFY_COMPLETED_CURRENT_INACTIVE")VersionSelector.RecordSelection(state,pointer!,current!.SHA256);
            var receipt=new RecoveryReceipt(1,state.InstallationId,journal.OperationId,Guid.NewGuid().ToString("N"),journal.PlanSHA256,journal.LastRecordSHA256,
                journal.Phase,journal.RecordCount,current?.SHA256,action,observation,failure,true,DateTime.UtcNow.ToString("o"));
            state.WriteNew("recovery-"+journal.OperationId+"-"+receipt.RecoveryId+".json",JsonSerializer.SerializeToUtf8Bytes(receipt));
            return receipt;
        }
        finally{verified?.Dispose();}
    }
    internal static void AssertNoPending(ProtectedState state,string? exceptOperation=null,bool forNetworkMigration=false,bool forManifestAccessRecovery=false)
    {
        state.AssertHeld();
        // Legacy parameter name; only explicit installed OS-resource inspect/
        // recovery commands skip the fixed OS-resource pending gates. All other
        // lifecycle, installed-host, elevation and recovery checks still run.
        if(!forManifestAccessRecovery)SessionManifestReadAccess.AssertNoPending(state);
        if(!forManifestAccessRecovery)SessionEtwProviderAccess.AssertNoPending(state);
        if(!forManifestAccessRecovery)SessionTimeZoneReadAccess.AssertNoPending(state);
        if(!forManifestAccessRecovery)SessionWinsockReadAccess.AssertNoPending(state);
        if(!forNetworkMigration)FencePlan.AssertNoPendingMigration(state);
        foreach(var leaf in state.ListLeaves("plan-"))
        {
            if(leaf.Length!=42 || !leaf.EndsWith(".json",StringComparison.Ordinal))throw new InvalidDataException("Unexpected plan filename");
            var id=Identifiers.Hex32(leaf.Substring(5,32));var journal=LifecycleJournal.Read(state,id);
            if(id==exceptOperation)continue; // Caller must separately reopen and validate this exact ledger.
            if(journal.Completed)continue;
            var resolved=false;
            foreach(var resolution in state.ListLeaves("recovery-").Where(n=>n.StartsWith("recovery-"+id+"-",StringComparison.Ordinal)))
            {
                var raw=state.Read(resolution,16384);using var doc=JsonDocument.Parse(raw.Bytes);var root=doc.RootElement;
                StrictJson.Fields(root,"SchemaVersion","InstallationId","OperationId","RecoveryId","PlanSHA256","LastRecordSHA256","OriginalPhase","OriginalRecordCount",
                    "CurrentPointerSHA256","Action","PayloadObservation","FailureType","OriginalLedgerRetained","AtUtc");
                var recoveryId=Identifiers.Hex32(StrictJson.Text(root,"RecoveryId"));
                if(root.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(root,"InstallationId")!=state.InstallationId || StrictJson.Text(root,"OperationId")!=id ||
                    resolution!="recovery-"+id+"-"+recoveryId+".json" || !root.GetProperty("OriginalLedgerRetained").GetBoolean())throw new InvalidDataException("Foreign recovery receipt");
                if(StrictJson.Text(root,"PlanSHA256")==journal.PlanSHA256 && StrictJson.Text(root,"LastRecordSHA256")==journal.LastRecordSHA256 &&
                    StrictJson.Text(root,"OriginalPhase")==journal.Phase && root.GetProperty("OriginalRecordCount").GetInt32()==journal.RecordCount &&
                    RecoveryPolicy.IsResolution(StrictJson.Text(root,"Action")))
                {
                    var action=StrictJson.Text(root,"Action");var pointerHash=LifecycleJournal.NullableText(root,"CurrentPointerSHA256");
                    var observation=StrictJson.Text(root,"PayloadObservation");
                    if(LifecycleJournal.NullableText(root,"FailureType") is not null ||
                        (action=="ABORT_UNCOMMITTED_RETAIN_PAYLOAD"?observation!="not-applicable":observation!="verified"))
                        throw new InvalidDataException("Recovery action contradicts its observation");
                    if(action=="ABORT_UNCOMMITTED_RETAIN_PAYLOAD")
                    {if(journal.PriorPointer is not null || pointerHash is not null || journal.Operation!="install")throw new InvalidDataException("Invalid uncommitted recovery");}
                    else if(action=="ABORT_PRIOR_UNCHANGED_RETAIN_PAYLOAD")
                    {if(journal.PriorPointer is null || pointerHash!=journal.PriorPointer.SHA256)throw new InvalidDataException("Recovery prior pointer differs");}
                    else
                    {if(journal.RecordCount==0 || journal.Target is null || pointerHash!=VersionSelector.ReadSelectionHash(state,journal.Target,id))throw new InvalidDataException("Recovery target selection differs");}
                    resolved=true;
                }
            }
            if(!resolved)throw new InvalidOperationException("Unresolved lifecycle operation requires explicit recovery: "+id);
        }
    }
}
