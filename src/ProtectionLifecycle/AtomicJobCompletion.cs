using System.Text.Json;

namespace ProtectionLifecycle;

// A completed one-shot admission cannot accept another process. Recovery may
// use its durable zero-members proof; arbitrary missing Jobs remain UNKNOWN.
internal sealed record AtomicJobCompletion(int SchemaVersion,string InstallationId,string JobId,string Release,string ManifestSHA256,
    string AdmissionSHA256,string Status,JobSnapshot Snapshot,
    [property:System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] bool? CreatorAccessRevoked=null)
{
    internal static AtomicJobCompletion? ReadClosed(ProtectedState state,OwnedJobIntent intent)
    {
        state.AssertHeld();var raw=state.ReadOptional("job-completed-"+intent.JobId+".json");if(raw is null)return null;
        if(state.ReadOptional(UnadmittedJobRetirement.Leaf(intent.JobId)) is not null)
            throw WfpNative.Contract("AtomicCompletionConflictsWithUnadmittedRetirement");
        if(state.InstallationId!=intent.InstallationId)throw WfpNative.Contract("AtomicCompletionInstallationMismatch");
        var result=ParseClosed(raw.Bytes,intent);
        var admission=state.Read("job-admission-"+intent.JobId+".json",8192);
        if(admission.SHA256!=Identifiers.Hash(result.AdmissionSHA256))throw WfpNative.Contract("AtomicCompletionAdmissionHashMismatch");
        using var data=JsonDocument.Parse(admission.Bytes);var a=data.RootElement;
        StrictJson.Fields(a,"SchemaVersion","InstallationId","JobId","Release","ManifestSHA256","Binding","Reusable");
        if(a.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(a,"InstallationId")!=state.InstallationId || StrictJson.Text(a,"JobId")!=intent.JobId ||
            StrictJson.Text(a,"Release")!=intent.Release || StrictJson.Text(a,"ManifestSHA256")!=intent.ManifestSHA256 ||
            StrictJson.Text(a,"Binding")!="ATOMIC_JOB_LIST_AT_CREATION" || a.GetProperty("Reusable").GetBoolean())throw WfpNative.Contract("AtomicAdmissionProofMismatch");
        return result;
    }
    internal static AtomicJobCompletion ParseClosed(byte[] bytes,OwnedJobIntent intent)
    {
        using var doc=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=5});var r=doc.RootElement;
        string[] fields=["SchemaVersion","InstallationId","JobId","Release","ManifestSHA256","AdmissionSHA256","Status","Snapshot"];
        StrictJson.Fields(r,intent.CreatorServiceSid is null?fields:[..fields,"CreatorAccessRevoked"]);
        StrictJson.Fields(r.GetProperty("Snapshot"),"JobId","LimitFlags","ActiveBefore","ActiveAfter","ProcessIds","AtUtc");
        var result=r.Deserialize<AtomicJobCompletion>()??throw WfpNative.Contract("MissingAtomicCompletion");
        if(result.SchemaVersion!=1 || result.InstallationId!=intent.InstallationId || result.JobId!=intent.JobId || result.Release!=intent.Release ||
            result.ManifestSHA256!=intent.ManifestSHA256 || result.Status!="ADMISSION_CLOSED_MEMBERS_ZERO_OBSERVED" || result.Snapshot is null ||
            result.Snapshot.JobId!=intent.JobId || !result.Snapshot.ExpectedLimits || !result.Snapshot.ObservedZero ||
            (intent.CreatorServiceSid is not null && result.CreatorAccessRevoked!=true))
            throw WfpNative.Contract("AtomicCompletionOwnershipOrZeroMismatch");
        return result;
    }
}
