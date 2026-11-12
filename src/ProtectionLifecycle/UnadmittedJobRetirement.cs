namespace ProtectionLifecycle;

using System.Text.Json;

internal sealed record UnadmittedJobRetirement(int SchemaVersion,string IntentSHA256,string Status,uint TotalProcesses,JobSnapshot Snapshot)
{
    internal const string Disposition="NEVER_ADMITTED_ORIGINAL_JOB_ZERO_OBSERVED";
    internal static string Leaf(string id)=>"job-unadmitted-retired-"+Identifiers.Hex32(id)+".json";

    internal static void AssertNoAdmissionEvidence(ProtectedState state,OwnedJobIntent intent)
    {
        if(state.ReadOptional("job-admission-"+intent.JobId+".json") is not null ||
            state.ReadOptional("job-completed-"+intent.JobId+".json") is not null)
            throw WfpNative.Contract("UnadmittedJobConflictingAdmissionEvidence");
    }

    internal static bool Read(ProtectedState state,OwnedJobIntent intent)
    {
        state.AssertHeld();
        var raw=state.ReadOptional(Leaf(intent.JobId));
        if(raw is null)return false;
        if(OwnedJobIntent.Read(state,intent.JobId)!=intent)throw WfpNative.Contract("UnadmittedJobIntentMismatch");
        AssertNoAdmissionEvidence(state,intent);
        Parse(raw.Bytes,intent,state.Read(OwnedJobIntent.Leaf(intent.JobId),8192).SHA256);
        return true;
    }

    internal static void Parse(byte[] bytes,OwnedJobIntent intent,string intentHash)
    {
        using var doc=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=5});
        var record=doc.RootElement;
        StrictJson.Fields(record,"SchemaVersion","IntentSHA256","Status","TotalProcesses","Snapshot");
        StrictJson.Fields(record.GetProperty("Snapshot"),"JobId","LimitFlags","ActiveBefore","ActiveAfter","ProcessIds","AtUtc");
        var result=record.Deserialize<UnadmittedJobRetirement>();
        if(intent.SchemaVersion!=2 || intent.CreatorServiceSid is not null || result is null || result.SchemaVersion!=1 ||
            result.IntentSHA256!=intentHash || result.Status!=Disposition || result.TotalProcesses!=0 ||
            result.Snapshot is not {ProcessIds:not null} snapshot ||
            snapshot.JobId!=intent.JobId || !snapshot.ExpectedLimits || !snapshot.ObservedZero)
            throw WfpNative.Contract("UnadmittedJobRetirementProofMismatch");
    }
}
