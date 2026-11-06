using System.Text.Json;

namespace ClaudeCodeProtection.Workspaces;

// Public support summary only; raw Token/device/progress/Job records remain on
// the trusted installed owner. A reply never grants protected execution.
internal sealed record HostGpuReferenceReply(int SchemaVersion,string Nonce,string Status,int ExitCode,string? RequestId,uint? ChildPid,
    bool Complete,bool OriginalJobClosed,uint[] FailureCodes,bool ProtectedGpuVerified,bool FormalAdmissionIssued,bool ClaudeLaunched)
{
    internal const string Passed="BOUND_ORDINARY_HOST_GPU_REFERENCE_CLOSED";
    internal const string Failed="BOUND_ORDINARY_HOST_GPU_REFERENCE_NOT_CONFIRMED";
    internal static HostGpuReferenceReply Parse(byte[] bytes,string nonce)
    {
        if(bytes.Length is <1 or >4096 || !Hex32(nonce))throw new InvalidDataException("Host GPU reply bounds");
        using var doc=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=3});var r=doc.RootElement;
        var fields=new[]{"SchemaVersion","Nonce","Status","ExitCode","RequestId","ChildPid","Complete","OriginalJobClosed","FailureCodes","ProtectedGpuVerified","FormalAdmissionIssued","ClaudeLaunched"};
        if(r.ValueKind!=JsonValueKind.Object)throw new InvalidDataException("Host GPU reply object required");
        var names=r.EnumerateObject().Select(p=>p.Name).ToArray();
        if(names.Length!=fields.Length || names.Distinct(StringComparer.Ordinal).Count()!=fields.Length ||
            !names.OrderBy(n=>n,StringComparer.Ordinal).SequenceEqual(fields.OrderBy(n=>n,StringComparer.Ordinal)))throw new InvalidDataException("Host GPU reply fields differ");
        var reply=JsonSerializer.Deserialize<HostGpuReferenceReply>(bytes)??throw new InvalidDataException("Host GPU reply missing");
        if(reply.SchemaVersion!=1 || reply.Nonce!=nonce || reply.ExitCode is not (0 or 3 or 125) || reply.FailureCodes is null || reply.FailureCodes.Length>32 ||
            reply.RequestId is not null && !Hex32(reply.RequestId) || reply.ChildPid==0 || reply.ProtectedGpuVerified || reply.FormalAdmissionIssued || reply.ClaudeLaunched ||
            reply.Complete!=(reply.ExitCode==0) || reply.Status!=(reply.Complete?Passed:Failed) ||
            reply.Complete && (!reply.OriginalJobClosed || reply.ChildPid is null || reply.RequestId is null || reply.FailureCodes.Length!=0) ||
            reply.OriginalJobClosed && reply.RequestId is null)throw new InvalidDataException("Host GPU reply scope or closure differs");
        return reply;
    }
    private static bool Hex32(string? value)=>value is {Length:32} && value.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f');
}
