using System.Text.Json;

namespace ClaudeCodeProtection.Workspaces;

internal sealed record WorkspaceStopEvidence(bool AdmissionClosed,bool QuarantineObservedBeforeStop,bool? FinalJobZero,int StopFailureCount)
{
    internal static WorkspaceStopEvidence? Parse(JsonElement value)
    {
        if(value.ValueKind==JsonValueKind.Null)return null;
        HostPrivacyContract.Fields(value,"AdmissionClosed","QuarantineObservedBeforeStop","FinalJobZero","StopFailureCount");
        bool Flag(string name)
        {
            var field=value.GetProperty(name);
            if(field.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                throw new InvalidDataException("Stop observation must be boolean");
            return field.GetBoolean();
        }
        var zero=value.GetProperty("FinalJobZero");
        var count=value.GetProperty("StopFailureCount");
        if(count.ValueKind!=JsonValueKind.Number || !count.TryGetInt32(out var failures) || failures is <0 or >1024)
            throw new InvalidDataException("Stop failure count refused");
        return new(Flag("AdmissionClosed"),Flag("QuarantineObservedBeforeStop"),zero.ValueKind==JsonValueKind.Null?null:Flag("FinalJobZero"),failures);
    }
}

internal static class WorkspaceStopControl
{
    internal const string ClientFlag="--project-stop-stdin";
    internal const string RequestedStage="WorkspaceProjectStopRequested";
    internal const byte Request=0x43;
    internal static async Task<bool> ReadRequest(Stream stream,CancellationToken cancel)
    {
        var request=new byte[1];
        if(await stream.ReadAsync(request.AsMemory(),cancel)==0)return false;
        if(request[0]!=Request)throw new InvalidDataException("Workspace project stop request refused");
        return true;
    }
}
