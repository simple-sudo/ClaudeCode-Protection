namespace ProtectionLifecycle;

internal sealed class WfpFailure : IOException
{
    internal uint Status { get; }
    internal string Stage { get; }
    internal WfpFailure(string stage,uint status):base(stage+":0x"+status.ToString("X8")){Stage=stage;Status=status;HResult=unchecked((int)status);}
}
internal sealed record WfpErrorEvidence(string Type,uint Code,string? Stage);
