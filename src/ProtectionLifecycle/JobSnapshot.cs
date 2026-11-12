namespace ProtectionLifecycle;

internal sealed record JobSnapshot(string JobId,uint LimitFlags,uint ActiveBefore,uint ActiveAfter,uint[] ProcessIds,string AtUtc)
{
    internal bool ExpectedLimits=>LimitFlags==OwnedKernelJob.RequiredLimits;
    internal bool ObservedZero=>ActiveBefore==0 && ActiveAfter==0 && ProcessIds.Length==0;
}
