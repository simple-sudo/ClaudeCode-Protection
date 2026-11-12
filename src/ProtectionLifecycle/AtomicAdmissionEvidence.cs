namespace ProtectionLifecycle;

internal sealed record AdmissionToken(bool IsAppContainer,string? PackageSid,int CapabilityCount,string IntegritySid,bool LpacAccessCheckObserved,uint ApplicationPackageAccessMask)
{
    // Held native observation, not caller JSON. Preserve the existing public
    // evidence schema while retaining exact SIDs/attributes for owner checks.
    [System.Text.Json.Serialization.JsonIgnore]
    internal TokenCapabilitySnapshot? Capabilities {get;init;}
}
internal sealed record ResourceBootstrapFailure(int SchemaVersion,string Scope,string Phase,string Type,int Code,string? NativeStage);
internal sealed record OwnedMemberInspection(uint Pid,bool MembershipConfirmed,long? CreatedFileTime,string? ImagePath,AdmissionToken? Token,WfpErrorEvidence[] Failures);
