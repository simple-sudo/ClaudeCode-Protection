namespace ClaudeCodeProtection.Workspaces;

internal sealed record HostPrivacyCase(string Role,string Kind,string Status,int Error);
internal sealed record HostPrivacyContentRead(string Role,string Status,int Error,int Length,string? SHA256,byte[]? Content);
internal sealed record HostPrivacyContentItem(string Actor,string Role,string Status,int Error,int Length,string? SHA256,byte[]? Content);
internal sealed record HostPrivacyContentBundle(int SchemaVersion,string SessionId,string PlanSHA256,string Scope,HostPrivacyContentItem[] Items);
internal sealed record HostPrivacyClosure(HostPrivacySummary Summary,HostPrivacyContentBundle Content);
internal sealed record HostPrivacyObservation(int SchemaVersion,string SessionId,string PlanSHA256,int Pid,HostPrivacyCase[] Cases)
{
    public HostPrivacyContentRead[] ContentReads {get;init;}=Array.Empty<HostPrivacyContentRead>();
}
internal sealed record HostPrivacySummary(string PolicySHA256,string PlanSHA256,string SessionId,int RootPid,int? ToolPid,
    HostPrivacyCase[] RootCases,HostPrivacyCase[] ToolCases)
{
    public int? ProbePid {get;init;}
    public HostPrivacyCase[] ProbeCases {get;init;}=Array.Empty<HostPrivacyCase>();
    public string? ContentEvidenceSHA256 {get;init;}
    public int ContentEvidenceCount {get;init;}
}

internal enum HostPrivacyTarget
{
    FlClashJson, FlClashYaml, FlClashPreferences, UuUserSettings, UuUserConfigures,
    UuSystemUser, UuSystemAssist, ClaudeSettings, GitConfig, MachineRegistry, UserRegistry,
    FlClashUi, FlClashCore, UuService, OwnerProcess, RootProcess, InstallationRecord, VersionSelection, RuntimeImage
}

internal enum HostPrivacyTargetKind { HostFile, MachineRegistry, UserRegistry, HostProcess, OwnerProcess, RootProcess, ControlFile }
