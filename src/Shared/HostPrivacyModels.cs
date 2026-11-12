namespace ClaudeCodeProtection.Workspaces;

internal sealed record HostPrivacyCase(string Role,string Kind,string Status,int Error);
internal sealed record HostPrivacyObservation(int SchemaVersion,string SessionId,string PlanSHA256,int Pid,HostPrivacyCase[] Cases);
internal sealed record HostPrivacySummary(string PolicySHA256,string PlanSHA256,string SessionId,int RootPid,int? ToolPid,
    HostPrivacyCase[] RootCases,HostPrivacyCase[] ToolCases)
{
    public int? ProbePid {get;init;}
    public HostPrivacyCase[] ProbeCases {get;init;}=Array.Empty<HostPrivacyCase>();
}

internal enum HostPrivacyTarget
{
    FlClashJson, FlClashYaml, FlClashPreferences, UuUserSettings, UuUserConfigures,
    UuSystemUser, UuSystemAssist, ClaudeSettings, GitConfig, MachineRegistry, UserRegistry,
    FlClashUi, FlClashCore, UuService, OwnerProcess, RootProcess, InstallationRecord, VersionSelection, RuntimeImage
}

internal enum HostPrivacyTargetKind { HostFile, MachineRegistry, UserRegistry, HostProcess, OwnerProcess, RootProcess, ControlFile }
