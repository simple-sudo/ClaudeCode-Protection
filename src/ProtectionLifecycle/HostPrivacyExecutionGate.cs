using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

// Original-owner memory only. Never deserialize this state from task files or
// accept a child's phase flag. PIDs are supplied by the held native Job checks.
internal sealed class HostPrivacyExecutionGate
{
    private readonly string session, planHash;
    private readonly bool resetSettingsAbsent;
    private HostPrivacyObservation? root, tool;
    private int phase; // 0 root pending, 1 root sealed, 2 tool creation, 3 tool sealed, 4 code released
    internal bool ExecutionReleased => phase == 4;
    internal bool ToolCreationAuthorized => phase >= 2;
    internal HostPrivacyExecutionGate(string session, string planHash,bool resetSettingsAbsent=false)
    {
        if(session.Length != 32 || session.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f')) || !WorkspaceBundle.IsHash(planHash))
            throw new InvalidDataException("Host privacy gate context differs");
        this.session = session; this.planHash = planHash;this.resetSettingsAbsent=resetSettingsAbsent;
    }
    private HostPrivacyObservation CopyChecked(HostPrivacyObservation value, int expectedPid)
    {
        if(expectedPid <= 0 || value.SchemaVersion != 1 || value.SessionId != session || value.PlanSHA256 != planHash || value.Pid != expectedPid)
            throw new InvalidDataException("Host privacy gate actor differs");
        HostPrivacyContract.ValidateCases(value.Cases);
        if(!HostPrivacyContract.CasesSatisfied(value.Cases,resetSettingsAbsent))
            throw new InvalidDataException("Host privacy gate needs plan-bound checks");
        return value with { Cases = value.Cases.ToArray() };
    }
    internal void SealRoot(HostPrivacyObservation value, int expectedPid)
    {
        if(phase != 0) throw new InvalidDataException("Host privacy root already sealed");
        root = CopyChecked(value, expectedPid); phase = 1;
    }
    internal void AuthorizeToolCreation()
    {
        if(phase != 1) throw new InvalidDataException("Host privacy single tool creation order differs");
        phase = 2;
    }
    internal void SealTool(HostPrivacyObservation value, int expectedPid)
    {
        if(phase != 2 || root is null || expectedPid == root.Pid)
            throw new InvalidDataException("Host privacy tool sealing order differs");
        tool = CopyChecked(value, expectedPid); phase = 3;
    }
    internal void ReleaseExecution()
    {
        if(phase != 3) throw new InvalidDataException("Host privacy paired sealed observations required before code");
        phase = 4;
    }
    internal HostPrivacySummary Snapshot(int rootPid, int toolPid)
    {
        if(phase < 3 || root is null || tool is null || root.Pid != rootPid || tool.Pid != toolPid)
            throw new InvalidDataException("Host privacy sealed actor binding differs");
        var result = new HostPrivacySummary(HostPrivacyContract.PolicySHA256, planHash, session, root.Pid, tool.Pid,
            root.Cases.ToArray(), tool.Cases.ToArray());
        HostPrivacyContract.Validate(result, session, true); return result;
    }
}
