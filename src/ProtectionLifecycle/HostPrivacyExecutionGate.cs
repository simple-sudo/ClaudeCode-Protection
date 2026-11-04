using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

// Original-owner memory only. Never deserialize this state from task files or
// accept a child's phase flag. PIDs are supplied by the held native Job checks.
internal sealed class HostPrivacyExecutionGate
{
    private readonly string session, planHash;
    private readonly bool resetSettingsAbsent;
    private HostPrivacyObservation? root, probe, tool;
    private int phase; // root sealed1, probe creation2/sealed3, compiler creation4/sealed5, code6
    internal bool ExecutionReleased => phase == 6;
    internal bool ToolCreationAuthorized => phase >= 2;
    internal bool ProbeSealed => phase >= 3;
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
    internal void AuthorizeProbeCreation()
    {
        if(phase != 1) throw new InvalidDataException("Host privacy single tool creation order differs");
        phase = 2;
    }
    internal void SealProbe(HostPrivacyObservation value, int expectedPid)
    {
        if(phase != 2 || root is null || expectedPid == root.Pid)
            throw new InvalidDataException("Host privacy tool sealing order differs");
        probe = CopyChecked(value, expectedPid); phase = 3;
    }
    // Only the owner calls this after held probe exit0 and plan withdrawal.
    internal void AuthorizeToolCreation()
    {
        if(phase!=3)throw new InvalidDataException("Host privacy probe must finish before compiler creation");
        phase=4;
    }
    internal void SealTool(HostPrivacyObservation value,int expectedPid)
    {
        if(phase!=4 || root is null || probe is null || expectedPid<=0 || expectedPid==root.Pid || expectedPid==probe.Pid ||
            value.SchemaVersion!=1 || value.SessionId!=session || value.PlanSHA256!=planHash || value.Pid!=expectedPid)
            throw new InvalidDataException("Host privacy compiler binding differs");
        HostPrivacyContract.ValidateCompilerCases(value.Cases);
        if(value.Cases.Any(c=>c.Status!="ACCESS_DENIED" || c.Error!=5))throw new InvalidDataException("Compiler control checks not denied");
        tool=value with {Cases=value.Cases.ToArray()};phase=5;
    }
    internal void ReleaseExecution()
    {
        if(phase != 5) throw new InvalidDataException("Host privacy three sealed actors required before code");
        phase = 6;
    }
    internal HostPrivacySummary Snapshot(int rootPid, int toolPid)
    {
        if(phase < 5 || root is null || probe is null || tool is null || root.Pid != rootPid || tool.Pid != toolPid)
            throw new InvalidDataException("Host privacy sealed actor binding differs");
        var result = new HostPrivacySummary(HostPrivacyContract.PolicySHA256, planHash, session, root.Pid, tool.Pid,
            root.Cases.ToArray(), tool.Cases.ToArray()){ProbePid=probe.Pid,ProbeCases=probe.Cases.ToArray()};
        HostPrivacyContract.Validate(result, session, true); return result;
    }
}
