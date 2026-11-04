using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ClaudeCodeProtection.Workspaces;

internal sealed record HostPrivacyCase(string Role,string Kind,string Status,int Error);
internal sealed record HostPrivacyObservation(int SchemaVersion,string SessionId,string PlanSHA256,int Pid,HostPrivacyCase[] Cases);
internal sealed record HostPrivacySummary(string PolicySHA256,string PlanSHA256,string SessionId,int RootPid,int? ToolPid,
    HostPrivacyCase[] RootCases,HostPrivacyCase[] ToolCases)
{
    public int? ProbePid {get;init;}
    public HostPrivacyCase[] ProbeCases {get;init;}=Array.Empty<HostPrivacyCase>();
}

// This is a bounded named-resource observation contract, not an admission or
// a claim that all host information, MAC/BSSID, COM or device APIs are hidden.
internal static class HostPrivacyContract
{
    internal const int HostResourceCount=14;
    internal const int ResetSettingsIndex=7;
    internal const string OwnerObservedAbsent="OWNER_OBSERVED_ABSENT";
    internal const int OwnerProcessEnd=23,ControlFileStart=23;
    internal const int CompilerCaseCount=28;
    internal static readonly string[] Roles={"flclash-config-json","flclash-config-yaml","flclash-preferences",
        "uu-user-settings","uu-user-configures","uu-system-user","uu-system-assist",
        "private-claude-settings","private-git-config","device-machine-guid","proxy-user-key",
        "flclash-ui-memory","flclash-core-memory","uu-service-memory",
        "protection-owner-memory","protection-owner-terminate","protection-owner-create-thread",
        "protection-owner-vm-operation","protection-owner-vm-write","protection-owner-duplicate-handle",
        "protection-owner-suspend-resume","protection-owner-write-dacl","protection-owner-write-owner",
        "protection-private-state-read","protection-private-state-write","protection-private-state-write-dacl","protection-private-state-write-owner",
        "protection-selection-write","protection-selection-write-dacl","protection-selection-write-owner",
        "protection-runtime-write","protection-runtime-write-dacl","protection-runtime-write-owner"};
    // One minimal right per open: denial of an unrelated additional right
    // must never hide an exposed terminate/injection/handle-control right.
    internal static uint OwnerAccess(int index)=>index switch {
        14=>0x10,15=>0x1,16=>0x2,17=>0x8,18=>0x20,19=>0x40,20=>0x800,21=>0x40000,22=>0x80000,
        _=>throw new InvalidDataException("Unknown protection owner access case")};
    internal static uint ControlFileAccess(int index)=>index switch {
        23=>1,24 or 27 or 30=>2,25 or 28 or 31=>0x40000,26 or 29 or 32=>0x80000,
        _=>throw new InvalidDataException("Unknown protection control file access case")};
    internal static string Kind(int index)=>index switch {
        >=0 and <9=>"file-read-data-open",>=9 and <11=>"registry-query-value-open",>=11 and <=14=>"process-vm-read-open",
        15=>"process-terminate-open",16=>"process-create-thread-open",17=>"process-vm-operation-open",18=>"process-vm-write-open",
        19=>"process-duplicate-handle-open",20=>"process-suspend-resume-open",21=>"process-write-dacl-open",22=>"process-write-owner-open",
        23=>"file-read-data-open",24 or 27 or 30=>"file-write-data-open",25 or 28 or 31=>"file-write-dacl-open",26 or 29 or 32=>"file-write-owner-open",
        _=>throw new InvalidDataException("Unknown host privacy case")};
    internal static string PolicySHA256=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        "CPC-HOST-PRIVACY-SEPARATE-PROBE-V5\nROOT_AND_FIXED_PROBE=33;PROBE_EXIT_ZERO_AND_PLAN_WITHDRAWN_BEFORE_COMPILER;COMPILER=19_OWNER_CONTROL_FILE_PLUS_9_ROOT_PROCESS;NO_PRIVATE_PLAN_IN_COMPILER\nOPTIONAL_RESET_SETTINGS=7;OWNER_METADATA_ABSENCE_BOUND_TO_PLAN;RECHECK_BEFORE_CODE_AND_AFTER_JOB;ABSENCE_IS_NOT_DENIAL\nFILE_READ_DATA=1;FILE_WRITE_DATA=2;WRITE_DAC=262144;WRITE_OWNER=524288;OVERLAPPED;SHARE=7;REG_QUERY_VALUE=1;VIEW64;PROCESS_VM_READ=16;NO_CONTENT_READ;NO_FILE_OR_PROCESS_OPERATION\n"+
        string.Join(";",Enumerable.Range(HostResourceCount,OwnerProcessEnd-HostResourceCount).Select(i=>Roles[i]+"="+OwnerAccess(i)))+"\n"+
        string.Join(";",Enumerable.Range(ControlFileStart,Roles.Length-ControlFileStart).Select(i=>Roles[i]+"="+ControlFileAccess(i)))+"\n"+
        string.Join("\n",Roles.Select((role,i)=>role+"|"+Kind(i))))));
    internal static void ValidateCases(HostPrivacyCase[] cases,bool allowEmpty=false)
    {
        if(cases is null || cases.Length!=(allowEmpty && cases.Length==0?0:Roles.Length))throw new InvalidDataException("Host privacy case inventory differs");
        for(var i=0;i<cases.Length;i++)
        {
            var c=cases[i];
            if(c is null || c.Role!=Roles[i] || c.Kind!=Kind(i) || c.Error is <0 or >65535 ||
                (c.Status switch {"ACCESS_DENIED"=>c.Error!=5,"OPENED"=>c.Error!=0,"UNKNOWN"=>c.Error is 0 or 5,OwnerObservedAbsent=>i!=ResetSettingsIndex || c.Error is not (2 or 3 or 5),_=>true}))
                throw new InvalidDataException("Host privacy observation differs");
        }
    }
    // Only the original owner can select the optional missing target in its
    // private plan/gate. A child report alone cannot make it optional.
    internal static bool CasesSatisfied(HostPrivacyCase[] cases,bool resetSettingsAbsent)
    {
        ValidateCases(cases);
        return cases.Select((c,i)=>i==ResetSettingsIndex && resetSettingsAbsent
            ? c.Status==OwnerObservedAbsent && c.Error is 2 or 3 or 5
            : c.Status=="ACCESS_DENIED" && c.Error==5).All(value=>value);
    }
    internal static HostPrivacyCase FileObservation(int index,bool ownerObservedAbsent,int error)
    {
        if(index is <0 or >8 || ownerObservedAbsent && index!=ResetSettingsIndex)
            throw new InvalidDataException("Optional reset target differs");
        var status=ownerObservedAbsent && error is 2 or 3 or 5?OwnerObservedAbsent:
            error==5?"ACCESS_DENIED":error==0?"OPENED":"UNKNOWN";
        return new(Roles[index],Kind(index),status,error);
    }
    internal static bool Satisfied(HostPrivacySummary summary)
    {
        if(summary.ToolPid is not >0 || summary.ProbePid is not >0 || summary.RootCases.Length!=Roles.Length || summary.ProbeCases.Length!=Roles.Length || summary.ToolCases.Length!=CompilerCaseCount)return false;
        var absent=summary.RootCases[ResetSettingsIndex].Status==OwnerObservedAbsent;
        return CasesSatisfied(summary.RootCases,absent) && CasesSatisfied(summary.ProbeCases,absent) && summary.ToolCases.All(c=>c.Status=="ACCESS_DENIED" && c.Error==5);
    }
    internal static (string Role,string Kind) CompilerCase(int index)
    {
        if(index is <0 or >=CompilerCaseCount)throw new InvalidDataException("Unknown compiler privacy case");
        if(index<19)return(Roles[index+HostResourceCount],Kind(index+HostResourceCount));
        var source=index-19+HostResourceCount;
        return(Roles[source].Replace("protection-owner-","protection-root-",StringComparison.Ordinal),Kind(source));
    }
    internal static void ValidateCompilerCases(HostPrivacyCase[] cases,bool allowEmpty=false)
    {
        if(cases is null || cases.Length!=(allowEmpty && cases.Length==0?0:CompilerCaseCount))throw new InvalidDataException("Compiler privacy inventory differs");
        for(var i=0;i<cases.Length;i++)
        {
            var expected=CompilerCase(i);var c=cases[i];
            if(c is null || c.Role!=expected.Role || c.Kind!=expected.Kind || c.Error is <0 or >65535 ||
                (c.Status switch {"ACCESS_DENIED"=>c.Error!=5,"OPENED"=>c.Error!=0,"UNKNOWN"=>c.Error is 0 or 5,_=>true}))
                throw new InvalidDataException("Compiler privacy observation differs");
        }
    }
    internal static void Validate(HostPrivacySummary summary,string session,bool requireSatisfied)
    {
        if(summary.RootCases is null || summary.ToolCases is null || summary.ProbeCases is null)throw new InvalidDataException("Host privacy cases missing");
        if(summary.PolicySHA256!=PolicySHA256 || summary.SessionId!=session || !WorkspaceBundle.IsHash(summary.PlanSHA256) ||
            summary.RootPid<=0 || summary.ToolPid is <=0 || summary.ToolPid==summary.RootPid ||
            summary.ProbePid is <=0 || summary.ProbePid==summary.RootPid || summary.ProbePid==summary.ToolPid && summary.ProbePid is not null ||
            (summary.ProbePid is null)!=(summary.ProbeCases.Length==0) ||
            (summary.ToolPid is null)!=(summary.ToolCases.Length==0))throw new InvalidDataException("Host privacy session binding differs");
        ValidateCases(summary.RootCases);ValidateCases(summary.ProbeCases,true);ValidateCompilerCases(summary.ToolCases,true);
        if(requireSatisfied && !Satisfied(summary))throw new InvalidDataException("Named resource checks and owner-bound applicability required");
    }
    internal static HostPrivacySummary Parse(JsonElement value,string session,bool requireSatisfied)
    {
        Fields(value,"PolicySHA256","PlanSHA256","SessionId","RootPid","ToolPid","RootCases","ToolCases","ProbePid","ProbeCases");
        foreach(var name in new[]{"RootCases","ToolCases","ProbeCases"})
        {
            var array=value.GetProperty(name);
            if(array.ValueKind!=JsonValueKind.Array || array.GetArrayLength()>Roles.Length)throw new InvalidDataException("Host privacy case bounds");
            foreach(var item in array.EnumerateArray())Fields(item,"Role","Kind","Status","Error");
        }
        var summary=JsonSerializer.Deserialize<HostPrivacySummary>(value.GetRawText())??throw new InvalidDataException("Host privacy summary missing");
        Validate(summary,session,requireSatisfied);return summary;
    }
    internal static void Fields(JsonElement value,params string[] expected)
    {
        if(value.ValueKind!=JsonValueKind.Object)throw new InvalidDataException("Host privacy object required");
        var names=value.EnumerateObject().Select(p=>p.Name).ToArray();
        if(names.Length!=expected.Length || !names.OrderBy(n=>n,StringComparer.Ordinal).SequenceEqual(expected.OrderBy(n=>n,StringComparer.Ordinal)))
            throw new InvalidDataException("Host privacy fields differ");
    }
}
