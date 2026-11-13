using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ClaudeCodeProtection.Workspaces;

internal sealed record HostPrivacyCheck(string Role,string Kind,HostPrivacyTarget Target,HostPrivacyTargetKind TargetKind,
    uint Access,bool AllowsOwnerObservedAbsence=false)
{
    internal HostPrivacyCase Observe(int error,bool ownerObservedAbsent=false)
    {
        if(ownerObservedAbsent && !AllowsOwnerObservedAbsence)
            throw new InvalidDataException("Optional reset target differs");
        var status=ownerObservedAbsent
            ?error is 2 or 3?HostPrivacyContract.OwnerObservedAbsent:error==0?"OPENED":"UNKNOWN"
            :error==5?"ACCESS_DENIED":error==0?"OPENED":"UNKNOWN";
        return new(Role,Kind,status,error);
    }
}

// This is a bounded named-resource observation contract, not an admission or
// a claim that all host information, MAC/BSSID, COM or device APIs are hidden.
internal static class HostPrivacyContract
{
    internal const string OwnerObservedAbsent="OWNER_OBSERVED_ABSENT";
    // Order is part of the v5 wire contract. The catalogue binds each
    // observation to its target and minimal native access right.
    internal static IReadOnlyList<HostPrivacyCheck> Checks {get;}=Array.AsReadOnly(new HostPrivacyCheck[]{
        new("flclash-config-json", "file-read-data-open", HostPrivacyTarget.FlClashJson, HostPrivacyTargetKind.HostFile, 0x1),
        new("flclash-config-yaml", "file-read-data-open", HostPrivacyTarget.FlClashYaml, HostPrivacyTargetKind.HostFile, 0x1),
        new("flclash-preferences", "file-read-data-open", HostPrivacyTarget.FlClashPreferences, HostPrivacyTargetKind.HostFile, 0x1),
        new("uu-user-settings", "file-read-data-open", HostPrivacyTarget.UuUserSettings, HostPrivacyTargetKind.HostFile, 0x1),
        new("uu-user-configures", "file-read-data-open", HostPrivacyTarget.UuUserConfigures, HostPrivacyTargetKind.HostFile, 0x1),
        new("uu-system-user", "file-read-data-open", HostPrivacyTarget.UuSystemUser, HostPrivacyTargetKind.HostFile, 0x1),
        new("uu-system-assist", "file-read-data-open", HostPrivacyTarget.UuSystemAssist, HostPrivacyTargetKind.HostFile, 0x1),
        new("private-claude-settings", "file-read-data-open", HostPrivacyTarget.ClaudeSettings, HostPrivacyTargetKind.HostFile, 0x1, AllowsOwnerObservedAbsence:true),
        new("private-git-config", "file-read-data-open", HostPrivacyTarget.GitConfig, HostPrivacyTargetKind.HostFile, 0x1),
        new("device-machine-guid", "registry-query-value-open", HostPrivacyTarget.MachineRegistry, HostPrivacyTargetKind.MachineRegistry, 0x101),
        new("proxy-user-key", "registry-query-value-open", HostPrivacyTarget.UserRegistry, HostPrivacyTargetKind.UserRegistry, 0x101),
        new("flclash-ui-memory", "process-vm-read-open", HostPrivacyTarget.FlClashUi, HostPrivacyTargetKind.HostProcess, 0x10),
        new("flclash-core-memory", "process-vm-read-open", HostPrivacyTarget.FlClashCore, HostPrivacyTargetKind.HostProcess, 0x10),
        new("uu-service-memory", "process-vm-read-open", HostPrivacyTarget.UuService, HostPrivacyTargetKind.HostProcess, 0x10),
        new("protection-owner-memory", "process-vm-read-open", HostPrivacyTarget.OwnerProcess, HostPrivacyTargetKind.OwnerProcess, 0x10),
        new("protection-owner-terminate", "process-terminate-open", HostPrivacyTarget.OwnerProcess, HostPrivacyTargetKind.OwnerProcess, 0x1),
        new("protection-owner-create-thread", "process-create-thread-open", HostPrivacyTarget.OwnerProcess, HostPrivacyTargetKind.OwnerProcess, 0x2),
        new("protection-owner-vm-operation", "process-vm-operation-open", HostPrivacyTarget.OwnerProcess, HostPrivacyTargetKind.OwnerProcess, 0x8),
        new("protection-owner-vm-write", "process-vm-write-open", HostPrivacyTarget.OwnerProcess, HostPrivacyTargetKind.OwnerProcess, 0x20),
        new("protection-owner-duplicate-handle", "process-duplicate-handle-open", HostPrivacyTarget.OwnerProcess, HostPrivacyTargetKind.OwnerProcess, 0x40),
        new("protection-owner-suspend-resume", "process-suspend-resume-open", HostPrivacyTarget.OwnerProcess, HostPrivacyTargetKind.OwnerProcess, 0x800),
        new("protection-owner-write-dacl", "process-write-dacl-open", HostPrivacyTarget.OwnerProcess, HostPrivacyTargetKind.OwnerProcess, 0x40000),
        new("protection-owner-write-owner", "process-write-owner-open", HostPrivacyTarget.OwnerProcess, HostPrivacyTargetKind.OwnerProcess, 0x80000),
        new("protection-private-state-read", "file-read-data-open", HostPrivacyTarget.InstallationRecord, HostPrivacyTargetKind.ControlFile, 0x1),
        new("protection-private-state-write", "file-write-data-open", HostPrivacyTarget.InstallationRecord, HostPrivacyTargetKind.ControlFile, 0x2),
        new("protection-private-state-write-dacl", "file-write-dacl-open", HostPrivacyTarget.InstallationRecord, HostPrivacyTargetKind.ControlFile, 0x40000),
        new("protection-private-state-write-owner", "file-write-owner-open", HostPrivacyTarget.InstallationRecord, HostPrivacyTargetKind.ControlFile, 0x80000),
        new("protection-selection-write", "file-write-data-open", HostPrivacyTarget.VersionSelection, HostPrivacyTargetKind.ControlFile, 0x2),
        new("protection-selection-write-dacl", "file-write-dacl-open", HostPrivacyTarget.VersionSelection, HostPrivacyTargetKind.ControlFile, 0x40000),
        new("protection-selection-write-owner", "file-write-owner-open", HostPrivacyTarget.VersionSelection, HostPrivacyTargetKind.ControlFile, 0x80000),
        new("protection-runtime-write", "file-write-data-open", HostPrivacyTarget.RuntimeImage, HostPrivacyTargetKind.ControlFile, 0x2),
        new("protection-runtime-write-dacl", "file-write-dacl-open", HostPrivacyTarget.RuntimeImage, HostPrivacyTargetKind.ControlFile, 0x40000),
        new("protection-runtime-write-owner", "file-write-owner-open", HostPrivacyTarget.RuntimeImage, HostPrivacyTargetKind.ControlFile, 0x80000),
    });
    internal const int MaximumHostFileContentBytes=256*1024;
    internal const string ContentEvidenceScope="FIXED_HOST_FILE_BYTES_ONLY;REGISTRY_VALUES_AND_PROCESS_MEMORY_NOT_READ";
    internal static IReadOnlyList<HostPrivacyCheck> HostFileChecks {get;}=Array.AsReadOnly(
        Checks.Where(check=>check.TargetKind==HostPrivacyTargetKind.HostFile).ToArray());
    internal static IReadOnlyList<HostPrivacyCheck> CompilerChecks {get;}=Array.AsReadOnly(
        Checks.Where(check=>check.TargetKind is HostPrivacyTargetKind.OwnerProcess or HostPrivacyTargetKind.ControlFile)
            .Concat(Checks.Where(check=>check.TargetKind==HostPrivacyTargetKind.OwnerProcess).Select(check=>check with {
                Role=check.Role.Replace("protection-owner-","protection-root-",StringComparison.Ordinal),
                Target=HostPrivacyTarget.RootProcess,TargetKind=HostPrivacyTargetKind.RootProcess
            })).ToArray());

    // V7 adds bounded actual host-file content reads; registry values and process memory remain open-only.
    internal static string PolicySHA256 {get;}=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        "CPC-HOST-PRIVACY-SEPARATE-PROBE-V7\nROOT_AND_FIXED_PROBE=33;PROBE_EXIT_ZERO_AND_PLAN_WITHDRAWN_BEFORE_COMPILER;COMPILER=19_OWNER_CONTROL_FILE_PLUS_9_ROOT_PROCESS;NO_PRIVATE_PLAN_IN_COMPILER\nOPTIONAL_RESET_SETTINGS=7;OWNER_METADATA_ABSENCE_BOUND_TO_PLAN;RECHECK_BEFORE_CODE_AND_AFTER_JOB;ABSENCE_IS_NOT_DENIAL;ABSENCE_NATIVE_ERRORS=2,3_ONLY\nFILE_READ_DATA=1;FILE_WRITE_DATA=2;WRITE_DAC=262144;WRITE_OWNER=524288;OVERLAPPED;SHARE=7;REG_QUERY_VALUE=1;VIEW64;PROCESS_VM_READ=16;BOUNDED_FILE_READ=262144;NO_REGISTRY_VALUE_OR_PROCESS_MEMORY_READ;NO_FILE_OR_PROCESS_OPERATION\nHOST_FILE_CONTENT_READ=9;OWNER_REFERENCE_PLUS_ROOT_AND_PROBE;PROTECTED_STATE_SEAL;TRUNCATED_CONTENT_IS_NOT_COMPLETE\n"+
        RightsText(HostPrivacyTargetKind.OwnerProcess)+"\n"+
        RightsText(HostPrivacyTargetKind.ControlFile)+"\n"+
        string.Join("\n",Checks.Select(check=>check.Role+"|"+check.Kind)))));
    private static string RightsText(HostPrivacyTargetKind kind)=>string.Join(";",Checks.Where(check=>check.TargetKind==kind)
        .Select(check=>FormattableString.Invariant($"{check.Role}={check.Access}")));

    internal static void ValidateCases(HostPrivacyCase[] cases,bool allowEmpty=false)
        =>ValidateInventory(cases,Checks,allowEmpty);
    internal static void ValidateCompilerCases(HostPrivacyCase[] cases,bool allowEmpty=false)
        =>ValidateInventory(cases,CompilerChecks,allowEmpty);
    internal static void ValidateContentReads(HostPrivacyContentRead[] reads)
    {
        if(reads is null || reads.Length!=HostFileChecks.Count)throw new InvalidDataException("Host file content inventory differs");
        for(var i=0;i<reads.Length;i++)
        {
            var item=reads[i];var check=HostFileChecks[i];
            if(item is null || item.Role!=check.Role || item.Error is <0 or >65535 ||
                item.Length is <0 or >MaximumHostFileContentBytes ||
                (item.Content is null)!=(item.Length==0 && item.SHA256 is null))
                throw new InvalidDataException("Host file content evidence shape differs");
            if(item.Content is not null &&
                (item.Content.Length!=item.Length || !WorkspaceBundle.IsHash(item.SHA256) ||
                 WorkspaceBundle.Hash(item.Content)!=item.SHA256))
                throw new InvalidDataException("Host file content digest or length differs");
            if(item.Content is null && (item.Length!=0 || item.SHA256 is not null))
                throw new InvalidDataException("Absent host content must not carry bytes or digest");
            var valid=item.Status switch {
                "CONTENT_READ"=>item.Error==0 && item.Content is not null,
                "TRUNCATED"=>item.Error==122 && item.Content?.Length==MaximumHostFileContentBytes,
                "ACCESS_DENIED"=>item.Error==5 && item.Content is null,
                "TARGET_ABSENT"=>item.Error is 2 or 3 && item.Content is null,
                "UNKNOWN"=>item.Error!=0 && item.Content is null,
                _=>false
            };
            if(!valid)throw new InvalidDataException("Host file content status contradicts its read evidence");
        }
    }
    internal static void ValidateContentBundle(HostPrivacyContentBundle bundle,string session,string planHash)
    {
        if(bundle is null || bundle.SchemaVersion!=1 || bundle.SessionId!=session || bundle.PlanSHA256!=planHash ||
            bundle.Scope!=ContentEvidenceScope || bundle.Items is null ||
            bundle.Items.Length is <18 or >27)
            throw new InvalidDataException("Host privacy content bundle binding or bounds differ");
        foreach(var actor in new[]{"owner","root","probe"})
        {
            var items=bundle.Items.Where(item=>item.Actor==actor).ToArray();
            if(actor=="probe" && items.Length==0)continue;
            if(items.Length!=HostFileChecks.Count ||
                !items.Select(item=>item.Role).SequenceEqual(HostFileChecks.Select(check=>check.Role),StringComparer.Ordinal))
                throw new InvalidDataException("Host privacy content actor inventory differs");
            foreach(var item in items)
            {
                if(item is null)throw new InvalidDataException("Host privacy content item missing");
                ValidateContentReads(new[]{new HostPrivacyContentRead(item.Role,item.Status,item.Error,item.Length,item.SHA256,item.Content)});
            }
            if(actor=="owner" && items.Any(item=>item.Status is not ("CONTENT_READ" or "TRUNCATED" or "TARGET_ABSENT")))
                throw new InvalidDataException("Owner host-file reference was not captured");
        }
        if(bundle.Items.Any(item=>item.Actor is not ("owner" or "root" or "probe")))
            throw new InvalidDataException("Unknown host privacy content actor");
    }
    private static void ValidateInventory(HostPrivacyCase[] cases,IReadOnlyList<HostPrivacyCheck> checks,bool allowEmpty)
    {
        if(cases is null || cases.Length!=checks.Count && !(allowEmpty && cases.Length==0))
            throw new InvalidDataException("Host privacy case inventory differs");
        for(var i=0;i<cases.Length;i++)
        {
            var c=cases[i];var check=checks[i];
            if(c is null || c.Role!=check.Role || c.Kind!=check.Kind || c.Error is <0 or >65535 ||
                (c.Status switch {"ACCESS_DENIED"=>c.Error!=5,"OPENED"=>c.Error!=0,
                    "UNKNOWN"=>c.Error==0 || c.Error==5 && !check.AllowsOwnerObservedAbsence,
                    OwnerObservedAbsent=>!check.AllowsOwnerObservedAbsence || c.Error is not (2 or 3),_=>true}))
                throw new InvalidDataException("Host privacy observation differs");
        }
    }
    // Only the original owner can select the optional missing target in its
    // private plan/gate. A child report alone cannot make it optional.
    internal static bool CasesSatisfied(HostPrivacyCase[] cases,bool resetSettingsAbsent)
    {
        ValidateCases(cases);
        return cases.Select((c,i)=>Checks[i].AllowsOwnerObservedAbsence && resetSettingsAbsent
            ? c.Status==OwnerObservedAbsent && c.Error is 2 or 3
            : c.Status=="ACCESS_DENIED" && c.Error==5).All(value=>value);
    }
    internal static bool Satisfied(HostPrivacySummary summary)
    {
        if(summary.ToolPid is not >0 || summary.ProbePid is not >0 || summary.RootCases.Length!=Checks.Count ||
            summary.ProbeCases.Length!=Checks.Count || summary.ToolCases.Length!=CompilerChecks.Count)return false;
        var absent=summary.RootCases.Any(c=>c.Status==OwnerObservedAbsent);
        return CasesSatisfied(summary.RootCases,absent) && CasesSatisfied(summary.ProbeCases,absent) &&
            summary.ToolCases.All(c=>c.Status=="ACCESS_DENIED" && c.Error==5);
    }
    internal static void Validate(HostPrivacySummary summary,string session,bool requireSatisfied)
    {
        if(summary.RootCases is null || summary.ToolCases is null || summary.ProbeCases is null)throw new InvalidDataException("Host privacy cases missing");
        if(summary.ContentEvidenceCount is <0 or >27 ||
            (summary.ContentEvidenceSHA256 is null)!=(summary.ContentEvidenceCount==0) ||
            summary.ContentEvidenceSHA256 is not null && !WorkspaceBundle.IsHash(summary.ContentEvidenceSHA256) ||
            requireSatisfied && (summary.ContentEvidenceSHA256 is null || summary.ContentEvidenceCount!=27))
            throw new InvalidDataException("Host privacy content evidence receipt missing or inconsistent");
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
        Fields(value,"PolicySHA256","PlanSHA256","SessionId","RootPid","ToolPid","RootCases","ToolCases","ProbePid","ProbeCases","ContentEvidenceSHA256","ContentEvidenceCount");
        foreach(var name in new[]{"RootCases","ToolCases","ProbeCases"})
        {
            var array=value.GetProperty(name);
            var limit=name=="ToolCases"?CompilerChecks.Count:Checks.Count;
            if(array.ValueKind!=JsonValueKind.Array || array.GetArrayLength()>limit)throw new InvalidDataException("Host privacy case bounds");
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
