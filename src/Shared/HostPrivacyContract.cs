using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ClaudeCodeProtection.Workspaces;

internal sealed record HostPrivacyCase(string Role,string Kind,string Status,int Error);
internal sealed record HostPrivacyObservation(int SchemaVersion,string SessionId,string PlanSHA256,int Pid,HostPrivacyCase[] Cases);
internal sealed record HostPrivacySummary(string PolicySHA256,string PlanSHA256,string SessionId,int RootPid,int? ToolPid,
    HostPrivacyCase[] RootCases,HostPrivacyCase[] ToolCases);

// This is a bounded named-resource observation contract, not an admission or
// a claim that all host information, MAC/BSSID, COM or device APIs are hidden.
internal static class HostPrivacyContract
{
    internal const int HostResourceCount=14;
    internal static readonly string[] Roles={"flclash-config-json","flclash-config-yaml","flclash-preferences",
        "uu-user-settings","uu-user-configures","uu-system-user","uu-system-assist",
        "private-claude-settings","private-git-config","device-machine-guid","proxy-user-key",
        "flclash-ui-memory","flclash-core-memory","uu-service-memory",
        "protection-owner-memory","protection-owner-terminate","protection-owner-create-thread",
        "protection-owner-vm-operation","protection-owner-vm-write","protection-owner-duplicate-handle",
        "protection-owner-suspend-resume","protection-owner-write-dacl","protection-owner-write-owner"};
    // One minimal right per open: denial of an unrelated additional right
    // must never hide an exposed terminate/injection/handle-control right.
    internal static uint OwnerAccess(int index)=>index switch {
        14=>0x10,15=>0x1,16=>0x2,17=>0x8,18=>0x20,19=>0x40,20=>0x800,21=>0x40000,22=>0x80000,
        _=>throw new InvalidDataException("Unknown protection owner access case")};
    internal static string Kind(int index)=>index switch {
        >=0 and <9=>"file-read-data-open",>=9 and <11=>"registry-query-value-open",>=11 and <=14=>"process-vm-read-open",
        15=>"process-terminate-open",16=>"process-create-thread-open",17=>"process-vm-operation-open",18=>"process-vm-write-open",
        19=>"process-duplicate-handle-open",20=>"process-suspend-resume-open",21=>"process-write-dacl-open",22=>"process-write-owner-open",
        _=>throw new InvalidDataException("Unknown host privacy case")};
    internal static string PolicySHA256=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        "CPC-HOST-PRIVACY-OWNER-CONTROL-OPEN-ONLY-V2\nFILE_READ_DATA=1;OVERLAPPED;SHARE=7;REG_QUERY_VALUE=1;VIEW64;PROCESS_VM_READ=16;NO_CONTENT_READ;NO_PROCESS_OPERATION\n"+
        string.Join(";",Enumerable.Range(HostResourceCount,Roles.Length-HostResourceCount).Select(i=>Roles[i]+"="+OwnerAccess(i)))+"\n"+
        string.Join("\n",Roles.Select((role,i)=>role+"|"+Kind(i))))));
    internal static void ValidateCases(HostPrivacyCase[] cases,bool allowEmpty=false)
    {
        if(cases is null || cases.Length!=(allowEmpty && cases.Length==0?0:Roles.Length))throw new InvalidDataException("Host privacy case inventory differs");
        for(var i=0;i<cases.Length;i++)
        {
            var c=cases[i];
            if(c is null || c.Role!=Roles[i] || c.Kind!=Kind(i) || c.Error is <0 or >65535 ||
                (c.Status switch {"ACCESS_DENIED"=>c.Error!=5,"OPENED"=>c.Error!=0,"UNKNOWN"=>c.Error is 0 or 5,_=>true}))
                throw new InvalidDataException("Host privacy observation differs");
        }
    }
    internal static bool Satisfied(HostPrivacySummary summary)
        =>summary.ToolPid is >0 && summary.RootCases.Length==Roles.Length && summary.ToolCases.Length==Roles.Length &&
            summary.RootCases.Concat(summary.ToolCases).All(c=>c.Status=="ACCESS_DENIED" && c.Error==5);
    internal static void Validate(HostPrivacySummary summary,string session,bool requireSatisfied)
    {
        if(summary.RootCases is null || summary.ToolCases is null)throw new InvalidDataException("Host privacy cases missing");
        if(summary.PolicySHA256!=PolicySHA256 || summary.SessionId!=session || !WorkspaceBundle.IsHash(summary.PlanSHA256) ||
            summary.RootPid<=0 || summary.ToolPid is <=0 || summary.ToolPid==summary.RootPid ||
            (summary.ToolPid is null)!=(summary.ToolCases.Length==0))throw new InvalidDataException("Host privacy session binding differs");
        ValidateCases(summary.RootCases);ValidateCases(summary.ToolCases,true);
        if(requireSatisfied && !Satisfied(summary))throw new InvalidDataException("Named host resource denials required");
    }
    internal static HostPrivacySummary Parse(JsonElement value,string session,bool requireSatisfied)
    {
        Fields(value,"PolicySHA256","PlanSHA256","SessionId","RootPid","ToolPid","RootCases","ToolCases");
        foreach(var name in new[]{"RootCases","ToolCases"})
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
