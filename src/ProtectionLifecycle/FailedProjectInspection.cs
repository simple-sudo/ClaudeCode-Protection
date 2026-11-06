using System.Security.Cryptography;
using System.Text.Json;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

// A projection of one owner-written terminal record. This is neither a
// current OS observation nor a result-release, recovery or launch decision.
// The live reader belongs to InstalledBroker; this parser has no file access.
internal static class FailedProjectInspection
{
    internal const int MaximumBytes=128*1024;
    internal sealed record Failure(string Type,uint Code,string Stage);
    internal sealed record Child(uint Pid,int? ToolExit,string Type,int? Code,string Stage,ProjectWorkerFeedback.Failure? Worker);
    internal sealed record Summary(int SchemaVersion,string Status,string EvidenceScope,string SessionId,string InputSHA256,
        string TerminalRecordSHA256,string RecordedRelease,string RecordedManifestSHA256,uint? ChildExit,Child? ReportedChild,
        Failure[] ReportedFailures,int OmittedFailureCount,bool LaunchAuthorized=false,bool RecoveryAuthorized=false,bool ResultReleaseAuthorized=false);

    internal static Summary Parse(byte[] bytes,string installationId,string sessionId,string inputSHA256)
    {
        if(!IsId(installationId) || !IsId(sessionId) || !IsHash(inputSHA256) || bytes.Length is 0 or >MaximumBytes)throw Invalid();
        using var document=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=32});
        var root=document.RootElement;Unique(root);
        if(root.ValueKind!=JsonValueKind.Object || Int(root,"SchemaVersion")!=1 || Text(root,"InstallationId")!=installationId ||
            Text(root,"SessionId")!=sessionId || Text(root,"WorkspaceBaselineSHA256")!=inputSHA256 ||
            Text(root,"Scope")!=WorkspacePipe.CallerProjectScope || Text(root,"Status")!="OFFLINE_RESOURCE_SESSION_NOT_CONFIRMED")throw Invalid();
        foreach(var name in new[]{"FormalAdmissionIssued","LaunchAuthorized","NetworkOpened","ClaudeLaunched"})
            if(Field(root,name).ValueKind!=JsonValueKind.False)throw Invalid();
        var release=Text(root,"Release");var manifest=Text(root,"ManifestHash");
        if(!IsId(release) || !IsHash(manifest))throw Invalid();
        var exit=NullableUInt(root,"ChildExit");Child? child=null;
        var item=Field(root,"Child");
        if(item.ValueKind!=JsonValueKind.Null)
        {
            if(item.ValueKind!=JsonValueKind.Object || Int(item,"SchemaVersion")!=1 || Text(item,"Nonce")!=sessionId)throw Invalid();
            var pid=Int(item,"Pid");if(pid<=0)throw Invalid();
            var code=NullableInt(item,"FailureCode");var toolExit=NullableInt(item,"ToolExit");
            var type=Type(NullableText(item,"FailureType"));var stage=Stage(NullableText(item,"FailureStage"));
            child=new((uint)pid,toolExit,type,code,stage,ProjectWorkerFeedback.FromOwnerChild(item,sessionId,pid));
        }
        var failures=Field(root,"Failures");
        if(failures.ValueKind!=JsonValueKind.Array || failures.GetArrayLength()>1024)throw Invalid();
        var selected=new List<Failure>();var count=0;
        foreach(var failure in failures.EnumerateArray())
        {
            if(failure.ValueKind!=JsonValueKind.Object)throw Invalid();
            var type=Type(Text(failure,"Type"));var stage=Stage(NullableText(failure,"Stage"));
            if(!Field(failure,"Code").TryGetUInt32(out var code))throw Invalid();
            if(count++<16)selected.Add(new(type,code,stage));
        }
        return new(1,"FAILED_CALLER_PROJECT_TERMINAL_SUMMARY","REPORTED_TERMINAL_METADATA_NOT_CURRENT_OS_PROOF",sessionId,inputSHA256,
            Convert.ToHexString(SHA256.HashData(bytes)),release,manifest,exit,child,selected.ToArray(),Math.Max(0,count-16));
    }

    private static string Type(string? value)=>value is "InvalidDataException" or "TimeoutException" or "IOException" or
        "Win32Exception" or "WfpFailure" or "OperationCanceledException" or "UnauthorizedAccessException"?value:"UNKNOWN";
    private static string Stage(string? value)=>value is "WAIT_PROJECT_COMPILER" or "WAIT_PROJECT_COMPILER/ProjectDevelopmentNotConfirmed" or
        "WAIT_PROJECT_PROBE" or "START_PROJECT_PROBE" or "READ_WRITE_WORKSPACE" or "WAIT_GIT_TOOL" or "ResourceSessionFailed" or
        "ResourceChildReportMissing" or "ResourceChildIdentityMismatch" or "ResourceChildExitNotConfirmed" or "ResourceFinalQuarantineMissing"?value:"UNKNOWN";
    private static bool IsId(string value)=>value.Length==32 && value.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool IsHash(string value)=>value.Length==64 && value.All(c=>c is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static JsonElement Field(JsonElement value,string name)=>value.TryGetProperty(name,out var field)?field:throw Invalid();
    private static string Text(JsonElement value,string name)=>Field(value,name).ValueKind==JsonValueKind.String?Field(value,name).GetString()!:throw Invalid();
    private static string? NullableText(JsonElement value,string name)=>Field(value,name).ValueKind==JsonValueKind.Null?null:Text(value,name);
    private static int Int(JsonElement value,string name)=>Field(value,name).TryGetInt32(out var number)?number:throw Invalid();
    private static int? NullableInt(JsonElement value,string name)=>Field(value,name).ValueKind==JsonValueKind.Null?null:Int(value,name);
    private static uint? NullableUInt(JsonElement value,string name)=>Field(value,name).ValueKind==JsonValueKind.Null?null:
        Field(value,name).TryGetUInt32(out var number)?number:throw Invalid();
    private static InvalidDataException Invalid()=>new("Failed project terminal record not confirmed");
    private static void Unique(JsonElement value)
    {
        if(value.ValueKind==JsonValueKind.Object)
        {
            var names=new HashSet<string>(StringComparer.Ordinal);
            foreach(var property in value.EnumerateObject()){if(!names.Add(property.Name))throw Invalid();Unique(property.Value);}
        }
        else if(value.ValueKind==JsonValueKind.Array)foreach(var item in value.EnumerateArray())Unique(item);
    }
}
