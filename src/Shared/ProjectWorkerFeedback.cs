using System.Text.Json;

namespace ClaudeCodeProtection.Workspaces;

// Fixed original-owner failure vocabulary. No private messages, paths,
// stdout/stderr, serialized authority or successful result can cross here.
internal static class ProjectWorkerFeedback
{
    internal sealed record Failure(string Kind,int Code);
    internal static bool IsKind(string? kind)=>kind is "ProjectCompilerWaitTimeout" or "ProjectCompilerDrainTimeout" or
        "ProjectCompilerExited" or "ProjectCompilerOutputUnexpected" or "ProjectCompilerStartFailed" or "ProjectCompilerWaitFailed";

    internal static Failure? FromOwnerChild(JsonElement child,string session,int rootPid)
    {
        if(session.Length!=32 || session.Any(c=>!char.IsAsciiHexDigitLower(c)) || rootPid<=0 || child.ValueKind!=JsonValueKind.Object)return null;
        var names=child.EnumerateObject().Select(p=>p.Name).ToArray();
        if(names.Distinct(StringComparer.Ordinal).Count()!=names.Length)return null;
        bool Number(string key,out int value){value=0;return child.TryGetProperty(key,out var field) && field.ValueKind==JsonValueKind.Number && field.TryGetInt32(out value);}
        string? Text(string key)=>child.TryGetProperty(key,out var field) && field.ValueKind==JsonValueKind.String?field.GetString():null;
        if(!Number("SchemaVersion",out var schema) || schema!=1 || !Number("Pid",out var pid) || pid!=rootPid || Text("Nonce")!=session ||
            !Number("FailureCode",out var code) || child.TryGetProperty("ProjectFailure",out var project) && project.ValueKind!=JsonValueKind.Null)return null;
        var stage=Text("FailureStage");var type=Text("FailureType");
        if(stage=="WAIT_PROJECT_COMPILER" && type=="TimeoutException")
            return Number("ToolExit",out var exited)?new("ProjectCompilerDrainTimeout",exited):new("ProjectCompilerWaitTimeout",code);
        if(stage=="WAIT_PROJECT_COMPILER/ProjectDevelopmentNotConfirmed" && type=="InvalidDataException" && Number("ToolExit",out var exit))
            return new(exit==0?"ProjectCompilerOutputUnexpected":"ProjectCompilerExited",exit);
        if(stage=="WAIT_PROJECT_COMPILER" && type is "IOException" or "OperationCanceledException" or "InvalidDataException")
            return new("ProjectCompilerWaitFailed",code);
        if(stage is "START_PROJECT_COMPILER/CREATE_REDIRECT_PIPE" or "START_PROJECT_COMPILER/DUPLICATE_REDIRECT_HANDLE" or
            "START_PROJECT_COMPILER/CREATE_PROCESS" or "START_PROJECT_COMPILER/CREATE_PROCESS/InheritedToolCreateProcess" or
            "START_PROJECT_COMPILER/CREATE_REDIRECT_PIPE/InheritedToolInputPipe" or "START_PROJECT_COMPILER/CREATE_REDIRECT_PIPE/InheritedToolOutputPipe" or
            "START_PROJECT_COMPILER/CREATE_REDIRECT_PIPE/InheritedToolErrorPipe" or "START_PROJECT_COMPILER/DUPLICATE_REDIRECT_HANDLE/InheritedToolParentHandleSeal" or
            "START_PROJECT_COMPILER/START_UNCLASSIFIED/InheritedToolAttributes" or "START_PROJECT_COMPILER/START_UNCLASSIFIED/InheritedToolPackage" or
            "START_PROJECT_COMPILER/START_UNCLASSIFIED/InheritedToolLpac" or "START_PROJECT_COMPILER/START_UNCLASSIFIED/InheritedToolHandleList" or
            "START_PROJECT_COMPILER/START_UNCLASSIFIED/InheritedToolResume" or "START_PROJECT_COMPILER/START_UNCLASSIFIED/InheritedToolImageExecuteOpen")
            return new("ProjectCompilerStartFailed",code);
        return null;
    }
}
