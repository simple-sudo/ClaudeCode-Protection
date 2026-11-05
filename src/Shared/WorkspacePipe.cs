using System.Buffers.Binary;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ClaudeCodeProtection.Workspaces;

// Read-only diagnostics, never admission or cleanup authority. Policy query
// failures retain null flags and an error; a zero flag is an observed value.
internal sealed record ToolCreationEvidence(uint? ChildProcessPolicy,int? ChildPolicyQueryError,
    uint? ImageLoadPolicy,int? ImagePolicyQueryError,int? ImageExecuteOpenError);

// Local IPC between the ordinary daily UI and its one explicitly elevated
// installed Broker. v3 is DATA only; v5 requires paired host-resource denials.
// Never a host-path, script, arbitrary process or command service.
internal static class WorkspacePipe
{
    // WindowsPrincipal.IsInRole queries primary-token membership by making
    // a temporary Identification token. Query alone makes that check fail.
    // This does not request Impersonate, AssignPrimary or Adjust privileges.
    internal const uint CallerTokenQueryAccess=0x0008|0x0002;
    internal sealed record Reply(int ExitCode,string? SessionId,string? ResultSHA256,string? FailureStage,string? FailureKind,int? FailureCode,
        ToolCreationEvidence? CreationEvidence,WorkspaceStopEvidence? StopEvidence,HostPrivacySummary? HostPrivacy=null,bool OwnerSealedBeforeCode=false,ProjectTaskFailure? ProjectFailure=null);
    internal const string ProjectScope="EXPLICIT_TEXTSUMMARY_SOURCE_EDIT_BUILD_RUN_TEST";
    internal const string CallerProjectScope="EXPLICIT_CALLER_CSHARP_LITERAL_EDITS_BUILD_RUN_TEST";
    internal static Reply ParseReply(byte[] bytes,string expected,bool developProject=false,bool callerProject=false)
    {
        if(bytes.Length is <1 or >16384 || !WorkspaceBundle.IsHash(expected) || callerProject && !developProject)throw new InvalidDataException("Workspace reply bounds refused");
        using var doc=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=4});var r=doc.RootElement;
        var fields=new[]{"BaseSHA256","CreationEvidence","ExitCode","FailureCode","FailureKind","FailureStage","ResultSHA256","SchemaVersion","SessionId","Status","StopEvidence"};
        var hasProjectFailure=r.TryGetProperty("ProjectFailure",out var failureValue);
        var expectedFields=callerProject?fields.Concat(new[]{"Scope","HostPrivacy","OwnerSealedBeforeCode"}).ToArray():developProject?fields.Concat(new[]{"Scope","HostPrivacy"}).ToArray():fields;
        RequireFields(r,callerProject && hasProjectFailure?expectedFields.Append("ProjectFailure").ToArray():expectedFields);
        if(r.GetProperty("SchemaVersion").GetInt32()!=(callerProject?6:developProject?5:3) || r.GetProperty("BaseSHA256").GetString()!=expected ||
            developProject && ((!callerProject && expected!=TextSummarySource.BaselineHash) || r.GetProperty("Scope").GetString()!=(callerProject?CallerProjectScope:ProjectScope)))
            throw new InvalidDataException("Workspace reply contract differs");
        var exit=r.GetProperty("ExitCode").GetInt32();var session=r.GetProperty("SessionId").GetString();
        var hash=r.GetProperty("ResultSHA256").GetString();var stage=r.GetProperty("FailureStage").GetString();var kind=r.GetProperty("FailureKind").GetString();
        int? code=r.GetProperty("FailureCode").ValueKind==JsonValueKind.Null?null:r.GetProperty("FailureCode").GetInt32();
        var creation=ParseCreationEvidence(r.GetProperty("CreationEvidence"));var stop=WorkspaceStopEvidence.Parse(r.GetProperty("StopEvidence"));
        if(session is not null && (session.Length!=32 || session.Any(c=>c is not (>= '0' and <= '9' or >= 'a' and <= 'f'))))
            throw new InvalidDataException("Workspace reply session differs");
        if(exit==0)
        {
            if(session is null || !WorkspaceBundle.IsHash(hash) || stage is not null || kind is not null || code is not null || creation is not null || stop is not null ||
                r.GetProperty("Status").GetString()!=(callerProject?"CALLER_CSHARP_PROJECT_BUILT_AND_CLEANED":developProject?"BUNDLED_PROJECT_DEVELOPED_AND_CLEANED":"WORKSPACE_DATA_PROCESSED_AND_CLEANED"))throw new InvalidDataException("Workspace success reply differs");
        }
        else if(exit is not (3 or 125) || hash is not null || stage is not ("installation" or "caller" or "input" or "processing" or "export") ||
            kind is null || kind.Length is <1 or >80 || kind.Any(c=>!char.IsAsciiLetterOrDigit(c)) || code is null ||
            r.GetProperty("Status").GetString()!=(callerProject?"CALLER_CSHARP_PROJECT_NOT_CONFIRMED":developProject?"BUNDLED_PROJECT_NOT_CONFIRMED":"WORKSPACE_DATA_NOT_CONFIRMED"))throw new InvalidDataException("Workspace failure reply differs");
        if((creation is not null || stop is not null) && (exit==0 || stage!="processing" || session is null))throw new InvalidDataException("Workspace diagnostic session differs");
        if(kind=="ProjectStopRequested" && (!callerProject || exit!=3 || stage!="processing" || session is null || creation is not null || hasProjectFailure))
            throw new InvalidDataException("Workspace project stop reply differs");
        if(creation is not null && (kind is not ("PowerShellCreateProcess" or "PowerShellImageExecuteOpen") ||
            kind=="PowerShellCreateProcess" && creation.ImageExecuteOpenError!=0 ||
            kind=="PowerShellImageExecuteOpen" && (creation.ImageExecuteOpenError==0 || creation.ImageExecuteOpenError!=code)))
            throw new InvalidDataException("Workspace creation diagnostic differs");
        HostPrivacySummary? privacy=null;
        if(developProject)
        {
            var value=r.GetProperty("HostPrivacy");
            if(value.ValueKind!=JsonValueKind.Null)
            {
                if(session is null || exit!=0 && stage!="processing")throw new InvalidDataException("Host privacy diagnostic session differs");
                privacy=HostPrivacyContract.Parse(value,session,exit==0);
            }
            else if(exit==0)throw new InvalidDataException("Successful project requires named host denials");
        }
        var sealedBeforeCode=callerProject && r.GetProperty("OwnerSealedBeforeCode").GetBoolean();
        if(callerProject && exit==0 && !sealedBeforeCode || sealedBeforeCode && (privacy is null || !HostPrivacyContract.Satisfied(privacy)))
            throw new InvalidDataException("Caller project requires original owner sealed observations");
        ProjectTaskFailure? projectFailure=null;
        if(hasProjectFailure)
        {
            if(!callerProject || exit==0 || stage!="processing" || kind!="ProjectTaskFailed" || session is null || !sealedBeforeCode || creation is not null || failureValue.ValueKind==JsonValueKind.Null)
                throw new InvalidDataException("Project failure cannot authorize success or replace owner evidence");
            projectFailure=ProjectFailureContract.Parse(failureValue);
        }
        if(ProjectWorkerFeedback.IsKind(kind) && (!callerProject || exit==0 || stage!="processing" || session is null ||
            !sealedBeforeCode || privacy is null || creation is not null || hasProjectFailure))
            throw new InvalidDataException("Project worker feedback requires original sealed caller-project failure");
        return new(exit,session,hash,stage,kind,code,creation,stop,privacy,sealedBeforeCode,projectFailure);
    }
    internal static ToolCreationEvidence? ParseCreationEvidence(JsonElement value)
    {
        if(value.ValueKind==JsonValueKind.Null)return null;
        RequireFields(value,"ChildProcessPolicy","ChildPolicyQueryError","ImageLoadPolicy","ImagePolicyQueryError","ImageExecuteOpenError");
        uint? Policy(string name){var item=value.GetProperty(name);if(item.ValueKind==JsonValueKind.Null)return null;
            if(item.ValueKind!=JsonValueKind.Number || !item.TryGetUInt32(out var flag))throw new InvalidDataException("Policy flags must be bounded numbers");return flag;}
        int? Error(string name){var item=value.GetProperty(name);if(item.ValueKind==JsonValueKind.Null)return null;
            if(item.ValueKind!=JsonValueKind.Number || !item.TryGetInt32(out var code) || code is <0 or >65535)throw new InvalidDataException("Policy errors must be bounded numbers");return code;}
        var child=Policy("ChildProcessPolicy");var childError=Error("ChildPolicyQueryError");
        var image=Policy("ImageLoadPolicy");var imageError=Error("ImagePolicyQueryError");var execute=Error("ImageExecuteOpenError");
        if((child is null)!=(childError is not null) || (image is null)!=(imageError is not null) || childError==0 || imageError==0 || execute is null)
            throw new InvalidDataException("Unobserved policy cannot become a zero flag");
        return new(child,childError,image,imageError,execute);
    }
    private static void RequireFields(JsonElement value,params string[] expected)
    {
        if(value.ValueKind!=JsonValueKind.Object)throw new InvalidDataException("Workspace object required");
        var fields=value.EnumerateObject().Select(p=>p.Name).ToArray();
        if(fields.Length!=expected.Length || fields.Distinct(StringComparer.Ordinal).Count()!=expected.Length ||
            !fields.OrderBy(n=>n,StringComparer.Ordinal).SequenceEqual(expected.OrderBy(n=>n,StringComparer.Ordinal)))throw new InvalidDataException("Workspace diagnostic fields differ");
    }
    internal static string Name(int ownerPid,string nonce)
    {
        if(ownerPid<=0 || nonce.Length!=32 || nonce.Any(c=>c is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
            throw new InvalidDataException("Workspace channel identity refused");
        return "CPC.WorkspaceData."+ownerPid.ToString(System.Globalization.CultureInfo.InvariantCulture)+"."+nonce;
    }
    internal static NamedPipeServerStream Create(int ownerPid,string nonce)
    {
        if(ownerPid!=Environment.ProcessId)throw new InvalidDataException("Workspace channel must belong to this process");
        using var user=WindowsIdentity.GetCurrent();var sid=user.User??throw new InvalidOperationException("Human user required");
        WorkspaceFiles.RequireOrdinaryToken(user.AccessToken);
        var security=new PipeSecurity();security.SetOwner(sid);security.SetAccessRuleProtection(true,false);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid,null),PipeAccessRights.FullControl,AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(sid,PipeAccessRights.FullControl,AccessControlType.Allow));
        // Explicit same-user ACL permits the user's elevated token as well.
        // CurrentUserOnly would additionally impose elevation-specific checks.
        // No APP_PACKAGES/Everyone/Users grants; no remote or inherited access.
        return NamedPipeServerStreamAcl.Create(Name(ownerPid,nonce),PipeDirection.InOut,1,PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous|PipeOptions.FirstPipeInstance,65536,65536,security,HandleInheritability.None);
    }
    internal static void AssertPeer(PipeStream pipe,int expectedPid,bool server)
    {
        if(expectedPid<=0 || !pipe.IsConnected)throw new InvalidDataException("Connected workspace peer required");
        uint actual;
        var okay=server?GetNamedPipeClientProcessId(pipe.SafePipeHandle,out actual):GetNamedPipeServerProcessId(pipe.SafePipeHandle,out actual);
        if(!okay)throw new Win32Exception(Marshal.GetLastWin32Error(),"Read workspace peer identity");
        if(actual!=(uint)expectedPid)throw new InvalidDataException("Workspace peer process differs");
    }
    internal static async Task Write(Stream pipe,byte[] bytes,int maximum,CancellationToken cancel)
    {
        DemandLength(bytes.Length,maximum);
        var header=new byte[4];BinaryPrimitives.WriteInt32LittleEndian(header,bytes.Length);
        await pipe.WriteAsync(header,cancel);await pipe.WriteAsync(bytes,cancel);await pipe.FlushAsync(cancel);
    }
    internal static async Task<byte[]> Read(Stream pipe,int maximum,CancellationToken cancel)
    {
        var header=new byte[4];await pipe.ReadExactlyAsync(header,cancel);
        var length=BinaryPrimitives.ReadInt32LittleEndian(header);DemandLength(length,maximum);
        var bytes=new byte[length];await pipe.ReadExactlyAsync(bytes,cancel);return bytes;
    }
    private static void DemandLength(int length,int maximum)
    {
        if(maximum is <1 or >WorkspaceBundle.MaxBundleBytes || length<1 || length>maximum)
            throw new InvalidDataException("Workspace channel frame size refused");
    }
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe,out uint pid);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint pid);
}
