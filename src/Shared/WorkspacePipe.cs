using System.Buffers.Binary;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ClaudeCodeProtection.Workspaces;

// Local data IPC between the ordinary daily UI and its one explicitly elevated
// installed Broker. Never a host-path, script, process or command service.
internal static class WorkspacePipe
{
    // WindowsPrincipal.IsInRole queries primary-token membership by making
    // a temporary Identification token. Query alone makes that check fail.
    // This does not request Impersonate, AssignPrimary or Adjust privileges.
    internal const uint CallerTokenQueryAccess=0x0008|0x0002;
    internal sealed record Reply(int ExitCode,string? SessionId,string? ResultSHA256,string? FailureStage,string? FailureKind,int? FailureCode);
    internal static Reply ParseReply(byte[] bytes,string expected)
    {
        if(bytes.Length is <1 or >16384 || !WorkspaceBundle.IsHash(expected))throw new InvalidDataException("Workspace reply bounds refused");
        using var doc=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=4});var r=doc.RootElement;
        var fields=r.EnumerateObject().Select(p=>p.Name).ToArray();
        var required=new[]{"BaseSHA256","ExitCode","FailureCode","FailureKind","FailureStage","ResultSHA256","SchemaVersion","SessionId","Status"};
        if(fields.Length!=required.Length || fields.Distinct(StringComparer.Ordinal).Count()!=required.Length ||
            !fields.OrderBy(n=>n,StringComparer.Ordinal).SequenceEqual(required.OrderBy(n=>n,StringComparer.Ordinal)) ||
            r.GetProperty("SchemaVersion").GetInt32()!=2 || r.GetProperty("BaseSHA256").GetString()!=expected)
            throw new InvalidDataException("Workspace reply contract differs");
        var exit=r.GetProperty("ExitCode").GetInt32();var session=r.GetProperty("SessionId").GetString();
        var hash=r.GetProperty("ResultSHA256").GetString();var stage=r.GetProperty("FailureStage").GetString();var kind=r.GetProperty("FailureKind").GetString();
        int? code=r.GetProperty("FailureCode").ValueKind==JsonValueKind.Null?null:r.GetProperty("FailureCode").GetInt32();
        if(session is not null && (session.Length!=32 || session.Any(c=>c is not (>= '0' and <= '9' or >= 'a' and <= 'f'))))
            throw new InvalidDataException("Workspace reply session differs");
        if(exit==0)
        {
            if(session is null || !WorkspaceBundle.IsHash(hash) || stage is not null || kind is not null || code is not null ||
                r.GetProperty("Status").GetString()!="WORKSPACE_DATA_PROCESSED_AND_CLEANED")throw new InvalidDataException("Workspace success reply differs");
        }
        else if(exit is not (3 or 125) || hash is not null || stage is not ("installation" or "caller" or "input" or "processing" or "export") ||
            kind is null || kind.Length is <1 or >80 || kind.Any(c=>!char.IsAsciiLetterOrDigit(c)) || code is null ||
            r.GetProperty("Status").GetString()!="WORKSPACE_DATA_NOT_CONFIRMED")throw new InvalidDataException("Workspace failure reply differs");
        return new(exit,session,hash,stage,kind,code);
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
