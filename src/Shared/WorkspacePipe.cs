using System.Buffers.Binary;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ClaudeCodeProtection.Workspaces;

// Local data IPC between the ordinary daily UI and its one explicitly elevated
// installed Broker. Never a host-path, script, process or command service.
internal static class WorkspacePipe
{
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
