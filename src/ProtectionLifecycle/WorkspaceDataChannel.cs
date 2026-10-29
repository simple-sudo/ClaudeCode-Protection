using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

public static partial class InstalledBroker
{
    public static int ProcessWorkspacePipe(int callerPid,string nonce,string expectedSHA256)
    {
        ProtectedState.RequireAdministrator();var expected=Identifiers.Hash(expectedSHA256);
        using var channel=new NamedPipeClientStream(".",WorkspacePipe.Name(callerPid,nonce),PipeDirection.InOut,
            PipeOptions.Asynchronous,TokenImpersonationLevel.Identification);
        channel.Connect(15000);WorkspacePipe.AssertPeer(channel,callerPid,false);
        string? session=null,resultHash=null;byte[]? output=null;var exit=125;
        try
        {
            var processed=WithCurrentInstallation((layout,state,version)=>
            {
                // The current installation and all payload files are held by
                // the same original owner before receiving any project bytes.
                using var caller=OpenWorkspaceCaller(callerPid,layout.Version(version.Package.Release));
                WorkspacePipe.AssertPeer(channel,callerPid,false);
                using var transfer=new CancellationTokenSource(TimeSpan.FromSeconds(15));
                var input=WorkspacePipe.Read(channel,WorkspaceBundle.MaxBundleBytes,transfer.Token).GetAwaiter().GetResult();
                return ProcessWorkspaceBytes(layout,state,version,expected,input);
            });
            exit=processed.ExitCode;
            using var report=JsonDocument.Parse(processed.Report);var r=report.RootElement;
            session=Identifiers.Hex32(StrictJson.Text(r,"SessionId"));
            if(exit==0)
            {
                if(StrictJson.Text(r,"Status")!="WORKSPACE_DATA_PROCESSED_AND_CLEANED" ||
                    StrictJson.Text(r,"WorkspaceBaselineSHA256")!=expected)throw new InvalidDataException("Workspace terminal binding differs");
                resultHash=Identifiers.Hash(StrictJson.Text(r,"ClosedWorkspaceResultSHA256"));
                // Reuse the existing authoritative success/cleanup receipt
                // checks. Never expose a partial/private payload on failure.
                output=ExportWorkspaceData(session,resultHash);
            }
        }
        catch {exit=125;output=null;resultHash=null;}
        using var completion=new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var response=JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,ExitCode=exit,SessionId=session,BaseSHA256=expected,
            ResultSHA256=resultHash,Status=exit==0?"WORKSPACE_DATA_PROCESSED_AND_CLEANED":"WORKSPACE_DATA_NOT_CONFIRMED"});
        WorkspacePipe.AssertPeer(channel,callerPid,false);
        WorkspacePipe.Write(channel,response,16384,completion.Token).GetAwaiter().GetResult();
        if(exit==0)WorkspacePipe.Write(channel,output??throw new InvalidDataException("Closed output missing"),WorkspaceBundle.MaxBundleBytes,completion.Token).GetAwaiter().GetResult();
        return exit;
    }
    private static SafeProcessHandle OpenWorkspaceCaller(int pid,string versionRoot)
    {
        if(pid<=0 || pid==Environment.ProcessId)throw new InvalidDataException("Ordinary daily caller required");
        var process=OpenProcess(0x1000,false,(uint)pid); // QUERY_LIMITED_INFORMATION only
        if(process.IsInvalid){process.Dispose();throw new Win32Exception(Marshal.GetLastWin32Error(),"Open workspace caller");}
        try
        {
            var path=new StringBuilder(32768);var length=path.Capacity;
            if(!QueryFullProcessImageName(process,0,path,ref length))throw new Win32Exception(Marshal.GetLastWin32Error(),"Read daily caller image");
            if(!string.Equals(path.ToString(),WindowsPathSeal.Child(versionRoot,"bin/current/ClaudeProtection.exe"),StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Only the current installed daily caller can supply workspace data");
            if(!OpenProcessToken(process,8,out var token))throw new Win32Exception(Marshal.GetLastWin32Error(),"Read daily caller token");
            using(token)
            using(var identity=new WindowsIdentity(token.DangerousGetHandle()))
            using(var current=WindowsIdentity.GetCurrent())
            {
                if(identity.User is null || identity.User!=current.User || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                    throw new InvalidDataException("Ordinary caller must be the same human user as the elevated Broker");
            }
            return process;
        }
        catch{process.Dispose();throw;}
    }
    [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint pid);
    [DllImport("kernel32.dll",EntryPoint="QueryFullProcessImageNameW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder path,ref int size);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle process,uint access,out SafeAccessTokenHandle token);
}
