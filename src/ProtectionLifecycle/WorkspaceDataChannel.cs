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
        =>ExchangeWorkspacePipe(callerPid,nonce,expectedSHA256,false);
    public static int DevelopBundledProjectPipe(int callerPid,string nonce,string expectedSHA256)
        =>ExchangeWorkspacePipe(callerPid,nonce,expectedSHA256,true);
    public static int BuildCallerCSharpProjectPipe(int callerPid,string nonce,string expectedSHA256)
        =>ExchangeWorkspacePipe(callerPid,nonce,expectedSHA256,true,true);
    private static int ExchangeWorkspacePipe(int callerPid,string nonce,string expectedSHA256,bool developProject,bool callerProject=false)
    {
        ProtectedState.RequireAdministrator();var expected=Identifiers.Hash(expectedSHA256);
        if(developProject && !callerProject && expected!=TextSummarySource.BaselineHash)throw new InvalidDataException("Bundled project baseline required");
        using var channel=new NamedPipeClientStream(".",WorkspacePipe.Name(callerPid,nonce),PipeDirection.InOut,
            PipeOptions.Asynchronous,TokenImpersonationLevel.Identification);
        channel.Connect(15000);WorkspacePipe.AssertPeer(channel,callerPid,false);
        string? session=null,resultHash=null,failureStage=null,failureKind=null;int? failureCode=null;
        ToolCreationEvidence? creationEvidence=null;WorkspaceStopEvidence? stopEvidence=null;
        HostPrivacySummary? hostPrivacy=null;var ownerSealedBeforeCode=false;
        byte[]? output=null;var exit=125;var stage="installation";
        try
        {
            var processed=WithCurrentInstallation((layout,state,version)=>
            {
                // The current installation and all payload files are held by
                // the same original owner before receiving any project bytes.
                stage="caller";using var caller=OpenWorkspaceCaller(callerPid,layout.Version(version.Package.Release));
                WorkspacePipe.AssertPeer(channel,callerPid,false);
                stage="input";
                using var transfer=new CancellationTokenSource(TimeSpan.FromSeconds(15));
                var input=WorkspacePipe.Read(channel,WorkspaceBundle.MaxBundleBytes,transfer.Token).GetAwaiter().GetResult();
                stage="processing";
                if(!developProject)return ProcessWorkspaceBytes(layout,state,version,expected,input);
                if(callerProject)
                {
                    if(WorkspaceBundle.Hash(input)!=expected)throw new InvalidDataException("Caller project byte binding differs");
                    _=CSharpProjectTask.Parse(input);return ProtectedSession.BuildCallerProject(layout,state,version,input);
                }
                TextSummarySource.RequireBaseline(input);
                return ProtectedSession.DevelopBundledProject(layout,state,version);
            });
            exit=processed.ExitCode;
            using var report=JsonDocument.Parse(processed.Report);var r=report.RootElement;
            session=Identifiers.Hex32(StrictJson.Text(r,"SessionId"));
            if(developProject && r.TryGetProperty("HostPrivacy",out var privacy) && privacy.ValueKind!=JsonValueKind.Null)
                hostPrivacy=HostPrivacyContract.Parse(privacy,session,exit==0);
            ownerSealedBeforeCode=callerProject && r.TryGetProperty("ProjectExecutionPermitConsumedAfterOwnerSealedPrivacy",out var sealedValue) && sealedValue.GetBoolean() && hostPrivacy is not null && HostPrivacyContract.Satisfied(hostPrivacy);
            if(exit==0)
            {
                if(developProject && hostPrivacy is null)throw new InvalidDataException("Named host privacy evidence required");
                if(StrictJson.Text(r,"Status")!=(callerProject?"CALLER_CSHARP_PROJECT_BUILT_AND_CLEANED":developProject?"BUNDLED_PROJECT_DEVELOPED_AND_CLEANED":"WORKSPACE_DATA_PROCESSED_AND_CLEANED") ||
                    StrictJson.Text(r,"WorkspaceBaselineSHA256")!=expected ||
                    developProject && StrictJson.Text(r,"Scope")!=(callerProject?WorkspacePipe.CallerProjectScope:WorkspacePipe.ProjectScope) ||
                    callerProject && !ownerSealedBeforeCode)throw new InvalidDataException("Workspace terminal binding differs");
                resultHash=Identifiers.Hash(StrictJson.Text(r,"ClosedWorkspaceResultSHA256"));
                // Reuse the existing authoritative success/cleanup receipt
                // checks. Never expose a partial/private payload on failure.
                stage="export";output=callerProject?ExportCallerCSharpProject(session,resultHash):developProject?ExportDevelopedProject(session,resultHash):ExportWorkspaceData(session,resultHash);
            }
            else
            {
                failureStage="processing";failureKind="ResourceSessionFailed";failureCode=exit;
                if(r.TryGetProperty("Stop",out var stop) && stop.ValueKind==JsonValueKind.Object)
                {
                    var observed=JsonSerializer.Deserialize<RuntimeStop>(stop.GetRawText())??throw new InvalidDataException("Stop observation missing");
                    if(observed.SessionId!=session || observed.Reason!="OFFLINE_RESOURCE_QUALIFICATION_TERMINAL" || observed.Failures is null || observed.Failures.Length>1024)
                        throw new InvalidDataException("Stop observation binding differs");
                    stopEvidence=new(observed.AdmissionClosed,observed.QuarantineObservedBeforeStop,
                        observed.FinalJob is null?null:observed.FinalJob.ExpectedLimits && observed.FinalJob.ObservedZero,observed.Failures.Length);
                }
                // Return only bounded bootstrap metadata already validated by
                // the session owner. No second elevated receipt read should
                // be needed just to locate an early worker startup failure.
                if(r.TryGetProperty("ChildBootstrapFailure",out var bootstrap) && bootstrap.ValueKind==JsonValueKind.Object)
                {
                    var type=StrictJson.Text(bootstrap,"Type");var phase=StrictJson.Text(bootstrap,"Phase");
                    if(type.Length is >=1 and <=60 && type.All(char.IsAsciiLetterOrDigit) && phase is "self-token" or "resource-input")
                    {failureKind=(phase=="self-token"?"SelfToken":"ResourceInput")+type;failureCode=bootstrap.GetProperty("Code").GetInt32();}
                }
                else if(r.TryGetProperty("Child",out var child) && child.ValueKind==JsonValueKind.Object &&
                    child.TryGetProperty("FailureStage",out var childStage) && childStage.ValueKind==JsonValueKind.String)
                {
                    failureKind=childStage.GetString() switch {
                        "START_FIXED_POWERSHELL/CREATE_REDIRECT_PIPE"=>"PowerShellRedirectPipe",
                        "START_FIXED_POWERSHELL/DUPLICATE_REDIRECT_HANDLE"=>"PowerShellRedirectHandle",
                        "START_FIXED_POWERSHELL/CREATE_PROCESS" or "START_FIXED_POWERSHELL/CREATE_PROCESS/InheritedToolCreateProcess"=>"PowerShellCreateProcess",
                        "START_FIXED_POWERSHELL/CREATE_REDIRECT_PIPE/InheritedToolInputPipe" or "START_FIXED_POWERSHELL/CREATE_REDIRECT_PIPE/InheritedToolOutputPipe" or "START_FIXED_POWERSHELL/CREATE_REDIRECT_PIPE/InheritedToolErrorPipe"=>"PowerShellRedirectPipe",
                        "START_FIXED_POWERSHELL/DUPLICATE_REDIRECT_HANDLE/InheritedToolParentHandleSeal"=>"PowerShellRedirectHandle",
                        "START_FIXED_POWERSHELL/START_UNCLASSIFIED/InheritedToolAttributes"=>"PowerShellAttributes",
                        "START_FIXED_POWERSHELL/START_UNCLASSIFIED/InheritedToolPackage"=>"PowerShellPackage",
                        "START_FIXED_POWERSHELL/START_UNCLASSIFIED/InheritedToolLpac"=>"PowerShellLpacPolicy",
                        "START_FIXED_POWERSHELL/START_UNCLASSIFIED/InheritedToolHandleList"=>"PowerShellHandleList",
                        "START_FIXED_POWERSHELL/START_UNCLASSIFIED/InheritedToolResume"=>"PowerShellResume",
                        "START_FIXED_POWERSHELL/START_UNCLASSIFIED/InheritedToolImageExecuteOpen"=>"PowerShellImageExecuteOpen",
                        "START_FIXED_POWERSHELL/START_UNCLASSIFIED" or "START_FIXED_POWERSHELL"=>"PowerShellStart",
                        _=>"ResourceSessionFailed"};
                    if(failureKind!="ResourceSessionFailed" && child.TryGetProperty("FailureCode",out var code) && code.ValueKind==JsonValueKind.Number)
                        failureCode=code.GetInt32();
                    if(failureKind is "PowerShellCreateProcess" or "PowerShellImageExecuteOpen" && child.TryGetProperty("CreationEvidence",out var creation))
                        creationEvidence=WorkspacePipe.ParseCreationEvidence(creation);
                }
            }
        }
        catch(Exception ex){exit=125;output=null;resultHash=null;creationEvidence=null;stopEvidence=null;hostPrivacy=null;ownerSealedBeforeCode=false;failureStage=stage;failureKind=ex.GetType().Name;failureCode=ex is Win32Exception native?native.NativeErrorCode:ex.HResult;}
        using var completion=new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var response=JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=3,ExitCode=exit,SessionId=session,BaseSHA256=expected,
            ResultSHA256=resultHash,Status=exit==0?"WORKSPACE_DATA_PROCESSED_AND_CLEANED":"WORKSPACE_DATA_NOT_CONFIRMED",
            FailureStage=failureStage,FailureKind=failureKind,FailureCode=failureCode,CreationEvidence=creationEvidence,StopEvidence=stopEvidence});
        if(developProject)response=JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=5,Scope=WorkspacePipe.ProjectScope,HostPrivacy=hostPrivacy,ExitCode=exit,SessionId=session,BaseSHA256=expected,
            ResultSHA256=resultHash,Status=exit==0?"BUNDLED_PROJECT_DEVELOPED_AND_CLEANED":"BUNDLED_PROJECT_NOT_CONFIRMED",
            FailureStage=failureStage,FailureKind=failureKind,FailureCode=failureCode,CreationEvidence=creationEvidence,StopEvidence=stopEvidence});
        if(callerProject)response=JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=6,Scope=WorkspacePipe.CallerProjectScope,HostPrivacy=hostPrivacy,OwnerSealedBeforeCode=ownerSealedBeforeCode,ExitCode=exit,SessionId=session,BaseSHA256=expected,
            ResultSHA256=resultHash,Status=exit==0?"CALLER_CSHARP_PROJECT_BUILT_AND_CLEANED":"CALLER_CSHARP_PROJECT_NOT_CONFIRMED",
            FailureStage=failureStage,FailureKind=failureKind,FailureCode=failureCode,CreationEvidence=creationEvidence,StopEvidence=stopEvidence});
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
            if(!OpenProcessToken(process,WorkspacePipe.CallerTokenQueryAccess,out var token))throw new Win32Exception(Marshal.GetLastWin32Error(),"Read daily caller token");
            using(token)
            using(var identity=new WindowsIdentity(token.DangerousGetHandle()))
            using(var current=WindowsIdentity.GetCurrent())
            {
                WorkspaceFiles.RequireOrdinaryToken(token);
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
