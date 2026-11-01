using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;

namespace ClaudeProtection;

using ClaudeCodeProtection.Workspaces;

internal static class WorkspaceProcessing
{
    internal static async Task<(int ExitCode,object Report)> Run(string inputPath,string resultPath)
        =>await Exchange(inputPath,resultPath,false);
    internal static async Task<(int ExitCode,object Report)> Develop(string inputPath,string resultPath)
        =>await Exchange(inputPath,resultPath,true);
    internal static async Task<(int ExitCode,object Report)> BuildCaller(string inputPath,string resultPath)
        =>await Exchange(inputPath,resultPath,true,true);
    private static async Task<(int ExitCode,object Report)> Exchange(string inputPath,string resultPath,bool developProject,bool callerProject=false)
    {
        WorkspaceFiles.RequireOrdinaryUser();
        var input=WorkspaceFiles.ReadBundle(inputPath);var bundle=WorkspaceBundle.Parse(input);
        if(bundle.BaseSHA256 is not null || bundle.Files.Length==0)throw new InvalidDataException("Nonempty baseline workspace required");
        if(callerProject)_=CSharpProjectTask.Parse(input);
        else if(developProject)TextSummarySource.RequireBaseline(input);
        var expected=WorkspaceBundle.Hash(input);
        // Only the installed sibling Broker, never a caller-supplied path or
        // dotnet command. An old installed daily binary is rejected by the
        // Broker's current-version checks; there is no development fallback.
        var daily=Assembly.GetEntryAssembly()?.Location??throw new InvalidOperationException("Installed daily entry required");
        var folder=Path.GetDirectoryName(daily)!;
        if(!string.Equals(Environment.ProcessPath,Path.Combine(folder,"ClaudeProtection.exe"),StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Installed daily application host required");
        var root=Path.GetFullPath(Path.Combine(folder,"..",".."));
        var release=Path.GetFileName(root);
        if(release.Length!=32 || release.Any(c=>c is not (>= '0' and <= '9' or >= 'a' and <= 'f')) ||
            !string.Equals(root,Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ClaudeCodeProtection","versions",release),StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Installed release location required");
        using var installed=new WorkspaceInstalledHost(root);
        using var output=WorkspaceFiles.ReserveBundleNew(resultPath);
        var nonce=Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        using var server=WorkspacePipe.Create(Environment.ProcessId,nonce);
        var start=new ProcessStartInfo(Path.Combine(root,"bin","admin","ProtectionBroker.exe")) {
            UseShellExecute=true,Verb="runas",WorkingDirectory=Path.Combine(root,"bin","admin"),WindowStyle=ProcessWindowStyle.Hidden
        };
        // Every argument is a validated decimal/hex value. No shell or host
        // source/output path crosses elevation. UAC is always human-controlled.
        start.Arguments=(callerProject?"build-caller-csharp-project-pipe ":developProject?"develop-bundled-project-pipe ":"process-workspace-pipe ")+Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture)+" "+nonce+" "+expected;
        using var broker=Process.Start(start)??throw new IOException("Installed Broker did not start");
        // Hold the returned process handle through the exchange, preventing
        // PID-reuse acceptance. Never terminate an elevated session on UI loss.
        _=broker.SafeHandle;
        using var connection=new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await server.WaitForConnectionAsync(connection.Token);
        WorkspacePipe.AssertPeer(server,broker.Id,true);
        using(var transfer=new CancellationTokenSource(TimeSpan.FromSeconds(15)))
            await WorkspacePipe.Write(server,input,WorkspaceBundle.MaxBundleBytes,transfer.Token);
        using var completion=new CancellationTokenSource(TimeSpan.FromSeconds(75));
        var response=await WorkspacePipe.Read(server,16384,completion.Token);
        var reply=WorkspacePipe.ParseReply(response,expected,developProject,callerProject);var session=reply.SessionId;var resultHash=reply.ResultSHA256;
        if(reply.ExitCode!=0)
        {
            await broker.WaitForExitAsync(completion.Token);
            if(broker.ExitCode!=reply.ExitCode)throw new IOException("Workspace failure process exit differs");
            if(developProject)return(reply.ExitCode,new {Status=callerProject?"CALLER_CSHARP_PROJECT_NOT_CONFIRMED":"BUNDLED_PROJECT_NOT_CONFIRMED",SessionId=session,BaseSHA256=expected,
                reply.FailureStage,reply.FailureKind,reply.FailureCode,reply.CreationEvidence,reply.StopEvidence,reply.HostPrivacy,ResultReleased=false,AutomaticRetry=false});
            return(reply.ExitCode,new {Status=developProject?"BUNDLED_PROJECT_NOT_CONFIRMED":"WORKSPACE_DATA_NOT_CONFIRMED",SessionId=session,BaseSHA256=expected,
                reply.FailureStage,reply.FailureKind,reply.FailureCode,reply.CreationEvidence,reply.StopEvidence,ResultReleased=false,AutomaticRetry=false});
        }
        var result=await WorkspacePipe.Read(server,WorkspaceBundle.MaxBundleBytes,completion.Token);
        WorkspacePipe.AssertPeer(server,broker.Id,true);
        if(WorkspaceBundle.Hash(result)!=resultHash)throw new InvalidDataException("Workspace result digest differs");
        var changes=WorkspaceBundle.Compare(input,result);
        if(callerProject)CSharpProjectTask.Parse(input).VerifyResult(result);
        await broker.WaitForExitAsync(completion.Token);
        if(broker.ExitCode!=0)throw new IOException("Workspace Broker did not complete successfully");
        output.Complete(result);
        if(callerProject)return(0,new {Status="CALLER_CSHARP_PROJECT_RESULT_RECEIVED",SessionId=session,BaseSHA256=expected,ResultSHA256=resultHash,
            FileCount=WorkspaceBundle.Parse(result).Files.Length,Changes=changes,OriginalProjectModified=false,ProjectCodeExecuted=true,
            reply.HostPrivacy,reply.OwnerSealedBeforeCode,FormalAdmissionIssued=false,NetworkOpened=false,UACAutoConfirmed=false});
        if(developProject)return(0,new {Status="BUNDLED_PROJECT_RESULT_RECEIVED",SessionId=session,BaseSHA256=expected,ResultSHA256=resultHash,
            FileCount=WorkspaceBundle.Parse(result).Files.Length,Changes=changes,OriginalProjectModified=false,ProjectCodeExecuted=true,
            reply.HostPrivacy,FormalAdmissionIssued=false,NetworkOpened=false,UACAutoConfirmed=false});
        return (0,new {Status=developProject?"BUNDLED_PROJECT_RESULT_RECEIVED":"WORKSPACE_DATA_RESULT_RECEIVED",SessionId=session,BaseSHA256=expected,ResultSHA256=resultHash,
            FileCount=WorkspaceBundle.Parse(result).Files.Length,Changes=changes,OriginalProjectModified=false,ProjectCodeExecuted=developProject,
            FormalAdmissionIssued=false,NetworkOpened=false,UACAutoConfirmed=false});
    }
}
