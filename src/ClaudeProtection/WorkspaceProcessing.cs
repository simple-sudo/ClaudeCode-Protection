using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

namespace ClaudeProtection;

using ClaudeCodeProtection.Workspaces;

internal static class WorkspaceProcessing
{
    internal static async Task<object> Run(string inputPath,string resultPath)
    {
        WorkspaceFiles.RequireOrdinaryUser();
        var input=WorkspaceFiles.ReadBundle(inputPath);var bundle=WorkspaceBundle.Parse(input);
        if(bundle.BaseSHA256 is not null || bundle.Files.Length==0)throw new InvalidDataException("Nonempty baseline workspace required");
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
        start.Arguments="process-workspace-pipe "+Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture)+" "+nonce+" "+expected;
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
        using var doc=JsonDocument.Parse(response);var r=doc.RootElement;
        var fields=r.EnumerateObject().Select(p=>p.Name).ToArray();
        if(fields.Length!=6 || fields.Distinct(StringComparer.Ordinal).Count()!=6 ||
            !fields.OrderBy(n=>n,StringComparer.Ordinal).SequenceEqual(new[]{"BaseSHA256","ExitCode","ResultSHA256","SchemaVersion","SessionId","Status"}.OrderBy(n=>n,StringComparer.Ordinal)) ||
            r.GetProperty("SchemaVersion").GetInt32()!=1 || r.GetProperty("BaseSHA256").GetString()!=expected)
            throw new InvalidDataException("Workspace reply contract differs");
        var session=r.GetProperty("SessionId").GetString();var resultHash=r.GetProperty("ResultSHA256").GetString();
        if(r.GetProperty("ExitCode").GetInt32()!=0 || r.GetProperty("Status").GetString()!="WORKSPACE_DATA_PROCESSED_AND_CLEANED" ||
            session?.Length!=32 || session.Any(c=>c is not (>= '0' and <= '9' or >= 'a' and <= 'f')) || !WorkspaceBundle.IsHash(resultHash))
            throw new IOException("Workspace processing did not produce a closed successful result");
        var result=await WorkspacePipe.Read(server,WorkspaceBundle.MaxBundleBytes,completion.Token);
        WorkspacePipe.AssertPeer(server,broker.Id,true);
        if(WorkspaceBundle.Hash(result)!=resultHash)throw new InvalidDataException("Workspace result digest differs");
        var changes=WorkspaceBundle.Compare(input,result);
        await broker.WaitForExitAsync(completion.Token);
        if(broker.ExitCode!=0)throw new IOException("Workspace Broker did not complete successfully");
        output.Complete(result);
        return new {Status="WORKSPACE_DATA_RESULT_RECEIVED",SessionId=session,BaseSHA256=expected,ResultSHA256=resultHash,
            FileCount=WorkspaceBundle.Parse(result).Files.Length,Changes=changes,OriginalProjectModified=false,CodeExecuted=false,
            FormalAdmissionIssued=false,NetworkOpened=false,UACAutoConfirmed=false};
    }
}
