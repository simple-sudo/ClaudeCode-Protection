using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using ClaudeCodeProtection.Workspaces;

namespace ClaudeProtection;

internal static class HostGpuReferenceProcessing
{
    internal static async Task<(int ExitCode,object Report)> Run()
    {
        WorkspaceFiles.RequireOrdinaryUser();
        var entry=Assembly.GetEntryAssembly()?.Location??throw new InvalidOperationException("Installed daily entry required");
        var folder=Path.GetDirectoryName(entry)!;var root=Path.GetFullPath(Path.Combine(folder,"..",".."));var release=Path.GetFileName(root);
        if(release.Length!=32 || release.Any(c=>c is not (>= '0' and <= '9' or >= 'a' and <= 'f')) ||
            !string.Equals(Environment.ProcessPath,Path.Combine(folder,"ClaudeProtection.exe"),StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(root,Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ClaudeCodeProtection","versions",release),StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Current installed daily host required");
        using var installed=new WorkspaceInstalledHost(root);
        var nonce=Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        using var server=WorkspacePipe.CreateHostGpu(Environment.ProcessId,nonce);
        var start=new ProcessStartInfo(Path.Combine(root,"bin","admin","ProtectionBroker.exe")){
            UseShellExecute=true,Verb="runas",WorkingDirectory=Path.Combine(root,"bin","admin"),WindowStyle=ProcessWindowStyle.Hidden,
            Arguments="qualify-host-gpu-reference-pipe "+Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture)+" "+nonce};
        using var broker=Process.Start(start)??throw new IOException("Fixed host GPU owner did not start");_=broker.SafeHandle;
        try
        {
            using var connect=new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await server.WaitForConnectionAsync(connect.Token);WorkspacePipe.AssertPeer(server,broker.Id,true);
            using var receive=new CancellationTokenSource(TimeSpan.FromSeconds(50));
            var bytes=await WorkspacePipe.Read(server,4096,receive.Token);WorkspacePipe.AssertPeer(server,broker.Id,true);
            var reply=HostGpuReferenceReply.Parse(bytes,nonce);
            await broker.WaitForExitAsync(receive.Token);if(broker.ExitCode!=reply.ExitCode)throw new IOException("GPU owner exit differs from bound reply");
            // Only the fixed support summary reaches stdout. Raw current Token,
            // GPU identity and original Job receipts stay in protected state.
            return(reply.ExitCode,new{reply.Status,reply.RequestId,reply.ChildPid,reply.Complete,reply.OriginalJobClosed,reply.FailureCodes,
                OriginalOwnerTerminal=true,ProtectedGpuVerified=false,PrivacyVerified=false,FormalAdmissionIssued=false,ClaudeLaunched=false,AutomaticRetry=false});
        }
        catch
        {
            // Observation expiry, malformed reply or peer loss is never a
            // cleanup claim. Retain the original returned owner handle and
            // await it; do not kill, restart or adopt a replacement PID.
            await broker.WaitForExitAsync(CancellationToken.None);throw;
        }
    }
}
