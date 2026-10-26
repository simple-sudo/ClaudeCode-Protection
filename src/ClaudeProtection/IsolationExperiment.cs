using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ClaudeProtection;

// Deliberately experimental. Nothing here grants the production Gate a PASS.
// Commands that create profiles/ACLs are reserved for a separately approved probe.
internal static class IsolationExperiment
{
    internal static string Name(string run) => Regex.IsMatch(run, "^[a-f0-9]{32}$") ? "ClaudeProtectionProbe." + run : throw new ArgumentException("Expected a probe run identifier");
    internal static string DirectoryFor(string run) { _ = Name(run); return Path.Combine(Files.Root, "state", "isolation-probe", run); }
    internal sealed record Manifest(string Run, string Profile, string Sid, string Directory, Dictionary<string, string> Hashes);
    internal static object Plan() => new
    {
        status = "PLAN_ONLY_NOT_AUTHORIZED",
        purpose = "Evaluate inherited AppContainer network restrictions on disposable probe parent/child processes; no real Claude credentials",
        changes = new[] { "Create one uniquely named temporary AppContainer profile", "Grant that profile read/execute ONLY on a fresh probe staging directory", "Temporarily exempt ONLY that profile SID from loopback blocking via an elevated lease broker", "Run zero-network-capability probes and compare direct IPv4/IPv6 denial with explicit loopback-proxy TLS", "Remove exact loopback exemption, remove staging ACL grant, and delete only that new profile; preserve evidence" },
        exclusions = new[] { "No real Claude or auth files", "No changes to existing firewall rules, profiles, FlClash or system region", "No global IPv6 change", "No production launch qualification from probe-only results" }
    };

    internal static string Derive(string name)
    {
        if (!Regex.IsMatch(name, "^ClaudeProtectionProbe\\.[a-f0-9]{32}$")) throw new ArgumentException("Unexpected profile name");
        Marshal.ThrowExceptionForHR(DeriveAppContainerSidFromAppContainerName(name, out var sid));
        try { return new SecurityIdentifier(sid).Value; } finally { FreeSid(sid); }
    }

    internal static Manifest Create(string run)
    {
        var directory = DirectoryFor(run);
        if (Directory.Exists(directory)) throw new InvalidOperationException("Probe directory already exists");
        Directory.CreateDirectory(directory);
        var name = Name(run);
        File.WriteAllText(Path.Combine(directory, "creation-plan.json"), JsonSerializer.Serialize(new { run, profile = name, directory, atUtc = DateTimeOffset.UtcNow }, Files.Json));
        Marshal.ThrowExceptionForHR(CreateAppContainerProfile(name, name, "Disposable ClaudeProtection network probe; no credentials", IntPtr.Zero, 0, out var sid));
        try
        {
            var identity = new SecurityIdentifier(sid);
            var hashes = new Dictionary<string, string>();
            // Persist recovery identity before copying images or changing ACLs.
            File.WriteAllText(Path.Combine(directory, "manifest.json"), JsonSerializer.Serialize(new Manifest(run, name, identity.Value, directory, hashes), Files.Json));
            foreach (var filename in new[] { "ClaudeProtection.exe", "ClaudeProtection.dll", "ClaudeProtection.deps.json", "ClaudeProtection.runtimeconfig.json" })
            {
                var destination = Path.Combine(directory, filename);
                File.Copy(Path.Combine(AppContext.BaseDirectory, filename), destination, false);
                hashes.Add(filename, ProxySettings.Hash(File.ReadAllBytes(destination)));
            }
            var acl = new DirectoryInfo(directory).GetAccessControl();
            acl.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.ReadAndExecute, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(directory).SetAccessControl(acl);
            var manifest = new Manifest(run, name, identity.Value, directory, hashes);
            File.WriteAllText(Path.Combine(directory, "manifest.json"), JsonSerializer.Serialize(manifest, Files.Json));
            return manifest;
        }
        catch (Exception failure)
        {
            bool aclCleaned = false;
            try
            {
                var info = new DirectoryInfo(directory);
                var acl = info.GetAccessControl();
                acl.PurgeAccessRules(new SecurityIdentifier(sid));
                info.SetAccessControl(acl); aclCleaned = true;
            }
            catch { /* Record cleanup failure below; never silently grant success. */ }
            int cleanupHr = DeleteAppContainerProfile(name);
            File.WriteAllText(Path.Combine(directory, "creation-failed.json"), JsonSerializer.Serialize(new { errorType = failure.GetType().Name, aclCleaned, profileCleanupHResult = cleanupHr }, Files.Json));
            if (!aclCleaned || cleanupHr < 0) throw new AggregateException(failure, new InvalidOperationException("Disposable profile recovery incomplete; exact identity is preserved in its manifest"));
            throw;
        }
        finally { FreeSid(sid); }
    }

    internal static Manifest Load(string run, bool verifyImages = true)
    {
        var directory = DirectoryFor(run);
        var manifest = JsonSerializer.Deserialize<Manifest>(File.ReadAllText(Path.Combine(directory, "manifest.json")), Files.Json) ?? throw new InvalidDataException();
        if (manifest.Run != run || manifest.Profile != Name(run) || manifest.Directory != directory || manifest.Sid != Derive(manifest.Profile)) throw new InvalidDataException("Manifest scope mismatch");
        if (verifyImages)
            foreach (var filename in new[] { "ClaudeProtection.exe", "ClaudeProtection.dll", "ClaudeProtection.deps.json", "ClaudeProtection.runtimeconfig.json" })
                if (!manifest.Hashes.TryGetValue(filename, out var expected) || ProxySettings.Hash(File.ReadAllBytes(Path.Combine(directory, filename))) != expected) throw new InvalidDataException("Staged probe hash mismatch");
        return manifest;
    }

    internal static async Task<JsonElement> Run(string run)
    {
        var manifest = Load(run);
        var proxyBaseline = UserProxyBaseline.Read();
        if (!proxyBaseline.ExpectedFlClashProxy) throw new InvalidOperationException("Global proxy APIs are inconsistent or differ from the validated FlClash endpoint; no probe started");
        Marshal.ThrowExceptionForHR(DeriveAppContainerSidFromAppContainerName(manifest.Profile, out var sid));
        try
        {
            using var pipe = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
            using var controlled = new ControlledLoopback();
            var stdout = new IntPtr(long.Parse(pipe.GetClientHandleAsString()));
            using var job = new NativeJob(Path.Combine(manifest.Directory, "ClaudeProtection.exe"), new[] { "_sandbox-worker", JsonSerializer.Serialize(controlled.Endpoints) }, manifest.Directory,
                new Dictionary<string, string> { ["DOTNET_EnableDiagnostics"] = "0", ["HTTP_PROXY"] = "http://127.0.0.1:7890", ["HTTPS_PROXY"] = "http://127.0.0.1:7890" }, sid, stdout, true);
            pipe.DisposeLocalCopyOfClientHandle();
            using var reader = new StreamReader(pipe);
            var read = reader.ReadToEndAsync();
            await ExperimentMonitor.Wait(job, proxyBaseline.Fingerprint, () => UserProxyBaseline.Read().Fingerprint, TimeSpan.FromSeconds(70));
            var text = await read.WaitAsync(TimeSpan.FromSeconds(5));
            if (job.ExitCode != 0) throw new InvalidOperationException("Disposable sandbox worker failed");
            await Task.Delay(300); // Drain already-sent local datagrams before reporting.
            var node = System.Text.Json.Nodes.JsonNode.Parse(text) as System.Text.Json.Nodes.JsonObject ?? throw new InvalidDataException();
            node["controlledLoopback"] = JsonSerializer.SerializeToNode(controlled.Receipts());
            var report = JsonSerializer.SerializeToElement(node);
            File.WriteAllText(Path.Combine(manifest.Directory, "worker-results-" + Guid.NewGuid().ToString("N") + ".json"), JsonSerializer.Serialize(report, Files.Json));
            return report;
        }
        finally { FreeSid(sid); }
    }

    internal static void Remove(string run)
    {
        var manifest = Load(run, false);
        if (LoopbackContains(manifest.Sid)) throw new InvalidOperationException("Remove the exact temporary loopback exemption before deleting this profile");
        var directory = new DirectoryInfo(manifest.Directory);
        var acl = directory.GetAccessControl();
        acl.PurgeAccessRules(new SecurityIdentifier(manifest.Sid));
        directory.SetAccessControl(acl);
        Marshal.ThrowExceptionForHR(DeleteAppContainerProfile(manifest.Profile));
        File.WriteAllText(Path.Combine(manifest.Directory, "profile-cleaned.json"), JsonSerializer.Serialize(new { atUtc = DateTimeOffset.UtcNow, profile = manifest.Profile, removed = true }, Files.Json));
    }

    internal static async Task<object> GuardFailure(string run)
    {
        var manifest = Load(run);
        var baseline = UserProxyBaseline.Read();
        if (!baseline.ExpectedFlClashProxy) throw new InvalidOperationException("Host proxy baseline differs from the validated environment");
        var hostProxy = await EnvironmentAudit.Transport("unaffected-host-proxy", "https://api.anthropic.com/v1/models", false);
        Marshal.ThrowExceptionForHR(DeriveAppContainerSidFromAppContainerName(manifest.Profile, out var sid));
        try
        {
            using var output = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
            using var session = new NativeJob(Path.Combine(manifest.Directory, "ClaudeProtection.exe"), new[] { "_sandbox-wait" }, manifest.Directory,
                new Dictionary<string, string> { ["DOTNET_EnableDiagnostics"] = "0" }, sid, new IntPtr(long.Parse(output.GetClientHandleAsString())), true);
            output.DisposeLocalCopyOfClientHandle();
            using var reader = new StreamReader(output);
            var line = await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10)) ?? throw new InvalidDataException("Missing parent probe identity");
            var announcement = JsonSerializer.Deserialize<JsonElement>(line);
            if (announcement.GetProperty("role").GetString() != "parent" || announcement.GetProperty("pid").GetUInt32() != session.Pid) throw new InvalidDataException("Parent identity mismatch");
            var membership = Stopwatch.StartNew();
            while (session.ProcessIds.Length < 2 && membership.Elapsed < TimeSpan.FromSeconds(10)) await Task.Delay(20);
            var ownedIds = session.ProcessIds;
            uint childId = announcement.GetProperty("childPid").GetUInt32();
            if (ownedIds.Length < 2 || !ownedIds.Contains(session.Pid) || !ownedIds.Contains(childId) || session.ActiveProcesses < 2) throw new InvalidDataException("Owned parent/child were not established");
            string scopedStatus = "UNKNOWN";
            var exit = await SessionMonitor.Run(session, async () =>
            {
                var scoped = await Run(run);
                scopedStatus = scoped.GetProperty("proxy").GetProperty("Status").GetString() ?? "UNKNOWN";
                return new Audit(1, DateTime.UtcNow.ToString("o"), new() { new("scoped-proxy-transport", scopedStatus, "Live disposable AppContainer transport result") });
            }, _ => { }, 20).WaitAsync(TimeSpan.FromSeconds(80));
            var watch = Stopwatch.StartNew();
            while (session.ActiveProcesses != 0 && watch.Elapsed < TimeSpan.FromSeconds(5)) await Task.Delay(20);
            var report = new
            {
                scope = "Disposable parent and child only; real Claude not started",
                hostProxyStillWorks = hostProxy.Status == "PASS",
                scopedProxyStatus = scopedStatus,
                guardExitCode = exit,
                reportedParentAndChild = ownedIds.Length >= 2,
                declaredChildPid = childId,
                ownedParentAndDeclaredChildVerified = ownedIds.Contains(session.Pid) && ownedIds.Contains(childId),
                ownedProcessIdsBeforeFailure = ownedIds,
                activeOwnedProcessesAfterStop = session.ActiveProcesses,
                systemProxyUnchanged = UserProxyBaseline.Read().Fingerprint == baseline.Fingerprint
            };
            File.WriteAllText(Path.Combine(manifest.Directory, "guard-failure-results.json"), JsonSerializer.Serialize(report, Files.Json));
            return report;
        }
        finally { FreeSid(sid); }
    }

    internal static bool LoopbackContains(string sid)
    {
        uint code = NetworkIsolationGetAppContainerConfig(out uint count, out var array);
        if (code != 0) throw new System.ComponentModel.Win32Exception((int)code);
        try
        {
            var stride = Marshal.SizeOf<SidAndAttributes>();
            for (int i = 0; i < count; i++)
            {
                var entry = Marshal.PtrToStructure<SidAndAttributes>(array + i * stride);
                if (new SecurityIdentifier(entry.Sid).Value == sid) return true;
            }
            return false;
        }
        finally
        {
            // GetAppContainerConfig allocates SID_AND_ATTRIBUTES plus each SID
            // on the process heap; EnumAppContainers uses a different free API.
            if (array != IntPtr.Zero)
            {
                var heap = GetProcessHeap();
                var stride = Marshal.SizeOf<SidAndAttributes>();
                for (int i = 0; i < count; i++)
                {
                    var entry = Marshal.PtrToStructure<SidAndAttributes>(array + i * stride);
                    if (entry.Sid != IntPtr.Zero) _ = HeapFree(heap, 0, entry.Sid);
                }
                _ = HeapFree(heap, 0, array);
            }
        }
    }

    internal static async Task<object> Worker(bool leaf, ControlledLoopback.Targets targets)
    {
        using var current = Process.GetCurrentProcess();
        var identity = SandboxToken.Read(current.Handle);
        var checks = new Dictionary<string, string>();
        foreach (var pair in new[] { ("ipv4", "1.1.1.1"), ("ipv6", "2606:4700:4700::1111") })
        {
            try
            {
                var address = IPAddress.Parse(pair.Item2);
                using var client = new TcpClient(address.AddressFamily);
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
                await client.ConnectAsync(address, 443, timeout.Token); checks[pair.Item1] = "CONNECTED_UNSAFE";
            }
            catch (SocketException ex) { checks[pair.Item1] = ex.SocketErrorCode == SocketError.AccessDenied ? "DENIED" : "UNKNOWN_" + ex.SocketErrorCode; }
            catch (OperationCanceledException) { checks[pair.Item1] = "UNKNOWN_TIMEOUT"; }
        }
        foreach (var pair in new[] { ("udp-ipv4", "1.1.1.1"), ("udp-ipv6", "2606:4700:4700::1111") })
        {
            try
            {
                var address = IPAddress.Parse(pair.Item2);
                using var socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                await socket.SendToAsync(new byte[] { 0 }, SocketFlags.None, new IPEndPoint(address, 3478));
                checks[pair.Item1] = "UNKNOWN_SEND_ACCEPTED"; // UDP send success is not delivery proof.
            }
            catch (SocketException ex) { checks[pair.Item1] = ex.SocketErrorCode == SocketError.AccessDenied ? "DENIED" : "UNKNOWN_" + ex.SocketErrorCode; }
        }
        foreach (var localTarget in new[] { ("alternate-loopback", IPAddress.Loopback, targets.Tcp4), ("alternate-loopback-ipv6", IPAddress.IPv6Loopback, targets.Tcp6) })
        {
            try
            {
                using var local = new TcpClient(localTarget.Item2.AddressFamily);
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await local.ConnectAsync(localTarget.Item2, localTarget.Item3, timeout.Token);
                checks[localTarget.Item1] = "REACHABLE_PROXY_EXCLUSIVITY_GAP";
            }
            catch (SocketException ex) { checks[localTarget.Item1] = ex.SocketErrorCode == SocketError.AccessDenied ? "DENIED" : "UNKNOWN_" + ex.SocketErrorCode; }
            catch (OperationCanceledException) { checks[localTarget.Item1] = "UNKNOWN_TIMEOUT"; }
        }
        foreach (var target in new[] { ("controlled-udp-ipv4-send", IPAddress.Loopback, targets.Udp4), ("controlled-udp-ipv6-send", IPAddress.IPv6Loopback, targets.Udp6) })
        {
            try
            {
                using var sender = new UdpClient(target.Item2.AddressFamily);
                var payload = System.Text.Encoding.ASCII.GetBytes(targets.Nonce + ":" + (leaf ? "child" : "parent"));
                await sender.SendAsync(payload, new IPEndPoint(target.Item2, target.Item3));
                checks[target.Item1] = "SEND_ACCEPTED_RECEIVER_MUST_VERIFY";
            }
            catch (SocketException ex) { checks[target.Item1] = ex.SocketErrorCode == SocketError.AccessDenied ? "DENIED" : "UNKNOWN_" + ex.SocketErrorCode; }
        }
        try
        {
            // Random public documentation-domain name avoids interpreting a cached
            // success as proof of isolation. Resolver outcome still needs attribution.
            _ = await Dns.GetHostAddressesAsync("probe-" + Guid.NewGuid().ToString("N") + ".example.com").WaitAsync(TimeSpan.FromSeconds(4));
            checks["system-dns"] = "UNKNOWN_RESOLVED_REQUIRES_ATTRIBUTION";
        }
        catch (SocketException ex) { checks["system-dns"] = "UNKNOWN_RESOLVER_" + ex.SocketErrorCode; }
        catch (TimeoutException) { checks["system-dns"] = "UNKNOWN_TIMEOUT"; }
        var proxy = await EnvironmentAudit.Transport("sandbox-proxy-tls", "https://api.anthropic.com/v1/models", false);
        JsonElement? child = null;
        if (!leaf)
        {
            var start = new ProcessStartInfo(Files.Host) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            start.ArgumentList.Add("_sandbox-leaf");
            start.ArgumentList.Add(JsonSerializer.Serialize(targets));
            using var process = Process.Start(start) ?? throw new InvalidOperationException();
            var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
            try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30)); }
            catch { process.Kill(true); throw; }
            _ = await stderr;
            if (process.ExitCode != 0) throw new InvalidOperationException("Sandbox descendant failed");
            child = JsonSerializer.Deserialize<JsonElement>(await stdout, Files.Json);
        }
        return new { identity, checks, proxy, child };
    }

    [StructLayout(LayoutKind.Sequential)] private struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)] private static extern int CreateAppContainerProfile(string name, string display, string description, IntPtr capabilities, uint count, out IntPtr sid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)] private static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)] private static extern int DeleteAppContainerProfile(string name);
    [DllImport("advapi32.dll")] private static extern IntPtr FreeSid(IntPtr sid);
    [DllImport("FirewallAPI.dll")] private static extern uint NetworkIsolationGetAppContainerConfig(out uint count, out IntPtr config);
    [DllImport("kernel32.dll")] private static extern IntPtr GetProcessHeap();
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool HeapFree(IntPtr heap, uint flags, IntPtr memory);
}
