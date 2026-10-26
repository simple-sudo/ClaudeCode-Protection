using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace ClaudeProtection;

internal static class SelfTests
{
    internal static async Task<int> Run()
    {
        var results = new List<object>();
        var directory = Path.Combine(Files.Root, "state", "selftest", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        async Task Test(string name, Func<Task> action)
        {
            try { await action(); results.Add(new { name, status = "PASS" }); }
            catch (Exception ex) { results.Add(new { name, status = "FAIL", error = ex.GetType().Name }); }
        }
        await Test("UNKNOWN and FAIL block required checks", () =>
        {
            foreach (var status in new[] { "FAIL", "UNKNOWN", "", "pass" })
                Assert(Gate.Reject(new(1, "", new() { new("test", status, "") })).Length == 1);
            Assert(Gate.Reject(new(1, "", new() { new("test", "PASS", "") })).Length == 0);
            return Task.CompletedTask;
        });
        await Test("No all-green fixture can bypass unqualified network backend", () =>
        {
            Assert(Gate.LaunchRejection(new(1, "", new() { new("fixture", "PASS", "") })) is not null);
            return Task.CompletedTask;
        });
        await Test("Windows command line preserves quotes spaces Unicode trailing slashes and empty arguments", async () =>
        {
            var path = Path.Combine(directory, "arguments.json");
            var expected = new[] { "", "a b", "a\"b", "C:\\space name\\", "中文", "x\\\"y", "&;$()`" };
            using var job = new NativeJob(Files.Host, new[] { "_echo-arguments", path }.Concat(expected), directory);
            await Wait(() => job.HasExited);
            Assert(job.ExitCode == 0);
            var actual = JsonSerializer.Deserialize<string[]>(File.ReadAllText(path));
            Assert(actual is not null && actual.SequenceEqual(expected));
        });
        await Test("Job close terminates owned parent and child and preserves unrelated sentinel", async () =>
        {
            var parent = Path.Combine(directory, "parent.pid"); var child = Path.Combine(directory, "child.pid");
            using var sentinel = Start("_worker", Path.Combine(directory, "sentinel.pid"));
            try
            {
                int parentId, childId;
                using (var job = new NativeJob(Files.Host, new[] { "_worker", parent, child }, directory))
                {
                    await Wait(() => File.Exists(parent) && File.Exists(child));
                    parentId = ReadPid(parent); childId = ReadPid(child);
                    Assert(Alive(parentId) && Alive(childId));
                    Assert(job.ProcessIds.Contains((uint)parentId) && job.ProcessIds.Contains((uint)childId));
                }
                await Wait(() => !Alive(parentId) && !Alive(childId));
                Assert(!sentinel.HasExited);
            }
            finally { if (!sentinel.HasExited) sentinel.Kill(true); await sentinel.WaitForExitAsync(); }
        });
        await Test("Abrupt guard death closes kernel job and terminates owned descendants", async () =>
        {
            var parent = Path.Combine(directory, "crash-parent.pid"); var child = Path.Combine(directory, "crash-child.pid");
            using var owner = Start("_job-owner", parent, child);
            try
            {
                await Wait(() => File.Exists(parent) && File.Exists(child));
                var parentId = ReadPid(parent); var childId = ReadPid(child);
                owner.Kill(false); await owner.WaitForExitAsync();
                await Wait(() => !Alive(parentId) && !Alive(childId));
            }
            finally { if (!owner.HasExited) { owner.Kill(true); await owner.WaitForExitAsync(); } }
        });
        await Test("Health failure stops only the owned session", async () =>
        {
            var pidFile = Path.Combine(directory, "health.pid");
            using var job = new NativeJob(Files.Host, new[] { "_worker", pidFile }, directory);
            await Wait(() => File.Exists(pidFile));
            bool logged = false;
            var code = await SessionMonitor.Run(job, () => Task.FromResult(new Audit(1, "", new() { new("proxy", "FAIL", "fixture") })), _ => logged = true, 20);
            await Wait(() => job.HasExited);
            await Wait(() => job.ActiveProcesses == 0);
            Assert(code == 125 && logged);
        });
        await Test("Health-reader exception terminates owned session before propagating", async () =>
        {
            var pidFile = Path.Combine(directory, "exception.pid");
            using var job = new NativeJob(Files.Host, new[] { "_worker", pidFile }, directory);
            await Wait(() => File.Exists(pidFile));
            bool threw = false;
            try { await SessionMonitor.Run(job, () => throw new IOException("fixture"), _ => { }, 20); }
            catch (IOException) { threw = true; }
            await Wait(() => job.HasExited); Assert(threw);
        });
        await Test("Explicit proxy failure never retries a reachable local origin directly", async () =>
        {
            var origin = new TcpListener(IPAddress.Loopback, 0); origin.Start();
            var proxy = new TcpListener(IPAddress.Loopback, 0); proxy.Start();
            int originPort = ((IPEndPoint)origin.LocalEndpoint).Port;
            int proxyPort = ((IPEndPoint)proxy.LocalEndpoint).Port;
            proxy.Stop();
            try
            {
                var result = await EnvironmentAudit.Transport("fixture", $"http://127.0.0.1:{originPort}/", false, $"http://127.0.0.1:{proxyPort}");
                Assert(result.Status == "FAIL" && !origin.Pending());
            }
            finally { origin.Stop(); }
        });
        await Test("STUN validates transaction cookie length bounds IPv4 IPv6 and missing response", () =>
        {
            var transaction = Enumerable.Range(1, 12).Select(i => (byte)i).ToArray();
            foreach (var ip in new[] { IPAddress.Parse("203.0.113.7"), IPAddress.Parse("2001:db8::7") })
            {
                var packet = Packet(ip, transaction);
                Assert(ip.Equals(StunCodec.Parse(packet, transaction)));
                Assert(StunCodec.Parse(packet.AsSpan(0, packet.Length - 1), transaction) is null);
                var wrong = transaction.ToArray(); wrong[0] ^= 1;
                Assert(StunCodec.Parse(packet, wrong) is null);
                packet[4] ^= 1; Assert(StunCodec.Parse(packet, transaction) is null); packet[4] ^= 1;
                packet[23] = 255; Assert(StunCodec.Parse(packet, transaction) is null);
            }
            Assert(StunCodec.Parse(Array.Empty<byte>(), transaction) is null);
            return Task.CompletedTask;
        });
        await Test("Proxy merge preserves unrelated settings and secret fields without logging values", () =>
        {
            var original = System.Text.Encoding.UTF8.GetBytes("{\"env\":{\"https_proxy\":\"http://old\",\"ANTHROPIC_AUTH_TOKEN\":\"fixture-secret\"},\"permissions\":{\"deny\":[\"fixture\"]},\"hooks\":{}}");
            var merged = System.Text.Json.Nodes.JsonNode.Parse(ProxySettings.Merge(original))!;
            Assert(merged["env"]!["ANTHROPIC_AUTH_TOKEN"]!.GetValue<string>() == "fixture-secret");
            Assert(merged["env"]!["HTTPS_PROXY"]!.GetValue<string>() == "http://127.0.0.1:7890");
            Assert(merged["env"]!["https_proxy"] is null);
            Assert(merged["permissions"]!["deny"]![0]!.GetValue<string>() == "fixture");
            Assert(merged["hooks"] is not null);
            bool failed = false;
            try { ProxySettings.Merge(System.Text.Encoding.UTF8.GetBytes("{\"env\":1}")); } catch (InvalidDataException) { failed = true; }
            Assert(failed); return Task.CompletedTask;
        });
        await Test("Isolation probe scope rejects traversal and existing-profile names without mutation", () =>
        {
            foreach (var value in new[] { "../other", "ExistingApp", "a b", "0000000000000000000000000000000Z" })
            {
                bool rejected = false;
                try { _ = IsolationExperiment.DirectoryFor(value); } catch (ArgumentException) { rejected = true; }
                Assert(rejected);
            }
            using var process = Process.GetCurrentProcess();
            Assert(!SandboxToken.Read(process.Handle).IsAppContainer);
            return Task.CompletedTask;
        });
        await Test("Injected system proxy drift terminates the owned probe without changing actual Windows proxy", async () =>
        {
            var before = UserProxyBaseline.Read().Fingerprint;
            var pidFile = Path.Combine(directory, "proxy-drift.pid");
            using var job = new NativeJob(Files.Host, new[] { "_worker", pidFile }, directory);
            await Wait(() => File.Exists(pidFile));
            bool refused = false;
            try { await ExperimentMonitor.Wait(job, "fixture-before", () => "fixture-after", TimeSpan.FromSeconds(2), 20); }
            catch (InvalidOperationException) { refused = true; }
            await Wait(() => job.HasExited);
            Assert(refused && before == UserProxyBaseline.Read().Fingerprint);
        });
        await Test("System proxy preflight accepts normal FlClash forms and refuses wrong ports and endpoints", () =>
        {
            foreach (var value in new[] { "127.0.0.1:7890", "http://127.0.0.1:7890", "http=127.0.0.1:7890;https=127.0.0.1:7890", "https=127.0.0.1:7890;http=127.0.0.1:7890" }) Assert(UserProxyBaseline.IsExpectedEndpoint(value));
            foreach (var value in new[] { "127.0.0.1:8888", "http=127.0.0.1:7890", "example.com:7890", "http://u:p@127.0.0.1:7890", "http://127.0.0.1:7890/path" }) Assert(!UserProxyBaseline.IsExpectedEndpoint(value));
            return Task.CompletedTask;
        });
        await Test("Controlled IPv4 and IPv6 UDP receivers correlate actual delivery and reject unrelated packets", async () =>
        {
            using var controlled = new ControlledLoopback();
            foreach (var pair in new[] { (IPAddress.Loopback, controlled.Endpoints.Udp4), (IPAddress.IPv6Loopback, controlled.Endpoints.Udp6) })
            {
                using var sender = new UdpClient(pair.Item1.AddressFamily);
                foreach (var text in new[] { "unrelated:parent", controlled.Endpoints.Nonce + ":parent", controlled.Endpoints.Nonce + ":child" })
                    await sender.SendAsync(System.Text.Encoding.ASCII.GetBytes(text), new IPEndPoint(pair.Item1, pair.Item2));
            }
            await Wait(() =>
            {
                var receipts = JsonSerializer.SerializeToElement(controlled.Receipts());
                return receipts.GetProperty("ipv4ReceiptRoles").GetArrayLength() == 2 && receipts.GetProperty("ipv6ReceiptRoles").GetArrayLength() == 2;
            });
        });
        await Test("Limited-information identity binds the running executable path and process lifetime", () =>
        {
            var identity = ProcessIdentity.Read((uint)Environment.ProcessId);
            Assert(identity.Running && identity.Pid == Environment.ProcessId && string.Equals(identity.ImagePath, Files.Host, StringComparison.OrdinalIgnoreCase));
            Assert(DateTime.TryParse(identity.CreatedUtc, out _));
            return Task.CompletedTask;
        });
        await Test("Proxy repair rejects stale review hashes and preserves original bytes on failure", () =>
        {
            var file = Path.Combine(directory, "repair-stale.json"); var bytes = System.Text.Encoding.UTF8.GetBytes("{\"env\":{},\"fixture\":true}");
            File.WriteAllBytes(file, bytes); bool refused = false;
            try { ProxySettings.Apply(file, new string('0', 64), Path.Combine(directory, "unused-backups")); }
            catch (InvalidOperationException) { refused = true; }
            Assert(refused && File.ReadAllBytes(file).SequenceEqual(bytes));
            return Task.CompletedTask;
        });
        await Test("Proxy repair verifies private byte backup and keeps unrelated JSON", () =>
        {
            var file = Path.Combine(directory, "repair-apply.json"); var bytes = System.Text.Encoding.UTF8.GetBytes("{\"fixture\":42}");
            File.WriteAllBytes(file, bytes);
            var backup = ProxySettings.Apply(file, ProxySettings.Hash(bytes), Path.Combine(directory, "private-backups"));
            Assert(File.ReadAllBytes(backup).SequenceEqual(bytes));
            var current = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllBytes(file))!;
            Assert(current["fixture"]!.GetValue<int>() == 42);
            var currentBytes = File.ReadAllBytes(file);
            Assert(ProxySettings.Apply(file, ProxySettings.Hash(currentBytes), Path.Combine(directory, "private-backups")) == "UNCHANGED");
            return Task.CompletedTask;
        });
        await Test("Configuration restoration returns exact original bytes and refuses later unrelated edits", () =>
        {
            var file = Path.Combine(directory, "restore-settings.json");
            var original = System.Text.Encoding.UTF8.GetBytes("{\"fixture\":99,\"env\":{}}\r\n");
            var backups = Path.Combine(directory, "restore-backups"); File.WriteAllBytes(file, original);
            var backup = ProxySettings.Apply(file, ProxySettings.Hash(original), backups);
            _ = ProxySettings.Restore(file, backup, backups);
            Assert(File.ReadAllBytes(file).SequenceEqual(original));
            backup = ProxySettings.Apply(file, ProxySettings.Hash(original), backups);
            var changed = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllBytes(file))!;
            changed["userEdit"] = true; File.WriteAllText(file, changed.ToJsonString());
            var beforeRefusal = File.ReadAllBytes(file); bool refused = false;
            try { ProxySettings.Restore(file, backup, backups); } catch (InvalidOperationException) { refused = true; }
            Assert(refused && File.ReadAllBytes(file).SequenceEqual(beforeRefusal));
            return Task.CompletedTask;
        });
        var report = new { atUtc = DateTimeOffset.UtcNow, scope = "Isolated local engineering tests only; no firewall changes; no real Claude inference; no live leak qualification", results };
        var json = JsonSerializer.Serialize(report, Files.Json);
        File.WriteAllText(Path.Combine(directory, "results.json"), json);
        Console.WriteLine(json);
        return results.Any(r => JsonSerializer.Serialize(r).Contains("\"FAIL\"")) ? 1 : 0;
    }
    private static void Assert(bool value) { if (!value) throw new InvalidOperationException("Assertion failed"); }
    private static int ReadPid(string path) => int.Parse(File.ReadAllText(path));
    private static bool Alive(int pid) { try { using var process = Process.GetProcessById(pid); return !process.HasExited; } catch (ArgumentException) { return false; } }
    private static async Task Wait(Func<bool> condition)
    {
        var watch = Stopwatch.StartNew();
        while (!condition()) { if (watch.Elapsed > TimeSpan.FromSeconds(10)) throw new TimeoutException(); await Task.Delay(40); }
    }
    private static Process Start(params string[] arguments)
    {
        var start = new ProcessStartInfo(Files.Host) { UseShellExecute = false, CreateNoWindow = true };
        foreach (var arg in arguments) start.ArgumentList.Add(arg);
        return Process.Start(start) ?? throw new InvalidOperationException();
    }
    private static byte[] Packet(IPAddress ip, byte[] transaction)
    {
        var bytes = ip.GetAddressBytes(); var packet = new byte[28 + bytes.Length];
        BinaryPrimitives.WriteUInt16BigEndian(packet, 0x0101);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)(packet.Length - 20));
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4), 0x2112a442);
        transaction.CopyTo(packet, 8);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20), 0x0020);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22), (ushort)(4 + bytes.Length));
        packet[25] = (byte)(bytes.Length == 4 ? 1 : 2);
        for (int i = 0; i < bytes.Length; i++) packet[28 + i] = (byte)(bytes[i] ^ packet[4 + i]);
        return packet;
    }
}
