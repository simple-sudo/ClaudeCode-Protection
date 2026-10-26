using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace ClaudeProtection;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = new System.Text.UTF8Encoding(false);
        try
        {
            switch (args.FirstOrDefault())
            {
                case "audit":
                    var audit = await EnvironmentAudit.Run(Environment.CurrentDirectory, args.Contains("--online"));
                    Console.WriteLine(JsonSerializer.Serialize(audit, Files.Json));
                    return Gate.Reject(audit).Length == 0 ? 0 : 2;
                case "system-proxy-baseline": Console.WriteLine(JsonSerializer.Serialize(UserProxyBaseline.Read(), Files.Json)); return 0;
                case "process-identity": Console.WriteLine(JsonSerializer.Serialize(ProcessIdentity.Read(uint.Parse(args[1])), Files.Json)); return 0;
                case "isolation-plan": Console.WriteLine(JsonSerializer.Serialize(IsolationExperiment.Plan(), Files.Json)); return 0;
                case "isolation-derive": Console.WriteLine(IsolationExperiment.Derive(args[1])); return 0;
                case "isolation-loopback-check": Console.WriteLine(IsolationExperiment.LoopbackContains(args[1]) ? "PRESENT" : "ABSENT"); return 0;
                case "isolation-create": Console.WriteLine(JsonSerializer.Serialize(IsolationExperiment.Create(args[1]), Files.Json)); return 0;
                case "isolation-run": Console.WriteLine(JsonSerializer.Serialize(await IsolationExperiment.Run(args[1]), Files.Json)); return 0;
                case "isolation-guard-failure": Console.WriteLine(JsonSerializer.Serialize(await IsolationExperiment.GuardFailure(args[1]), Files.Json)); return 0;
                case "isolation-remove": IsolationExperiment.Remove(args[1]); return 0;
                case "_sandbox-worker": Console.WriteLine(JsonSerializer.Serialize(await IsolationExperiment.Worker(false, JsonSerializer.Deserialize<ControlledLoopback.Targets>(args[1])!), Files.Json)); return 0;
                case "_sandbox-leaf": Console.WriteLine(JsonSerializer.Serialize(await IsolationExperiment.Worker(true, JsonSerializer.Deserialize<ControlledLoopback.Targets>(args[1])!), Files.Json)); return 0;
                case "_sandbox-wait":
                    var waitStart = new ProcessStartInfo(Files.Host) { UseShellExecute = false, CreateNoWindow = true };
                    waitStart.ArgumentList.Add("_sandbox-waitleaf");
                    using (var waitChild = Process.Start(waitStart) ?? throw new InvalidOperationException("Child probe did not start"))
                    {
                        Console.WriteLine(JsonSerializer.Serialize(new { role = "parent", pid = Environment.ProcessId, childPid = waitChild.Id }));
                        await Task.Delay(Timeout.Infinite);
                    }
                    return 0;
                case "_sandbox-waitleaf":
                    Console.WriteLine(JsonSerializer.Serialize(new { role = "child", pid = Environment.ProcessId }));
                    await Task.Delay(Timeout.Infinite); return 0;
                case "transport":
                    var transport = await EnvironmentAudit.Transport("claude-api-transport", "https://api.anthropic.com/v1/models", false);
                    Console.WriteLine(JsonSerializer.Serialize(transport, Files.Json));
                    return transport.Status == "PASS" ? 0 : 2;
                case "probe-tcp": return await Probe(args);
                default:
                    Console.WriteLine("ClaudeProtection ENGINEERING ONLY | isolation-plan | probe-tcp IP PORT");
                    Console.WriteLine("No real Claude launch or aggregate selftest command. Separate engineering build; not shipped with daily tools.");
                    return args.Length == 0 ? 0 : 64;
            }
        }
        catch (Exception ex)
        {
            // Never print arguments, credentials, response bodies, or environment values.
            var code = ex is System.ComponentModel.Win32Exception native ? native.NativeErrorCode : ex.HResult;
            Console.Error.WriteLine("Operation failed: " + ex.GetType().Name + "; code=" + code + "; stage=" + ex.Data["Stage"]);
            return 125;
        }
    }

    private static async Task<int> Probe(string[] args)
    {
        if (args.Length != 3 || !IPAddress.TryParse(args[1], out var address) || !int.TryParse(args[2], out var port) || port < 1 || port > 65535) return 64;
        try
        {
            using var client = new TcpClient(address.AddressFamily);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await client.ConnectAsync(address, port, timeout.Token);
            Console.WriteLine("CONNECTED"); return 0;
        }
        catch (SocketException ex) { Console.WriteLine("SOCKET=" + ex.SocketErrorCode); return ex.SocketErrorCode == SocketError.AccessDenied ? 10 : 11; }
        catch (OperationCanceledException) { Console.WriteLine("UNKNOWN_TIMEOUT"); return 12; }
    }
}

internal static class SessionMonitor
{
    internal static async Task<int> Run(NativeJob session, Func<Task<Audit>> readHealth, Action<string[]> stopped, int intervalMs)
    {
        try
        {
            while (!session.HasExited)
            {
                await Task.Delay(intervalMs);
                if (session.HasExited) break;
                var failures = Gate.Reject(await readHealth());
                if (failures.Length == 0) continue;
                session.Terminate();
                stopped(failures);
                return 125;
            }
            return (int)session.ExitCode;
        }
        catch
        {
            // Stop first, even if the health reader or logging fails.
            session.Terminate();
            throw;
        }
    }
}

