using System.Diagnostics;
using System.IO;
using System.Text.Json;

namespace ProtectionCenter;

internal sealed record BackendResult(int ExitCode, string Output, string Error);
internal static class BackendClient
{
    internal static string Root => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", ".."));
    internal static async Task<BackendResult> Command(params string[] arguments)
    {
        // Defense in depth: the GUI cannot dispatch engineering commands even
        // if a future caller accidentally wires one into a button.
        if (arguments.Length == 0 || arguments[0] is not ("audit" or "system-proxy-baseline" or "repair-proxy-plan" or "repair-proxy" or "restore-proxy"))
            throw new InvalidOperationException("此操作不属于日常检查与维护");
        return await Run(Path.Combine(Root, "bin", "current", "ClaudeProtection.exe"), arguments);
    }
    private static async Task<BackendResult> Run(string executable, IEnumerable<string> arguments)
    {
        var info = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = System.Text.Encoding.UTF8, StandardErrorEncoding = System.Text.Encoding.UTF8,
            WorkingDirectory = Root
        };
        info.Environment.Remove("PSModulePath");
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("检查程序未能启动");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        // Daily operations own their completion; engineering harnesses are excluded.
        await process.WaitForExitAsync();
        return new(process.ExitCode, await output, await error);
    }
    internal static string SaveReport(string name, BackendResult result)
    {
        if(name is not ("environment" or "config-repair"))throw new InvalidDataException("Unknown report kind");
        var directory = ClaudeProtection.Storage.UserDataPaths.Reports;
        var file = Path.Combine(directory, name + "-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..6] + ".json");
        using(var stream=new FileStream(file,FileMode.CreateNew,FileAccess.Write,FileShare.Read))
        {JsonSerializer.Serialize(stream,new { atUtc = DateTimeOffset.UtcNow, result.ExitCode, result.Output, result.Error },new JsonSerializerOptions{WriteIndented=true});stream.Flush(true);}
        return file;
    }
}
