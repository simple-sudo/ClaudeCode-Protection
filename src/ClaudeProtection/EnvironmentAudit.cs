using System.Diagnostics;
using System.Net;
using System.Text.Json;

namespace ClaudeProtection;

internal static class EnvironmentAudit
{
    internal static async Task<Audit> Run(string cwd, bool online)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"))
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
            CreateNoWindow = true, StandardOutputEncoding = System.Text.Encoding.UTF8
        };
        // A caller running PowerShell 7 can export Core-only module paths.
        // Let Windows PowerShell 5.1 construct its own default module search path.
        start.Environment.Remove("PSModulePath");
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", Path.Combine(AppContext.BaseDirectory, "Read-Environment.ps1"), "-WorkingDirectory", Path.GetFullPath(cwd) })
            start.ArgumentList.Add(arg);
        using var child = Process.Start(start) ?? throw new InvalidOperationException("Audit worker failed to start");
        var stdout = child.StandardOutput.ReadToEndAsync();
        var stderr = child.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        try { await child.WaitForExitAsync(timeout.Token); }
        catch { child.Kill(true); throw new InvalidOperationException("Environment audit timed out; launch refused"); }
        var data = await stdout;
        _ = await stderr; // Do not echo potentially sensitive PowerShell diagnostics.
        if (child.ExitCode != 0) throw new InvalidOperationException("Environment audit worker failed; launch refused");
        var audit = JsonSerializer.Deserialize<Audit>(data, Files.Json) ?? throw new InvalidDataException("Missing audit report");
        if (online)
        {
            audit.Checks.Add(await Transport("claude-api-transport", "https://api.anthropic.com/v1/models", false));
            audit.Checks.Add(await Transport("proxy-egress-country", "https://www.cloudflare.com/cdn-cgi/trace", true));
        }
        else
        {
            audit.Checks.Add(new("claude-api-transport", "UNKNOWN", "Online transport test not requested"));
            audit.Checks.Add(new("proxy-egress-country", "UNKNOWN", "Online egress test not requested"));
        }
        return audit;
    }

    internal static async Task<Check> Transport(string name, string url, bool country, string proxy = "http://127.0.0.1:7890")
    {
        try
        {
            using var handler = new HttpClientHandler
            {
                Proxy = new WebProxy(proxy) { BypassProxyOnLocal = false }, UseProxy = true,
                AllowAutoRedirect = false, UseCookies = false
            };
            // Default certificate validation stays enabled. No credentials are sent.
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(12), MaxResponseContentBufferSize = 65536 };
            using var response = await client.GetAsync(url);
            var code = (int)response.StatusCode;
            if (country)
            {
                var body = await response.Content.ReadAsStringAsync();
                var location = body.Split('\n').FirstOrDefault(s => s.StartsWith("loc=", StringComparison.Ordinal))?.Trim();
                return new(name, code == 200 && location == "loc=US" ? "PASS" : "FAIL",
                    code == 200 && location == "loc=US" ? "Explicit proxy HTTPS trace reports US; IP omitted; not a residential-ASN proof" : "Expected US egress was not established; response withheld");
            }
            return new(name, code is 200 or 401 or 403 ? "PASS" : "FAIL",
                $"Explicit proxy HTTPS response HTTP={code}; TLS verified; account/auth/access permission NOT verified");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or UriFormatException)
        {
            return new(name, "FAIL", "Explicit proxy transport failed (no direct retry): " + ex.GetType().Name);
        }
    }
}
