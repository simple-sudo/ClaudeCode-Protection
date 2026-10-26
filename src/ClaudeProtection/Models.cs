using System.Text.Json;

namespace ClaudeProtection;

internal sealed record Check(string Name, string Status, string Detail, bool Required = true);
internal sealed record Audit(int SchemaVersion, string AtUtc, List<Check> Checks);
internal static class Files
{
    internal static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };
    internal static string Root => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", ".."));
    internal static string Claude => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "bin", "claude.exe");
    internal static string Host => Environment.ProcessPath ?? throw new InvalidOperationException("Missing host path");
    internal static void Event(string name, string detail)
    {
        var directory = Path.Combine(Root, "logs");
        Directory.CreateDirectory(directory);
        var entry = JsonSerializer.Serialize(new { atUtc = DateTimeOffset.UtcNow, name, detail });
        File.AppendAllText(Path.Combine(directory, $"guard-{DateTime.UtcNow:yyyyMMdd}.jsonl"), entry + Environment.NewLine);
    }
}

internal static class Gate
{
    internal static string[] Reject(Audit audit) => audit.Checks
        .Where(c => c.Required && c.Status != "PASS")
        .Select(c => c.Name + ": " + c.Status).ToArray();

    // This release has no qualified process-tree network isolation backend.
    // Job membership controls lifetime, not network permissions.
    internal static string? LaunchRejection(Audit audit)
    {
        var failures = Reject(audit);
        return failures.Length != 0
            ? "Preflight refused: " + string.Join("; ", failures)
            : "No qualified process-tree network isolation backend. Launch remains blocked.";
    }
}
