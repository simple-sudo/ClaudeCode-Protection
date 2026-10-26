using System.Text.Json;

namespace ClaudeProtection;

// Daily maintenance only. Engineering workers, Job control, AppContainer setup
// and fault injection are absent from this project's explicit Compile list.
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
                    if (args.Length > 2 || (args.Length == 2 && args[1] != "--online")) return 64;
                    var audit = await EnvironmentAudit.Run(Environment.CurrentDirectory, args.Contains("--online"));
                    Console.WriteLine(JsonSerializer.Serialize(audit, Files.Json));
                    return Gate.Reject(audit).Length == 0 ? 0 : 2;
                case "launch":
                    Console.Error.WriteLine("DEFERRED_BY_USER: Real Claude launch remains unavailable; protection and lifecycle qualification are incomplete.");
                    return 125;
                case "repair-proxy-plan":
                    if (args.Length != 1) return 64;
                    Storage.UserDataPaths.AssertUserContext();
                    Console.WriteLine(JsonSerializer.Serialize(ProxySettings.Plan(SettingsPath), Files.Json));
                    return 0;
                case "repair-proxy":
                    if (args.Length != 2 || !System.Text.RegularExpressions.Regex.IsMatch(args[1], "^[A-Fa-f0-9]{64}$")) return 64;
                    var backupRoot = Storage.UserDataPaths.ProxyBackups;
                    var backup = ProxySettings.Apply(SettingsPath, args[1].ToUpperInvariant(), backupRoot);
                    if (backup != "UNCHANGED") Storage.UserDataPaths.PublishLatestBackup(Path.GetFileName(backup));
                    Console.WriteLine(JsonSerializer.Serialize(new { status = backup == "UNCHANGED" ? "UNCHANGED" : "REPAIRED", backup = backup == "UNCHANGED" ? null : backup, systemProxyModified = false }, Files.Json));
                    return 0;
                case "restore-proxy":
                    if (args.Length != 1) return 64;
                    var restoreRoot = Storage.UserDataPaths.ProxyBackups;
                    var pointer = Path.Combine(restoreRoot, "latest-repair.json");
                    byte[] pointerBytes;
                    try { pointerBytes=File.ReadAllBytes(pointer); }
                    catch(FileNotFoundException) { Console.WriteLine("{\"status\":\"NO_CURRENT_USER_BACKUP\",\"legacyBackupsMigrated\":false}");return 0; }
                    using (var document = JsonDocument.Parse(pointerBytes))
                    {
                        var name = document.RootElement.GetProperty("backup").GetString() ?? "";
                        if (!System.Text.RegularExpressions.Regex.IsMatch(name, "^settings-[a-f0-9]{32}\\.json$")) throw new InvalidDataException("Invalid backup identifier");
                        var reverse = ProxySettings.Restore(SettingsPath, Path.Combine(restoreRoot, name), restoreRoot);
                        Console.WriteLine(JsonSerializer.Serialize(new { status = "RESTORED", reverseBackup = reverse, systemProxyModified = false }, Files.Json));
                    }
                    return 0;
                case "system-proxy-baseline":
                    if (args.Length != 1) return 64;
                    Console.WriteLine(JsonSerializer.Serialize(UserProxyBaseline.Read(), Files.Json)); return 0;
                case "process-identity":
                    if (args.Length != 2 || !uint.TryParse(args[1], out var pid)) return 64;
                    Console.WriteLine(JsonSerializer.Serialize(ProcessIdentity.Read(pid), Files.Json)); return 0;
                case "transport":
                    if (args.Length != 1) return 64;
                    var transport = await EnvironmentAudit.Transport("claude-api-transport", "https://api.anthropic.com/v1/models", false);
                    Console.WriteLine(JsonSerializer.Serialize(transport, Files.Json));
                    return transport.Status == "PASS" ? 0 : 2;
                default:
                    Console.WriteLine("ClaudeProtection daily | audit [--online] | system-proxy-baseline | process-identity PID | transport | repair-proxy-plan | repair-proxy SHA256 | restore-proxy");
                    Console.WriteLine("Real Claude launch is deferred. Engineering commands are excluded from this build.");
                    return args.Length == 0 ? 0 : 64;
            }
        }
        catch (Exception ex)
        {
            // Never print arguments, credentials, response bodies or environment values.
            var code = ex is System.ComponentModel.Win32Exception native ? native.NativeErrorCode : ex.HResult;
            Console.Error.WriteLine("Operation failed: " + ex.GetType().Name + "; code=" + code + "; stage=" + ex.Data["Stage"]);
            return 125;
        }
    }
    private static string SettingsPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".claude", "settings.json");
}
