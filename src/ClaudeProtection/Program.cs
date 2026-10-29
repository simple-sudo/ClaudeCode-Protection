using System.Text.Json;
using ClaudeCodeProtection.Workspaces;

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
                case "workspace-process":
                    if(args.Length!=3)return 64;
                    Console.WriteLine(JsonSerializer.Serialize(await WorkspaceProcessing.Run(args[1],args[2])));
                    return 0;
                case "workspace-pack":
                    if(args.Length!=4)return 64;
                    WorkspaceFiles.RequireOrdinaryUser();
                    var bundle=WorkspaceFiles.Capture(args[1],WorkspaceFiles.ReadSelection(args[2]));
                    WorkspaceFiles.WriteBundleNew(args[3],bundle);
                    Console.WriteLine(JsonSerializer.Serialize(new {Status="WORKSPACE_DATA_PACKED",SHA256=WorkspaceBundle.Hash(bundle),
                        FileCount=WorkspaceBundle.Parse(bundle).Files.Length,AdmissionIssued=false,HostAclChanged=false,CodeExecuted=false}));
                    return 0;
                case "workspace-review":
                    if(args.Length!=3)return 64;
                    WorkspaceFiles.RequireOrdinaryUser();
                    var baseline=WorkspaceFiles.ReadBundle(args[1]);var result=WorkspaceFiles.ReadBundle(args[2]);
                    var changes=WorkspaceBundle.Compare(baseline,result);
                    Console.WriteLine(JsonSerializer.Serialize(new {Status="WORKSPACE_RESULT_COMPARED",BaseSHA256=WorkspaceBundle.Hash(baseline),
                        ResultSHA256=WorkspaceBundle.Hash(result),Changes=changes,HostFilesModified=false,AdmissionIssued=false}));
                    return 0;
                case "workspace-extract":
                    if(args.Length!=4)return 64;
                    WorkspaceFiles.RequireOrdinaryUser();
                    var extractBase=WorkspaceFiles.ReadBundle(args[1]);var extractResult=WorkspaceFiles.ReadBundle(args[2]);
                    WorkspaceFiles.ExtractResultNew(args[3],extractBase,extractResult);
                    Console.WriteLine(JsonSerializer.Serialize(new {Status="WORKSPACE_RESULT_EXTRACTED_TO_NEW_DIRECTORY",
                        ResultSHA256=WorkspaceBundle.Hash(extractResult),Files=WorkspaceBundle.Parse(extractResult).Files.Length,OriginalProjectModified=false,CodeExecuted=false}));
                    return 0;
                case "audit":
                    if (args.Length > 2 || (args.Length == 2 && args[1] != "--online")) return 64;
                    var audit = await EnvironmentAudit.Run(Environment.CurrentDirectory, args.Contains("--online"));
                    Console.WriteLine(JsonSerializer.Serialize(audit, Files.Json));
                    return Gate.Reject(audit).Length == 0 ? 0 : 2;
                case "preflight":
                    if (args.Length > 2 || (args.Length == 2 && args[1] != "--online")) return 64;
                    var observed = await EnvironmentAudit.Run(Environment.CurrentDirectory, args.Contains("--online"));
                    Console.WriteLine(JsonSerializer.Serialize(StrictPreflight.Evaluate(observed, DateTimeOffset.UtcNow), Files.Json));
                    // A read-only user audit cannot authorize protected launch.
                    return 2;
                case "launch":
                    if(args.Length!=1)return 64;
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
                    return WriteMaintenance(ProxySettings.Apply(SettingsPath, args[1].ToUpperInvariant(), backupRoot));
                case "restore-proxy":
                    if (args.Length != 1) return 64;
                    var restoreRoot = Storage.UserDataPaths.ProxyBackups;
                    return WriteMaintenance(ProxySettings.RestoreLatest(SettingsPath, restoreRoot));
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
                    Console.WriteLine("ClaudeProtection daily | audit [--online] | preflight [--online] | system-proxy-baseline | process-identity PID | transport | repair-proxy-plan | repair-proxy SHA256 | restore-proxy");
                    Console.WriteLine("Real Claude launch is deferred. Engineering commands are excluded from this build.");
                    Console.WriteLine("workspace-pack ROOT SELECTION_JSON NEW_BUNDLE | workspace-review BASE_BUNDLE RESULT_BUNDLE (data transfer only; no launch or host writeback)");
                    Console.WriteLine("workspace-extract BASE_BUNDLE RESULT_BUNDLE NEW_DIRECTORY (new files only; no merge or overwrite)");
                    Console.WriteLine("workspace-process BASE_BUNDLE NEW_RESULT_BUNDLE (installed Broker, human UAC; fixed offline Git data processing only)");
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
    private static int WriteMaintenance(ProxySettings.Result result)
    {
        Console.WriteLine(JsonSerializer.Serialize(new { status = result.Status, backup = result.Backup,
            recoveryRequired = result.RecoveryRequired, settingsMayHaveChanged = result.SettingsMayHaveChanged,
            errorType = result.ErrorType, systemProxyModified = false, legacyBackupsMigrated = false }, Files.Json));
        return result.RecoveryRequired ? 3 : result.Status.StartsWith("REFUSED_", StringComparison.Ordinal) ? 2 : 0;
    }
    private static string SettingsPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".claude", "settings.json");
}
