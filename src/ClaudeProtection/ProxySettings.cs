using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ClaudeProtection;

// Repairs only three explicitly owned proxy fields. No authentication migration.
// Callers must stop an active session first and explicitly request this operation.
internal static class ProxySettings
{
    private sealed record Receipt(int SchemaVersion, string Target, string BeforeHash, string AfterHash, string AtUtc);
    private sealed record Pointer(string Backup);
    internal sealed record Result(string Status, string? Backup = null, bool RecoveryRequired = false,
        bool SettingsMayHaveChanged = false, string? ErrorType = null);
    internal static readonly Dictionary<string, string> Expected = new(StringComparer.OrdinalIgnoreCase)
    {
        ["HTTP_PROXY"] = "http://127.0.0.1:7890",
        ["HTTPS_PROXY"] = "http://127.0.0.1:7890",
        ["NO_PROXY"] = "localhost,127.0.0.1,::1"
    };

    internal static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    internal static byte[] Merge(byte[] original)
    {
        var text = System.Text.Encoding.UTF8.GetString(original).TrimStart('\ufeff');
        var node = JsonNode.Parse(text) as JsonObject ?? throw new InvalidDataException("Settings must be a JSON object");
        var environment = node["env"] as JsonObject;
        if (node["env"] is not null && environment is null) throw new InvalidDataException("env must be an object");
        environment ??= new JsonObject();
        // Windows environment names are case-insensitive; preserve unrelated names.
        foreach (var key in environment.Select(p => p.Key).Where(k => Expected.ContainsKey(k)).ToArray())
            environment.Remove(key);
        foreach (var pair in Expected) environment[pair.Key] = pair.Value;
        node["env"] = environment;
        return System.Text.Encoding.UTF8.GetBytes(node.ToJsonString(Files.Json) + Environment.NewLine);
    }

    internal static object Plan(string path)
    {
        var original = ReadChecked(path);
        _ = Merge(original); // Validate without writing anything.
        return new { mode = "PLAN_ONLY", sha256 = Hash(original), fields = Expected.Keys,
            action = "Explicit repair creates a private byte-for-byte backup, then replaces only the three proxy fields in parsed JSON. Unrelated properties are retained. No credentials are printed." };
    }

    internal static Result Apply(string path, string expectedHash, string backupRoot)
    {
        using var maintenance = Lock(backupRoot);
        var recovery = RecoverPending(path, backupRoot);
        if (recovery is not null) return recovery;
        var original = ReadChecked(path);
        if (Hash(original) != expectedHash) return new("REFUSED_STALE_PLAN");
        var replacement = Merge(original);
        var existing = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(original).TrimStart('\ufeff'));
        var merged = JsonNode.Parse(replacement);
        if (JsonNode.DeepEquals(existing, merged)) return new("UNCHANGED");
        return Replace(path, expectedHash, replacement, backupRoot);
    }

    internal static Result RestoreLatest(string path, string backupRoot)
    {
        using var maintenance = Lock(backupRoot);
        var recovery = RecoverPending(path, backupRoot);
        if (recovery is not null) return recovery;
        var pointer = Path.Combine(backupRoot, "latest-repair.json");
        string name;
        try { name = ReadPointer(pointer); }
        catch (FileNotFoundException) { return new("NO_CURRENT_USER_BACKUP"); }
        var (receipt, original) = ReadBackup(path, backupRoot, name);
        // A user edit after repair must not be replaced by an older full snapshot.
        if (Hash(ReadChecked(path)) != receipt.AfterHash) return new("REFUSED_LATER_EDIT");
        return Replace(path, receipt.AfterHash, original, backupRoot);
    }

    private static Result Replace(string path, string expectedHash, byte[] replacement, string backupRoot)
    {
        if (replacement.Length > 8 * 1024 * 1024) throw new InvalidDataException("Replacement exceeds maintenance size limit");
        var original = ReadChecked(path);
        if (Hash(original) != expectedHash) return new("REFUSED_CONCURRENT_EDIT");
        var backup = Path.Combine(backupRoot, "settings-" + Guid.NewGuid().ToString("N") + ".json");
        WriteNew(backup, original);
        if (Hash(ReadChecked(backup)) != expectedHash) throw new IOException("Backup verification failed");
        WriteNew(backup + ".receipt.json", JsonSerializer.SerializeToUtf8Bytes(new Receipt(1, Path.GetFullPath(path), expectedHash, Hash(replacement), DateTime.UtcNow.ToString("o")), Files.Json));
        // Fixed derivation lets a stopped operation retain its replacement bytes
        // without accepting an arbitrary recovery path from JSON.
        var temporary = path + ".ClaudeProtection-" + Path.GetFileNameWithoutExtension(backup) + ".tmp";
        // Apply the target DACL at creation, before any settings/credentials are written.
        var security = new FileInfo(path).GetAccessControl();
        using (var output = new FileInfo(temporary).Create(FileMode.CreateNew, FileSystemRights.Read | FileSystemRights.Write,
            FileShare.None, 4096, FileOptions.WriteThrough, security))
        { output.Write(replacement); output.Flush(true); }
        PublishPointer(backupRoot, "pending-repair.json", Path.GetFileName(backup));
        try
        {
            if (Hash(ReadChecked(path)) != expectedHash) throw new InvalidOperationException("Concurrent edit detected; refusing repair");
            // Atomic replacement prevents partial JSON. The hash check is optimistic,
            // not a system-wide CAS against editors replacing the file concurrently.
            File.Replace(temporary, path, null);
            if (Hash(ReadChecked(path)) != Hash(replacement)) throw new IOException("Replacement verification failed; private backup retained");
            PublishPointer(backupRoot, "latest-repair.json", Path.GetFileName(backup));
            File.Delete(Path.Combine(backupRoot, "pending-repair.json"));
            return new("APPLIED", backup, SettingsMayHaveChanged: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            // ReplaceFile failures do not all leave the original names intact.
            // Never remove the temporary or claim the settings were unchanged.
            return new("RECOVERY_REQUIRED", backup, true, true, ex.GetType().Name);
        }
    }

    private static Result? RecoverPending(string path, string backupRoot)
    {
        var pending = Path.Combine(backupRoot, "pending-repair.json");
        string name;
        try { name = ReadPointer(pending); }
        catch (FileNotFoundException) { return null; }
        try
        {
            var (receipt, _) = ReadBackup(path, backupRoot, name);
            var current = Hash(ReadChecked(path));
            if (current == receipt.AfterHash)
                PublishPointer(backupRoot, "latest-repair.json", name);
            else if (current != receipt.BeforeHash)
                return new("RECOVERY_CONFLICT", Path.Combine(backupRoot, name), true, true);
            File.Delete(pending);
            // End this request after reconciliation: a second click/command is
            // deliberate, so an undo cannot silently consume the wrong operation.
            return new(current == receipt.AfterHash ? "RECOVERED_APPLIED" : "RECOVERED_NOT_APPLIED", Path.Combine(backupRoot, name),
                SettingsMayHaveChanged: current == receipt.AfterHash);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or JsonException)
        { return new("RECOVERY_REQUIRED", Path.Combine(backupRoot, name), true, true, ex.GetType().Name); }
    }

    private static (Receipt Receipt, byte[] Original) ReadBackup(string path, string root, string name)
    {
        AssertBackupName(name);
        var backup = Path.Combine(root, name);
        var receipt = JsonSerializer.Deserialize<Receipt>(ReadChecked(backup + ".receipt.json", 16384), Files.Json)
            ?? throw new InvalidDataException("Missing repair receipt");
        var original = ReadChecked(backup);
        if (receipt.SchemaVersion != 1 || !string.Equals(Path.GetFullPath(path), receipt.Target, StringComparison.OrdinalIgnoreCase) ||
            !IsHash(receipt.BeforeHash) || !IsHash(receipt.AfterHash) || Hash(original) != receipt.BeforeHash || receipt.BeforeHash == receipt.AfterHash)
            throw new InvalidDataException("Repair receipt or backup differs");
        return (receipt, original);
    }
    private static string ReadPointer(string path)
    {
        var pointer = JsonSerializer.Deserialize<Pointer>(ReadChecked(path, 4096), Files.Json)
            ?? throw new InvalidDataException("Missing backup identifier");
        AssertBackupName(pointer.Backup); return pointer.Backup;
    }
    private static void AssertBackupName(string name)
    {
        if (name is null || !System.Text.RegularExpressions.Regex.IsMatch(name, "\\Asettings-[a-f0-9]{32}\\.json\\z"))
            throw new InvalidDataException("Invalid backup identifier");
    }
    private static bool IsHash(string value) => value is not null && System.Text.RegularExpressions.Regex.IsMatch(value, "\\A[A-F0-9]{64}\\z");
    private static void PublishPointer(string root, string leaf, string name)
    {
        AssertBackupName(name);
        var destination = Path.Combine(root, leaf);
        AssertPlainPath(destination, true);
        var temporary = Path.Combine(root, "pointer-" + Guid.NewGuid().ToString("N") + ".tmp");
        WriteNew(temporary, JsonSerializer.SerializeToUtf8Bytes(new Pointer(name), Files.Json));
        File.Move(temporary, destination, true); // Failed publication preserves the file.
    }
    private static FileStream Lock(string root)
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (identity.User is null || identity.User.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
            new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new InvalidOperationException("Configuration maintenance requires ordinary user context");
        AssertPlainPath(root);
        var path = Path.Combine(root, "maintenance.lock");
        AssertPlainPath(path, true);
        // Persistent empty lock file: never unlink a held lock or use PID liveness.
        return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }
    private static byte[] ReadChecked(string path, int limit = 8 * 1024 * 1024)
    {
        AssertPlainPath(path);
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length > limit) throw new InvalidDataException("Maintenance file exceeds size limit");
        var bytes = new byte[checked((int)input.Length)]; input.ReadExactly(bytes); return bytes;
    }
    private static void WriteNew(string path, byte[] bytes)
    {
        AssertPlainPath(path, true);
        using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        output.Write(bytes); output.Flush(true);
    }
    private static void AssertPlainPath(string path, bool allowMissingLeaf = false)
    {
        var full = Path.GetFullPath(path);
        try
        { if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Redirected maintenance path refused"); }
        catch (FileNotFoundException) when (allowMissingLeaf) { }
        for (var parent = Directory.GetParent(full); parent is not null; parent = parent.Parent)
            if ((parent.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Redirected maintenance ancestor refused");
        // These path checks are defense in depth, not a handle-bound security
        // boundary against a malicious process running as the same user.
    }

}
