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
        var original = File.ReadAllBytes(path);
        _ = Merge(original); // Validate without writing anything.
        return new { mode = "PLAN_ONLY", sha256 = Hash(original), fields = Expected.Keys,
            action = "Explicit repair creates a private byte-for-byte backup, then replaces only the three proxy fields in parsed JSON. Unrelated properties are retained. No credentials are printed." };
    }

    internal static string Apply(string path, string expectedHash, string backupRoot)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Reparse settings path refused");
        var original = File.ReadAllBytes(path);
        if (Hash(original) != expectedHash) throw new InvalidOperationException("Settings changed since review; refusing repair");
        var replacement = Merge(original);
        var existing = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(original).TrimStart('\ufeff'));
        var merged = JsonNode.Parse(replacement);
        if (JsonNode.DeepEquals(existing, merged)) return "UNCHANGED";
        return Replace(path, expectedHash, replacement, backupRoot);
    }

    internal static string Restore(string path, string backup, string backupRoot)
    {
        if ((File.GetAttributes(backup) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Reparse backup refused");
        var receipt = JsonSerializer.Deserialize<Receipt>(File.ReadAllText(backup + ".receipt.json"), Files.Json) ?? throw new InvalidDataException("Missing repair receipt");
        var original = File.ReadAllBytes(backup);
        if (receipt.SchemaVersion != 1 || !string.Equals(Path.GetFullPath(path), receipt.Target, StringComparison.OrdinalIgnoreCase) || Hash(original) != receipt.BeforeHash) throw new InvalidDataException("Repair receipt or backup differs");
        // A user edit after repair must not be replaced by an older full snapshot.
        if (Hash(File.ReadAllBytes(path)) != receipt.AfterHash) throw new InvalidOperationException("Settings edited after repair; automatic restore refused");
        return Replace(path, receipt.AfterHash, original, backupRoot);
    }

    private static string Replace(string path, string expectedHash, byte[] replacement, string backupRoot)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Reparse settings path refused");
        var original = File.ReadAllBytes(path);
        if (Hash(original) != expectedHash) throw new InvalidOperationException("Settings changed before replacement");
        PrivateDirectory(backupRoot);
        var backup = Path.Combine(backupRoot, "settings-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllBytes(backup, original);
        if (Hash(File.ReadAllBytes(backup)) != expectedHash) throw new IOException("Backup verification failed");
        File.WriteAllText(backup + ".receipt.json", JsonSerializer.Serialize(new Receipt(1, Path.GetFullPath(path), expectedHash, Hash(replacement), DateTime.UtcNow.ToString("o")), Files.Json));
        var temporary = path + ".ClaudeProtection-" + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllBytes(temporary, replacement);
            // Preserve the target's access permissions; backup is independently private.
            new FileInfo(temporary).SetAccessControl(new FileInfo(path).GetAccessControl());
            if (Hash(File.ReadAllBytes(path)) != expectedHash) throw new InvalidOperationException("Concurrent edit detected; refusing repair");
            // Atomic replacement prevents partial JSON. The hash check is optimistic,
            // not a system-wide CAS against editors replacing the file concurrently.
            File.Replace(temporary, path, null);
            if (Hash(File.ReadAllBytes(path)) != Hash(replacement)) throw new IOException("Replacement verification failed; private backup retained");
            return backup;
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    internal static void PrivateDirectory(string directory)
    {
        Directory.CreateDirectory(directory);
        if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Reparse backup directory refused");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        var user = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("Missing user SID");
        foreach (var sid in new[] { user, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(directory).SetAccessControl(security);
    }
}
