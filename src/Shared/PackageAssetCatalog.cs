namespace ProtectionLifecycle;

// Data-only v1 package inventory shared with the unprivileged installed client.
// Installer approval, hashing and privileged operations stay with their owners.
internal sealed record AssetSpec(string Id, string Path)
{
    internal bool VerifyBeforeElevation {get;init;}
}
internal static class PackageAssetCatalog
{
    internal const int MaxManifestBytes = 64 * 1024;
    internal const long MaxAssetBytes = 128L * 1024 * 1024;
    internal static readonly IReadOnlyList<AssetSpec> Catalog = Array.AsReadOnly(new[] {
        new AssetSpec("daily-exe", "bin/current/ClaudeProtection.exe") {VerifyBeforeElevation=true},
        new AssetSpec("daily-dll", "bin/current/ClaudeProtection.dll") {VerifyBeforeElevation=true},
        new AssetSpec("daily-deps", "bin/current/ClaudeProtection.deps.json") {VerifyBeforeElevation=true},
        new AssetSpec("daily-runtime", "bin/current/ClaudeProtection.runtimeconfig.json") {VerifyBeforeElevation=true},
        new AssetSpec("daily-reader", "bin/current/Read-Environment.ps1"),
        new AssetSpec("center-exe", "bin/center/ProtectionCenter.exe"),
        new AssetSpec("center-dll", "bin/center/ProtectionCenter.dll"),
        new AssetSpec("center-deps", "bin/center/ProtectionCenter.deps.json"),
        new AssetSpec("center-runtime", "bin/center/ProtectionCenter.runtimeconfig.json"),
        new AssetSpec("broker-exe", "bin/admin/ProtectionBroker.exe") {VerifyBeforeElevation=true},
        new AssetSpec("broker-dll", "bin/admin/ProtectionBroker.dll") {VerifyBeforeElevation=true},
        new AssetSpec("broker-deps", "bin/admin/ProtectionBroker.deps.json") {VerifyBeforeElevation=true},
        new AssetSpec("broker-runtime", "bin/admin/ProtectionBroker.runtimeconfig.json") {VerifyBeforeElevation=true},
        new AssetSpec("broker-lifecycle", "bin/admin/ProtectionLifecycle.dll") {VerifyBeforeElevation=true}
    });
}
