using System.IO;

namespace ProtectionLifecycle;

// Data-only package inventories shared with the unprivileged installed client.
// Installer approval, hashing and privileged operations stay with their owners.
internal sealed record AssetSpec(string Id, string Path)
{
    internal bool VerifyBeforeElevation {get;init;}
    internal long? FixedLength {get;init;}
    internal string? FixedSHA256 {get;init;}
    internal bool Matches(long length,string? sha256)=>
        length is >=1 and <=PackageAssetCatalog.MaxAssetBytes &&
        (FixedLength is null || (length==FixedLength && sha256==FixedSHA256));
}
internal static class PackageAssetCatalog
{
    internal const int MaxManifestBytes = 64 * 1024;
    internal const long MaxAssetBytes = 128L * 1024 * 1024;
    internal const string OpenSslCryptoId="broker-openssl-crypto",OpenSslLibraryId="broker-openssl-ssl";
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
    // The only v2 native inputs are OpenSSL 3.5.9 from the PSF 3.14.10 x64 archive.
    private static readonly IReadOnlyList<AssetSpec> WithOfflineOpenSsl=Array.AsReadOnly(Catalog.Concat(new[] {
        new AssetSpec(OpenSslCryptoId,"bin/admin/libcrypto-3.dll") {
            VerifyBeforeElevation=true,FixedLength=6021880,FixedSHA256="75495FE0E079AB00D49BE740D3C710A0B94E3F74F9648CB7CC9F768FC7F52319"
        },
        new AssetSpec(OpenSslLibraryId,"bin/admin/libssl-3.dll") {
            VerifyBeforeElevation=true,FixedLength=1308920,FixedSHA256="8957182A9C385BFD9F3F790921DE2DDC614CF91F99EDBED4E9E5446A46504E32"
        }
    }).ToArray());
    internal static IReadOnlyList<AssetSpec> ForSchema(int schema)=>schema switch {
        1=>Catalog,2=>WithOfflineOpenSsl,_=>throw new InvalidDataException("Unknown installed package schema")
    };
    // Map a previously authorized role to a path. Release authorization
    // always uses the exact inventory selected by ForSchema.
    internal static IReadOnlyList<AssetSpec> KnownAssets=>WithOfflineOpenSsl;
}
