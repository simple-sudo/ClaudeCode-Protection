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
    internal const int OpenSslWindowsEntropySchema=3;
    internal const int FixedHeadTrustSchema=4;
    internal const string OpenSslWindowsCryptoId="broker-openssl-windows-crypto",OpenSslWindowsLibraryId="broker-openssl-windows-ssl";
    internal const string HeadRootId="broker-fixed-head-root",HeadLeafCrlId="broker-fixed-head-leaf-crl",
        HeadIssuerCrlId="broker-fixed-head-issuer-crl",HeadRootCrlId="broker-fixed-head-root-crl";
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
    private static readonly IReadOnlyList<AssetSpec> WindowsEntropyModules=Array.AsReadOnly(new[] {
        new AssetSpec(OpenSslWindowsCryptoId,"bin/admin/libcrypto-3-x64.dll") {
            VerifyBeforeElevation=true,FixedLength=5476352,FixedSHA256="9E7EF27C8F8CD5AD816BD916213F26A8D6D9B3F190EEF24412975A910F20995D"
        },
        new AssetSpec(OpenSslWindowsLibraryId,"bin/admin/libssl-3-x64.dll") {
            VerifyBeforeElevation=true,FixedLength=1412096,FixedSHA256="55F6A6F6E88423DE07E59C641357420F8174EC431674C9678422BBFB2CA39A20"
        }
    });
    private static readonly IReadOnlyList<AssetSpec> WithWindowsEntropy=Array.AsReadOnly(Catalog.Concat(WindowsEntropyModules).ToArray());
    internal static readonly IReadOnlyList<AssetSpec> FixedHeadTrustAssets=Array.AsReadOnly(new[] {
        new AssetSpec(HeadRootId,"bin/admin/digicert-root.der") {
            VerifyBeforeElevation=true,FixedLength=914,FixedSHA256="CB3CCBB76031E5E0138F8DD39A23F9DE47FFC35E43C1144CEA27D46A5AB1CB5F"
        },
        new AssetSpec(HeadLeafCrlId,"bin/admin/microsoft-leaf-list.crl") {
            VerifyBeforeElevation=true,FixedLength=34768,FixedSHA256="2019420D136F8781274551A56C89A1F6A608163D71D2432B9F118367EBA1BF50"
        },
        new AssetSpec(HeadIssuerCrlId,"bin/admin/microsoft-issuer-list.crl") {
            VerifyBeforeElevation=true,FixedLength=1032,FixedSHA256="A809A98B205F19E3732FDC4365B739E2648AC4BB6972899C05578727329F4836"
        },
        new AssetSpec(HeadRootCrlId,"bin/admin/digicert-root-list.crl") {
            VerifyBeforeElevation=true,FixedLength=2102,FixedSHA256="D596D979A40B291B906DDD62E083AF21EAEED34A6BB9C744CF563E9E2E1CBA0B"
        }
    });
    private static readonly IReadOnlyList<AssetSpec> WithFixedHeadTrust=Array.AsReadOnly(WithWindowsEntropy.Concat(FixedHeadTrustAssets).ToArray());
    internal static IReadOnlyList<AssetSpec> ForSchema(int schema)=>schema switch {
        1=>Catalog,2=>WithOfflineOpenSsl,OpenSslWindowsEntropySchema=>WithWindowsEntropy,FixedHeadTrustSchema=>WithFixedHeadTrust,
        _=>throw new InvalidDataException("Unknown installed package schema")
    };
    // Map a previously authorized role to a path. Release authorization
    // always uses the exact inventory selected by ForSchema.
    internal static IReadOnlyList<AssetSpec> KnownAssets {get;}=Array.AsReadOnly(WithOfflineOpenSsl.Concat(WindowsEntropyModules).Concat(FixedHeadTrustAssets).ToArray());
}
