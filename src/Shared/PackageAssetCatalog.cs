using System.IO;

namespace ProtectionLifecycle;

// Data-only package inventories shared with the unprivileged installed client.
// Installer approval, hashing and privileged operations stay with their owners.
internal sealed record AssetSpec(string Id, string Path)
{
    internal bool VerifyBeforeElevation {get;init;}
    internal long? FixedLength {get;init;}
    internal string? FixedSHA256 {get;init;}
    internal string BinRole=>Path.Split('/')[1];
    internal bool Matches(long length,string? sha256)=>
        FixedLength is long pinned ? length==pinned && sha256==FixedSHA256 :
        length is >=1 and <=PackageAssetCatalog.MaxAssetBytes;
}
internal static class PackageAssetCatalog
{
    internal const int MaxManifestBytes = 64 * 1024;
    internal const long MaxAssetBytes = 128L * 1024 * 1024;
    internal const string OpenSslCryptoId="broker-openssl-crypto",OpenSslLibraryId="broker-openssl-ssl";
    internal const int OpenSslWindowsEntropySchema=3;
    internal const int FixedHeadTrustSchema=4;
    internal const int FixedResolverTrustSchema=5;
    internal const int OfficialClaudeOfflineSchema=6;
    internal const int SessionZeroStartupWitnessSchema=7;
    internal const int SessionZeroStartupDiagnosticsSchema=8;
    internal const int SessionZeroStartupBranchSchema=9;
    internal const int SessionZeroWindowAccessSchema=10;
    internal const int SessionZeroPrivateWindowSchema=11;
    internal const int SessionZeroPrivateWindowTraceSchema=12;
    internal const int SessionZeroPrivateWindowReadControlSchema=13;
    internal const int SessionZeroPrivateWindowConsoleSchema=14;
    internal const int SessionZeroIdentitySurveySchema=15;
    internal const int SessionZeroNetworkSurveySchema=16;
    internal const int ReviewedProxyRouteSchema=17;
    internal const int SessionZeroGitInitSchema=18;
    internal const int SessionZeroCudaSchema=19;
    internal const int SessionZeroCudaSplitInitSchema=20;
    internal const int SessionZeroCudaAccessTraceSchema=21;
    internal const int SessionZeroCudaMappedFaultSchema=22;
    internal const int SessionZeroCudaWddmSchema=23;
    internal const int SessionZeroCudaWddmSelfHandleSchema=24;
    internal const int SessionZeroCudaDeferredPreloadSchema=25;
    internal const int SessionZeroCudaInitializationTraceSchema=26;
    internal const int SessionZeroCudaHelperPathSchema=27;
    internal const int SessionZeroCudaRegistryCallsSchema=28;
    internal const string SessionZeroStartupWitnessId="broker-session-zero-startup-witness";
    internal const string SessionZeroStartupWitnessPath="bin/admin/SessionZeroStartupWitness.exe";
    internal const string OfficialClaudeId="official-claude-offline-exe",OfficialClaudeBinRole="official";
    internal const string OpenSslWindowsCryptoId="broker-openssl-windows-crypto",OpenSslWindowsLibraryId="broker-openssl-windows-ssl";
    internal const string HeadRootId="broker-fixed-head-root",HeadLeafCrlId="broker-fixed-head-leaf-crl",
        HeadIssuerCrlId="broker-fixed-head-issuer-crl",HeadRootCrlId="broker-fixed-head-root-crl";
    internal const string ResolverRootId="broker-fixed-resolver-root",ResolverLeafCrlId="broker-fixed-resolver-leaf-crl",
        ResolverIssuerCrlId="broker-fixed-resolver-issuer-crl";
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
    internal static readonly IReadOnlyList<AssetSpec> FixedResolverTrustAssets=Array.AsReadOnly(new[] {
        new AssetSpec(ResolverRootId,"bin/admin/resolver-root.der") {
            VerifyBeforeElevation=true,FixedLength=657,FixedSHA256="3417BB06CC6007DA1B961C920B8AB4CE3FAD820E4AA30B9ACBC4A74EBDCEBC65"
        },
        new AssetSpec(ResolverLeafCrlId,"bin/admin/resolver-leaf-list.crl") {
            VerifyBeforeElevation=true,FixedLength=815,FixedSHA256="AFF514853E404C6E10A241ACEEE89CE4C03E401DA5C017C2F0711E07C71413D2"
        },
        new AssetSpec(ResolverIssuerCrlId,"bin/admin/resolver-issuer-list.crl") {
            VerifyBeforeElevation=true,FixedLength=1152,FixedSHA256="530474D2F771280FB8C2BE63CE44EAF647DD76A21428D8D6B398A6412287E30C"
        }
    });
    private static readonly IReadOnlyList<AssetSpec> WithFixedResolverTrust=Array.AsReadOnly(WithFixedHeadTrust.Concat(FixedResolverTrustAssets).ToArray());
    // This inventory holds the single reviewed Authenticode image for offline
    // qualification. Package membership does not grant execution.
    internal static readonly AssetSpec OfficialClaudeImage=new(OfficialClaudeId,"bin/"+OfficialClaudeBinRole+"/claude.exe") {
        FixedLength=344807072,FixedSHA256="2E055732C9D03D22700D9046251A8370B673607BFCC9E4D16A1B0E8FB1345CBD"
    };
    private static readonly IReadOnlyList<AssetSpec> WithOfficialClaude=Array.AsReadOnly(WithFixedResolverTrust.Append(OfficialClaudeImage).ToArray());
    private static readonly AssetSpec StartupWitness=new(SessionZeroStartupWitnessId,SessionZeroStartupWitnessPath) {
        VerifyBeforeElevation=true,FixedLength=4096,FixedSHA256="DE7363C3EB6E7D54BF7D3B92DB2268E363B44C2F554DCB2F2894A15D7E796FAF"
    };
    private static readonly IReadOnlyList<AssetSpec> WithStartupWitness=Array.AsReadOnly(WithOfficialClaude.Append(StartupWitness).ToArray());
    private static readonly IReadOnlyList<AssetSpec> WithStartupDiagnostics=Array.AsReadOnly(WithOfficialClaude.Append(StartupWitness with {
        FixedLength=6144,FixedSHA256="7FFE9A92E7D99D655EBE3DB3C181D7CCC25808AA0B84B3AEA8B4E4CEB1DBD876"
    }).ToArray());
    private static readonly IReadOnlyList<AssetSpec> WithStartupBranch=Array.AsReadOnly(WithOfficialClaude.Append(StartupWitness with {
        FixedLength=3584,FixedSHA256="34945838654DAE320E70123B74A0628EA1A4FE889BD4061FEE5813BDECD7DC22"
    }).ToArray());
    private static readonly IReadOnlyList<AssetSpec> WithPrivateWindow=Array.AsReadOnly(WithOfficialClaude.Append(StartupWitness with {
        FixedLength=6656,FixedSHA256="F1C25D9DE733B2EE2D410E4DF5F9A1E467103213162B27305D89A85889C7C8DB"
    }).ToArray());
    private static readonly IReadOnlyList<AssetSpec> WithPrivateWindowTrace=Array.AsReadOnly(WithOfficialClaude.Append(StartupWitness with {
        FixedLength=8192,FixedSHA256="131A7413FB343018DDF2B322BCAB362D92B3605882F0ABA6838DEAA3EF4F4377"
    }).ToArray());
    internal static IReadOnlyList<AssetSpec> ForSchema(int schema)=>schema switch {
        1=>Catalog,2=>WithOfflineOpenSsl,OpenSslWindowsEntropySchema=>WithWindowsEntropy,FixedHeadTrustSchema=>WithFixedHeadTrust,
        FixedResolverTrustSchema=>WithFixedResolverTrust,OfficialClaudeOfflineSchema=>WithOfficialClaude,
        SessionZeroStartupWitnessSchema=>WithStartupWitness,
        SessionZeroStartupDiagnosticsSchema=>WithStartupDiagnostics,
        SessionZeroStartupBranchSchema or SessionZeroWindowAccessSchema=>WithStartupBranch,
        SessionZeroPrivateWindowSchema=>WithPrivateWindow,
        SessionZeroPrivateWindowTraceSchema or SessionZeroPrivateWindowReadControlSchema or SessionZeroPrivateWindowConsoleSchema or
        SessionZeroIdentitySurveySchema or SessionZeroNetworkSurveySchema or ReviewedProxyRouteSchema or SessionZeroGitInitSchema or SessionZeroCudaSchema or SessionZeroCudaSplitInitSchema or SessionZeroCudaAccessTraceSchema or SessionZeroCudaMappedFaultSchema or SessionZeroCudaWddmSchema or SessionZeroCudaWddmSelfHandleSchema or SessionZeroCudaDeferredPreloadSchema or SessionZeroCudaInitializationTraceSchema or SessionZeroCudaHelperPathSchema or SessionZeroCudaRegistryCallsSchema=>WithPrivateWindowTrace,
        _=>throw new InvalidDataException("Unknown installed package schema")
    };
    // Map a previously authorized role to a path. Release authorization
    // always uses the exact inventory selected by ForSchema.
    internal static IReadOnlyList<AssetSpec> KnownAssets {get;}=Array.AsReadOnly(WithOfflineOpenSsl.Concat(WindowsEntropyModules)
        .Concat(FixedHeadTrustAssets).Concat(FixedResolverTrustAssets).Append(OfficialClaudeImage).Append(StartupWitness).ToArray());
    internal static IEnumerable<string> BinRoles(IEnumerable<AssetSpec> assets)=>assets.Select(a=>a.BinRole).Distinct(StringComparer.Ordinal);
}
