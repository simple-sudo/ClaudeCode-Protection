using System.Security.Cryptography;

namespace ProtectionLifecycle;

// The original owner holds the reviewed package and all four installed files.
// The fixed worker independently checks the bytes it passes to OpenSSL.
internal sealed class FixedOpenSslHeadTrust
{
    private static readonly DateTimeOffset StartsUtc=new(2026,11,7,22,13,8,TimeSpan.Zero);
    private static readonly DateTimeOffset ExpiresUtc=new(2026,11,15,22,33,8,TimeSpan.Zero);
    private static readonly TimeSpan RequiredRemaining=TimeSpan.FromSeconds(30);
    internal byte[] Root { get; }
    internal IReadOnlyList<byte[]> Crls { get; }

    private FixedOpenSslHeadTrust(byte[] root,byte[][] crls)
    {
        Root=root;
        Crls=Array.AsReadOnly(crls);
    }

    internal static void RequireCurrent(DateTimeOffset now)
    {
        if(now<StartsUtc || now>=ExpiresUtc-RequiredRemaining)
            throw WfpNative.Contract("FixedHeadRevocationEvidenceNotCurrent");
    }

    internal static void AssertOwnedPackage(ReviewedPackage package)
    {
        OpenSslModuleLease.AssertOwnedPackage(package);
        if(package.SchemaVersion!=PackageAssetCatalog.FixedHeadTrustSchema ||
            PackageAssetCatalog.FixedHeadTrustAssets.Any(spec=>!package.Files.Any(
                file=>file.Asset==spec && spec.Matches(file.Length,file.SHA256))))
            throw WfpNative.Contract("FixedHeadRequiresExactInstalledTrustAssets");
        RequireCurrent(DateTimeOffset.UtcNow);
    }

    internal static FixedOpenSslHeadTrust ForWorker(string release)
        =>Read(OpenSslModuleLease.WorkerDirectory(release),DateTimeOffset.UtcNow);

    internal static FixedOpenSslHeadTrust Read(string directory,DateTimeOffset now)
    {
        RequireCurrent(now);
        var assets=PackageAssetCatalog.FixedHeadTrustAssets;
        var root=ReadAsset(assets.Single(a=>a.Id==PackageAssetCatalog.HeadRootId),directory);
        var crls=assets.Where(a=>a.Id!=PackageAssetCatalog.HeadRootId).Select(a=>ReadAsset(a,directory)).ToArray();
        return new(root,crls);
    }

    private static byte[] ReadAsset(AssetSpec asset,string directory)
    {
        var length=checked((int)(asset.FixedLength??throw new InvalidDataException("Fixed trust length missing")));
        var path=Path.Combine(directory,Path.GetFileName(asset.Path));
        using var held=File.Open(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(held.Length!=length)throw new InvalidDataException("Installed fixed trust length differs");
        var bytes=new byte[length];
        held.ReadExactly(bytes);
        if(!asset.Matches(length,Convert.ToHexString(SHA256.HashData(bytes))))
            throw new InvalidDataException("Installed fixed trust digest differs");
        return bytes;
    }
}
