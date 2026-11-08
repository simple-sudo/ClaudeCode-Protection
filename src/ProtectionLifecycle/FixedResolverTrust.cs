using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace ProtectionLifecycle;

internal sealed class FixedResolverTrust
{
    private const string IntermediateSHA256="948B7111AF42F546D579CFF5CE2BDEC82134DD9914842BDDB0C52872EB604E39";
    private static readonly DateTimeOffset StartsUtc=new(2026,11,8,1,10,0,TimeSpan.Zero);
    private static readonly DateTimeOffset ExpiresUtc=new(2026,11,15,1,9,59,TimeSpan.Zero);
    private static readonly AssetSpec RootAsset=PackageAssetCatalog.FixedResolverTrustAssets.Single(a=>a.Id==PackageAssetCatalog.ResolverRootId);
    private readonly byte[] root;
    private readonly byte[][] crls;
    private readonly string release;

    private FixedResolverTrust(string release,byte[] root,byte[][] crls)
    {
        this.release=release;
        this.root=root;
        this.crls=crls;
    }

    internal static void RequireCurrent(DateTimeOffset now)
    {
        if(now<StartsUtc || now>=ExpiresUtc-TimeSpan.FromSeconds(30))
            throw WfpNative.Contract("FixedResolverRevocationEvidenceNotCurrent");
    }

    internal static FixedResolverTrust ReadOwned(ReviewedPackage package)
    {
        FixedOpenSslHeadTrust.AssertOwnedPackage(package);
        if(package.SchemaVersion!=PackageAssetCatalog.FixedResolverTrustSchema ||
            PackageAssetCatalog.FixedResolverTrustAssets.Any(spec=>!package.Files.Any(
                file=>file.Asset==spec && spec.Matches(file.Length,file.SHA256))))
            throw WfpNative.Contract("FixedResolverRequiresExactInstalledTrustAssets");
        return Read(OpenSslModuleLease.WorkerDirectory(package.Release),package.Release,DateTimeOffset.UtcNow);
    }

    internal static FixedResolverTrust Read(string directory,string release,DateTimeOffset now)
    {
        RequireCurrent(now);
        var root=FixedOpenSslHeadTrust.ReadAsset(RootAsset,directory);
        var crls=PackageAssetCatalog.FixedResolverTrustAssets.Where(a=>a!=RootAsset)
            .Select(a=>FixedOpenSslHeadTrust.ReadAsset(a,directory)).ToArray();
        return new(release,root,crls);
    }

    internal OpenSslModuleLease OpenModules()=>OpenSslModuleLease.OpenForInstalledWorker(release);

    internal bool Verify(OpenSslModuleLease modules,ResolverTlsEvidence evidence,X509Certificate? certificate,X509Chain? chain)
    {
        RequireCurrent(DateTimeOffset.UtcNow);
        if(!AcceptsPlatformChain(evidence) || certificate is null || chain?.ChainElements.Count!=3)return false;
        var leaf=chain.ChainElements[0].Certificate.RawData;
        return leaf.AsSpan().SequenceEqual(certificate.GetRawCertData()) && OpenSslOfflineChain.Verify(modules,
            ResolverTlsEvidence.Host,root,leaf,chain.ChainElements[1].Certificate.RawData,crls);
    }

    internal static bool AcceptsPlatformChain(ResolverTlsEvidence evidence)
    {
        if(!evidence.ExpectedHost || !evidence.CertificatePresent || !evidence.ChainPresent ||
            evidence.ChainCertificateSHA256 is not [_,IntermediateSHA256,var rootHash] || rootHash!=RootAsset.FixedSHA256)
            return false;
        if(evidence.PolicyErrors==(int)SslPolicyErrors.None)
            return evidence.ChainStatus.All(status=>status==0);
        const int offline=(int)(X509ChainStatusFlags.RevocationStatusUnknown|X509ChainStatusFlags.OfflineRevocation);
        return evidence.PolicyErrors==(int)SslPolicyErrors.RemoteCertificateChainErrors &&
            evidence.ChainStatus.Any(status=>status!=0) && evidence.ChainStatus.All(status=>(status&~offline)==0);
    }
}
