using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ProtectionLifecycle;

// Original owner only. Raw certificates and callback details cannot become a
// permit, and only bounded digests and native policy codes enter the receipt.
internal sealed record ResolverTlsEvidence(bool ExpectedHost,bool CertificatePresent,bool ChainPresent,int PolicyErrors,
    int[] ChainStatus,string[] ChainCertificateSHA256,bool Accepted)
{
    internal const string Host="cloudflare-dns.com";
    internal static ResolverTlsEvidence Observe(string? host,X509Certificate? certificate,X509Chain? chain,SslPolicyErrors errors)
    {
        var expectedHost=string.Equals(host,Host,StringComparison.Ordinal);
        var chainCount=chain?.ChainElements.Count??0;
        var status=chain?.ChainStatus;
        if(chainCount>8 || status is {Length:>16})
            return new(expectedHost,certificate is not null,chain is not null,(int)errors,[],[],false);
        var statusCodes=status?.Select(item=>(int)item.Status).ToArray()??[];
        var digests=chain?.ChainElements.Select(element=>
            Convert.ToHexString(SHA256.HashData(element.Certificate.RawData))).ToArray()??[];
        var accepted=expectedHost && chainCount>0 && ProxyChannelLease.AcceptObservedTls(
            new((int)errors,statusCodes,certificate is not null,chain is not null));
        return new(expectedHost,certificate is not null,chain is not null,(int)errors,statusCodes,digests,accepted);
    }
}
