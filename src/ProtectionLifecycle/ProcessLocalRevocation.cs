using System.ComponentModel;
using System.Formats.Asn1;
using System.Net;
using System.Net.Security;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ProtectionLifecycle;

internal sealed record CrlVerification(bool Parsed,bool SignatureValid,bool ScopeValid,int? TimeValidity,bool NotRevoked,
    bool CleanupSucceeded,uint NativeError,string? FailureStage);
internal sealed record SuppliedCrl(string CertificateSHA256,string IssuerSHA256,string Uri,string SHA256,int Bytes,CrlVerification Verification);
internal sealed record RevocationSupply(bool Accepted,SuppliedCrl[] Crls,string? FailureType);

// The original OS name/trust/time/signature validation must have succeeded;
// ONLY offline/unknown revocation may be repaired with independently verified
// CRLs. This fixed Microsoft qualification is not general destination policy.
internal static class ProcessLocalRevocation
{
    private const int MaxCrlBytes=1024*1024;
    private static readonly (string Issuer,string Uri)[] Approved={
        ("AC8EA9F2874FD368A3E778B1A0B165EE898DB9B9687C17EDCDC76908AB58C82C","http://www.microsoft.com/pkiops/crl/partition/Microsoft%20TLS%20G2%20RSA%20CA%20OCSP%2004_Partition00093.crl"),
        ("DDCD1E8A20638D4AAFF7201BB1D56452ACD2C759F1686BDC38F73DD15732BDC2","http://www.microsoft.com/pkiops/crl/Microsoft%20TLS%20RSA%20Root%20G2.crl"),
        ("CB3CCBB76031E5E0138F8DD39A23F9DE47FFC35E43C1144CEA27D46A5AB1CB5F","http://crl3.digicert.com/DigiCertGlobalRootG2.crl")};
    internal static bool Eligible(TlsValidationObservation original)=>original.CertificatePresent && original.ChainPresent &&
        original.PolicyErrors==(int)SslPolicyErrors.RemoteCertificateChainErrors && original.ChainStatus.Length>0 &&
        original.ChainStatus.All(s=>s!=0 && (s&~(64|16777216))==0);
    internal static RevocationSupply Validate(X509Certificate2? peer,X509Chain? chain,TlsValidationObservation original)
    {
        var supplied=new List<SuppliedCrl>();
        try
        {
            if(!Eligible(original) || peer is null || chain is null || chain.ChainElements.Count!=4 ||
                Hash(peer)!=Hash(chain.ChainElements[0].Certificate))throw new InvalidDataException("UnsupportedPeerOrValidationErrors");
            using var handler=new HttpClientHandler{UseProxy=true,Proxy=new WebProxy("http://127.0.0.1:7890"),AllowAutoRedirect=false,
                UseCookies=false,UseDefaultCredentials=false,MaxResponseHeadersLength=8};
            using var client=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(3)};
            for(var index=0;index<3;index++)
            {
                var subject=chain.ChainElements[index].Certificate;var issuer=chain.ChainElements[index+1].Certificate;
                if(Hash(issuer)!=Approved[index].Issuer)throw new InvalidDataException("UnreviewedIssuer");
                var extension=subject.Extensions.SingleOrDefault(e=>e.Oid?.Value=="2.5.29.31")??throw new InvalidDataException("CrlDistributionPointMissing");
                if(!ProxyChannelLease.ReadCrlUris(extension.RawData).Contains(Approved[index].Uri,StringComparer.Ordinal))throw new InvalidDataException("UnreviewedCrlEndpoint");
                // Request the compiled URI, never a supplied or redirected URI.
                var bytes=Retrieve(client,Approved[index].Uri).GetAwaiter().GetResult();
                var result=Verify(subject,issuer,bytes);
                supplied.Add(new(Hash(subject),Hash(issuer),Approved[index].Uri,Convert.ToHexString(SHA256.HashData(bytes)),bytes.Length,result));
                if(!Qualified(result))return new(false,supplied.ToArray(),"CrlValidationFailed");
            }
            return new(true,supplied.ToArray(),null);
        }
        catch(Exception ex) when(ex is HttpRequestException or OperationCanceledException or InvalidDataException or InvalidOperationException or AsnContentException)
        {return new(false,supplied.ToArray(),ex.GetType().Name);}
    }
    private static async Task<byte[]> Retrieve(HttpClient client,string uri)
    {
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(3));
        using var response=await client.GetAsync(uri,HttpCompletionOption.ResponseHeadersRead,timeout.Token);
        if(response.StatusCode!=HttpStatusCode.OK || response.Content.Headers.ContentLength is <1 or >MaxCrlBytes)throw new InvalidDataException("CrlResponseRejected");
        await using var input=await response.Content.ReadAsStreamAsync(timeout.Token);using var output=new MemoryStream();var buffer=new byte[8192];
        int count;while((count=await input.ReadAsync(buffer,timeout.Token))>0){if(output.Length+count>MaxCrlBytes)throw new InvalidDataException("CrlResponseTooLarge");output.Write(buffer,0,count);}
        if(output.Length==0)throw new InvalidDataException("CrlResponseEmpty");return output.ToArray();
    }
    private static string Hash(X509Certificate2 cert)=>Convert.ToHexString(SHA256.HashData(cert.RawData));
    internal static bool Qualified(CrlVerification result)=>result.Parsed && result.SignatureValid && result.ScopeValid && result.TimeValidity==0 &&
        result.NotRevoked && result.CleanupSucceeded && result.NativeError==0 && result.FailureStage is null;
    private static CrlVerification Verify(X509Certificate2 subject,X509Certificate2 issuer,byte[] bytes)
    {
        AssertLayout();IntPtr crl=IntPtr.Zero,store=IntPtr.Zero;bool parsed=false,signature=false,scope=false,notRevoked=false,cleanup=true;
        int? time=null;uint error=0;string? failure=null;string stage="CreateCrlContext";
        try
        {
            if(bytes.Length is <1 or >MaxCrlBytes)throw new InvalidDataException("CrlSize");
            crl=CertCreateCRLContext(1,bytes,checked((uint)bytes.Length));Need(crl!=IntPtr.Zero);parsed=true;
            stage="VerifyCrlIssuerSignature";Need(CryptVerifyCertificateSignatureEx(IntPtr.Zero,1,3,crl,2,issuer.Handle,0,IntPtr.Zero));signature=true;
            stage="VerifyCrlTime";var info=Marshal.PtrToStructure<CrlContext>(crl);time=CertVerifyCRLTimeValidity(IntPtr.Zero,info.Info);if(time!=0)throw new InvalidDataException("CrlNotCurrent");
            stage="VerifyCrlScope";Need(CertIsValidCRLForCertificate(subject.Handle,crl,0,IntPtr.Zero));scope=true;
            stage="FindCertificateInSuppliedCrl";Need(CertFindCertificateInCRL(subject.Handle,crl,0,IntPtr.Zero,out var entry));
            if(entry!=IntPtr.Zero){error=0x80092010;throw new InvalidDataException("CertificateListedAsRevoked");}
            stage="OpenMemoryCrlStore";store=CertOpenStore((IntPtr)2,0,IntPtr.Zero,0,IntPtr.Zero);Need(store!=IntPtr.Zero);
            stage="AddMemoryCrl";Need(CertAddEncodedCRLToStore(store,1,bytes,checked((uint)bytes.Length),1,IntPtr.Zero));
            var para=new RevocationParameters{Size=(uint)Marshal.SizeOf<RevocationParameters>(),Issuer=issuer.Handle,CrlStore=store};
            var status=new RevocationStatus{Size=(uint)Marshal.SizeOf<RevocationStatus>()};
            stage="VerifyRevocationCacheOnly";notRevoked=CertVerifyRevocation(0x10001,1,1,new[]{subject.Handle},2,ref para,ref status);
            if(!notRevoked){error=status.Error;throw new InvalidDataException("CertificateRevocationNotConfirmed");}
        }
        catch(Exception ex) when(ex is Win32Exception or InvalidDataException){failure=stage;if(error==0)error=ex is Win32Exception w?unchecked((uint)w.NativeErrorCode):unchecked((uint)ex.HResult);}
        finally
        {
            if(crl!=IntPtr.Zero && !CertFreeCRLContext(crl))cleanup=false;
            if(store!=IntPtr.Zero && !CertCloseStore(store,2))cleanup=false;
            GC.KeepAlive(subject);GC.KeepAlive(issuer);
        }
        return new(parsed,signature,scope,time,notRevoked,cleanup,error,failure);
        static void Need(bool ok){if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error());}
    }
    internal static object QualifyPrimitives()
    {
        AssertLayout();var now=DateTimeOffset.UtcNow;using var key=RSA.Create(2048);
        var request=new CertificateRequest("CN=CPC-owned-revocation-"+Guid.NewGuid().ToString("N"),key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign,true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey,false));
        using var issuer=request.CreateSelfSigned(now.AddDays(-1),now.AddDays(1));using var leafKey=RSA.Create(2048);
        var leafRequest=new CertificateRequest("CN=CPC-owned-leaf",leafKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        using var leaf=leafRequest.Create(issuer,now.AddHours(-1),now.AddHours(1),RandomNumberGenerator.GetBytes(16));
        var builder=new CertificateRevocationListBuilder();
        var current=builder.Build(issuer,BigInteger.One,now.AddHours(1),HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1,now.AddMinutes(-1));
        var expired=builder.Build(issuer,new BigInteger(2),now.AddMinutes(-1),HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1,now.AddHours(-1));
        builder.AddEntry(leaf,now.AddSeconds(-30));var revoked=builder.Build(issuer,new BigInteger(3),now.AddHours(1),HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1,now.AddMinutes(-1));
        var changed=(byte[])current.Clone();changed[^1]^=1;
        var cases=new[]{("valid",current,issuer,true),("revoked",revoked,issuer,false),("expired",expired,issuer,false),
            ("bad-signature",changed,issuer,false),("wrong-issuer",current,leaf,false),("malformed",new byte[]{0x30,0},issuer,false)};
        var results=cases.Select(c=>new {Case=c.Item1,Expected=c.Item4,Verification=Verify(leaf,c.Item3,c.Item2)}).ToArray();
        if(results.Any(r=>Qualified(r.Verification)!=r.Expected))throw WfpNative.Contract("LocalRevocationPrimitiveQualificationFailed");
        return new {Status="SYNTHETIC_MEMORY_ONLY_REVOCATION_PRIMITIVES_QUALIFIED",Cases=results,NetworkCalled=false,TrustStoreModified=false,RealCertificateTrustQualified=false};
    }
    private static void AssertLayout()
    {if(!Environment.Is64BitProcess || Marshal.SizeOf<CrlContext>()!=40 || Marshal.SizeOf<RevocationParameters>()!=96 || Marshal.SizeOf<RevocationStatus>()!=24)throw new PlatformNotSupportedException("RevocationX64Layout");}
    [StructLayout(LayoutKind.Sequential)] private struct CrlContext{internal uint Encoding;internal IntPtr Encoded;internal uint Length;internal IntPtr Info,Store;}
    [StructLayout(LayoutKind.Sequential)] private struct RevocationParameters
    {internal uint Size;internal IntPtr Issuer;internal uint StoreCount;internal IntPtr Stores,CrlStore,Time;internal uint Timeout;internal int CheckFreshness;internal uint Freshness;internal IntPtr CurrentTime,CrlInfo,Resync,Chain;}
    [StructLayout(LayoutKind.Sequential)] private struct RevocationStatus{internal uint Size,Index,Error,Reason;internal int HasFreshness;internal uint Freshness;}
    [DllImport("crypt32.dll",SetLastError=true)] private static extern IntPtr CertCreateCRLContext(uint encoding,byte[] bytes,uint length);
    [DllImport("crypt32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CertFreeCRLContext(IntPtr crl);
    [DllImport("crypt32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CryptVerifyCertificateSignatureEx(IntPtr provider,uint encoding,uint subjectType,IntPtr subject,uint issuerType,IntPtr issuer,uint flags,IntPtr extra);
    [DllImport("crypt32.dll")] private static extern int CertVerifyCRLTimeValidity(IntPtr time,IntPtr info);
    [DllImport("crypt32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CertIsValidCRLForCertificate(IntPtr cert,IntPtr crl,uint flags,IntPtr reserved);
    [DllImport("crypt32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CertFindCertificateInCRL(IntPtr cert,IntPtr crl,uint flags,IntPtr reserved,out IntPtr entry);
    [DllImport("crypt32.dll",SetLastError=true)] private static extern IntPtr CertOpenStore(IntPtr provider,uint encoding,IntPtr crypt,uint flags,IntPtr para);
    [DllImport("crypt32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CertCloseStore(IntPtr store,uint flags);
    [DllImport("crypt32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CertAddEncodedCRLToStore(IntPtr store,uint encoding,byte[] bytes,uint length,uint disposition,IntPtr context);
    [DllImport("crypt32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CertVerifyRevocation(uint encoding,uint type,uint count,[In]IntPtr[] contexts,uint flags,ref RevocationParameters parameters,ref RevocationStatus status);
}
