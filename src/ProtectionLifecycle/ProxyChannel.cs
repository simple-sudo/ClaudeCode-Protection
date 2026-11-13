using System.ComponentModel;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Security;

namespace ProtectionLifecycle;

// Holds the existing proxy process and its on-disk image, without starting,
// stopping or reconfiguring it. Path/hash are observations, not AV clearance or
// proof that every byte in the already-running image equals the disk image.
internal sealed class ProxyChannelLease : IDisposable
{
    private const string ExpectedImage="E:\\program\\FlClash\\FlClashCore.exe";
    private readonly SafeProcessHandle process;
    private readonly PathLease directory;
    private readonly FileStream image;
    private readonly uint pid;
    private bool disposed;
    internal object Evidence {get;}
    private readonly ProxyProcessIdentity identity;
    private ProxyChannelLease(SafeProcessHandle process,PathLease directory,FileStream image,ProxyProcessIdentity identity,object evidence)
    {this.process=process;this.directory=directory;this.image=image;this.identity=identity;pid=identity.Pid;Evidence=evidence;}
    internal static ProxyChannelLease Open(ProtectedState state)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();var pid=ListenerOwner();
        var process=OpenProcess(0x101000,false,pid);PathLease? directory=null;FileStream? image=null;
        try
        {
            if(process.IsInvalid)throw Error("OpenExistingProxyIdentity");
            if(!GetProcessTimes(process,out var created,out _,out _,out _))throw Error("ReadProxyCreationTime");
            var path=new StringBuilder(32768);uint length=(uint)path.Capacity;
            if(!QueryFullProcessImageName(process,0,path,ref length))throw Error("ReadProxyImagePath");
            if(!string.Equals(WindowsPathSeal.Canonical(path.ToString()),ExpectedImage,StringComparison.OrdinalIgnoreCase))throw WfpNative.Contract("ProxyListenerImagePathMismatch");
            directory=WindowsPathSeal.LockDirectory(Path.GetDirectoryName(ExpectedImage)!,PathPolicy.Source);
            var file=WindowsPathSeal.Open(ExpectedImage,false,true);image=new(file,FileAccess.Read,65536,false);
            if(image.Length is <1 or >128*1024*1024)throw WfpNative.Contract("ProxyImageSizeRefused");
            var hash=Convert.ToHexString(SHA256.HashData(image));
            var identity=new ProxyProcessIdentity(pid,created,hash,WindowsPathSeal.Identity(image.SafeFileHandle));
            var evidence=new {Pid=pid,ImagePath=ExpectedImage,CreatedUtc=DateTime.FromFileTimeUtc(created).ToString("o"),DiskImageSHA256=hash,
                identity.FileIdentity,MappedImageBytesQualified=false,Endpoint="127.0.0.1:7890"};
            var lease=new ProxyChannelLease(process,directory,image,identity,evidence);lease.AssertHealthy();
            state.WriteNew("proxy-observed-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(evidence));return lease;
        }
        catch{image?.Dispose();directory?.Dispose();process.Dispose();throw;}
    }
    internal void AssertHealthy()
    {
        if(disposed || process.IsClosed || image.SafeFileHandle.IsClosed)throw new ObjectDisposedException(nameof(ProxyChannelLease));
        directory.AssertHeld();WindowsPathSeal.VerifyObject(image.SafeFileHandle,ExpectedImage,false);
        if(WaitForSingleObject(process,0)!=0x102 || ListenerOwner()!=pid)throw WfpNative.Contract("ProxyProcessOrListenerIdentityDrift");
    }
    internal ProxyProcessIdentity ObserveIdentity()
    {
        AssertControllerListener();
        return identity;
    }

    internal async Task<MachineProxyRouteBinding?> ObserveMachineRoute(CancellationToken cancellation)
    {
        var before = ObserveIdentity();
        var started = Stopwatch.GetTimestamp();
        var selection = await ProxyRouteObservation.CaptureStableSelection(this, cancellation).ConfigureAwait(false);
        cancellation.ThrowIfCancellationRequested();
        var finished = Stopwatch.GetTimestamp();
        return before == ObserveIdentity() && selection is { AllowsRoutePrecheck: true, SelectionDigest: { } digest }
            ? new(before, digest, started, finished) : null;
    }
    // Pin the accepted server-side socket, not just whichever process happens
    // to own the listener when checked. No CONNECT data may precede this check.
    // An uncertain/closed connection is refused; there is no listener fallback.
    internal void AssertConnectedPeer(Socket socket)=>AssertConnectedPeer(socket,CompiledFencePolicy.ProxyPort);
    internal void AssertControllerPeer(Socket socket)=>AssertConnectedPeer(socket,LocalManagementBoundary.ControllerPort);
    internal void AssertControllerListener()
    {
        AssertHealthy();
        if(ReadLoopbackOwner(LocalManagementBoundary.ControllerPort,null)!=pid)
            throw WfpNative.Contract("LocalControllerListenerOwnerDrift");
    }
    private void AssertConnectedPeer(Socket socket,int port)
    {
        AssertHealthy();
        if(socket.LocalEndPoint is not IPEndPoint local || !local.Address.Equals(IPAddress.Loopback) ||
            socket.RemoteEndPoint is not IPEndPoint remote || !remote.Address.Equals(IPAddress.Loopback) ||
            remote.Port!=port || ReadLoopbackOwner(remote.Port,local.Port)!=pid)
            throw WfpNative.Contract("ProxyConnectedPeerIdentityMismatch");
        AssertHealthy();
    }
    internal static async Task<int> CheckTransport(Action<TlsValidationObservation>? observe=null,Action<TlsCertificateObservation[]>? observeCertificates=null,Action<RevocationSupply>? observeRevocation=null)
    {
        using var handler=CreateTransportHandler(observe,observeCertificates,observeRevocation);
        using var client=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(20)};
        using var response=await client.GetAsync("https://www.microsoft.com/",HttpCompletionOption.ResponseHeadersRead);
        return (int)response.StatusCode;
    }
    private static SocketsHttpHandler CreateTransportHandler(Action<TlsValidationObservation>? observe,Action<TlsCertificateObservation[]>? observeCertificates,Action<RevocationSupply>? observeRevocation)
    {
        // Chain building runs BEFORE the observation callback. Online checks
        // here could start OS certificate downloads outside the explicit proxy.
        // Share the gateway's offline/no-AIA policy; missing evidence still
        // fails unless the existing fixed, independently verified CRLs suffice.
        var handler=new SocketsHttpHandler{UseProxy=true,Proxy=new WebProxy("http://127.0.0.1:7890"),AllowAutoRedirect=false,
            UseCookies=false,Credentials=null,DefaultProxyCredentials=null,SslOptions=SessionProxy.OfflineTls()};
        if(observe is not null || observeCertificates is not null || observeRevocation is not null)handler.SslOptions.RemoteCertificateValidationCallback=(sender,certificate,chain,errors)=>
        {
            if(sender is not SslStream transport || transport.TargetHostName!="www.microsoft.com")return false;
            var result=new TlsValidationObservation((int)errors,chain?.ChainStatus.Select(s=>(int)s.Status).ToArray()??Array.Empty<int>(),certificate is not null,chain is not null);
            observe?.Invoke(result);observeCertificates?.Invoke(ObserveCertificates(chain));
            if(AcceptObservedTls(result))return true;
            if(observeRevocation is null || !ProcessLocalRevocation.Eligible(result))return false;
            var verified=ProcessLocalRevocation.Validate(certificate as X509Certificate2,chain,result);observeRevocation(verified);return verified.Accepted;
        };
        return handler;
    }
    // The diagnostic callback accepts only a present, clean chain and no name,
    // trust or availability errors. Revocation checking remains enabled.
    internal static bool AcceptObservedTls(TlsValidationObservation result)=>result.CertificatePresent && result.ChainPresent &&
        result.PolicyErrors==(int)SslPolicyErrors.None && result.ChainStatus.All(s=>s==0);
    private static TlsCertificateObservation[] ObserveCertificates(X509Chain? chain)
    {
        if(chain is null)return Array.Empty<TlsCertificateObservation>();
        if(chain.ChainElements.Count>8)throw WfpNative.Contract("DiagnosticCertificateChainCapacity");
        return chain.ChainElements.Select(element=>
        {
            string? failure=null;string[] points=Array.Empty<string>();
            try
            {
                var extensions=element.Certificate.Extensions.Where(e=>e.Oid?.Value=="2.5.29.31").ToArray();
                if(extensions.Length>1)throw new InvalidDataException("DuplicateCrlDistributionExtension");
                if(extensions.Length==1)points=ReadCrlUris(extensions[0].RawData);
            }
            catch(Exception ex) when(ex is AsnContentException or InvalidDataException){failure=ex.GetType().Name;}
            return new TlsCertificateObservation(Convert.ToHexString(SHA256.HashData(element.Certificate.RawData)),
                element.ChainElementStatus.Select(s=>(int)s.Status).ToArray(),points,failure);
        }).ToArray();
    }
    // Observation only. A certificate-provided URI is untrusted data, never an
    // authorized destination. No retrieval, trust-store or cache change occurs.
    internal static string[] ReadCrlUris(byte[] encoded)
    {
        if(encoded.Length is <2 or >16384)throw new InvalidDataException("CrlExtensionSize");
        var source=new AsnReader(encoded,AsnEncodingRules.DER);var points=source.ReadSequence();source.ThrowIfNotEmpty();
        var uris=new List<string>();Walk(points,0);return uris.ToArray();
        void Walk(AsnReader reader,int depth)
        {
            if(depth>8)throw new InvalidDataException("CrlExtensionDepth");
            while(reader.HasData)
            {
                var tag=reader.PeekTag();
                if(tag.TagClass==TagClass.ContextSpecific && tag.TagValue==6 && !tag.IsConstructed)
                {
                    var uri=reader.ReadCharacterString(UniversalTagNumber.IA5String,tag);
                    if(uri.Length is <1 or >1024 || uris.Count>=16)throw new InvalidDataException("CrlUriCapacity");uris.Add(uri);
                }
                else if(tag.IsConstructed)Walk(reader.ReadSequence(tag),depth+1);
                else _=reader.ReadEncodedValue();
            }
        }
    }
    private static uint ListenerOwner()=>ReadLoopbackOwner(CompiledFencePolicy.ProxyPort,null);
    internal static uint SessionPeerOwner(int sourcePort)=>ReadLoopbackOwner(sourcePort,SessionProxy.Port);
    internal static uint SessionListenerOwner()=>ReadLoopbackOwner(SessionProxy.Port,null);
    internal static uint QueryTcpOwnerTableSize(bool ipv6,out uint size)
    {
        size=0;
        return GetExtendedTcpTable(IntPtr.Zero,ref size,false,ipv6?23u:2u,5,0);
    }
    private static uint ReadLoopbackOwner(int localPort,int? remotePort)
    {
        var first=QueryTcpOwnerTableSize(false,out var size);
        if(first!=122 || size is <4 or >1024*1024)throw new WfpFailure("SizeProxyOwnerTable",first);
        for(var attempt=0;attempt<4;attempt++)
        {
            var capacity=size;var buffer=Marshal.AllocHGlobal(checked((int)capacity));
            try
            {
                var status=GetExtendedTcpTable(buffer,ref size,false,2,5,0);
                if(status==122){if(size is <4 or >1024*1024)throw WfpNative.Contract("ProxyOwnerTableCapacity");continue;}
                WfpNative.Check(status,"ReadProxyOwnerTable");
                if(size is <4 || size>capacity)throw WfpNative.Contract("ProxyOwnerTableBounds");
                var bytes=new byte[checked((int)size)];Marshal.Copy(buffer,bytes,0,bytes.Length);
                return LoopbackTcpTable.FindOwner(bytes,localPort,remotePort);
            }
            finally{Marshal.FreeHGlobal(buffer);}
        }
        throw WfpNative.Contract("ProxyOwnerTableChangedRepeatedly");
    }
    public void Dispose(){if(disposed)return;disposed=true;image.Dispose();directory.Dispose();process.Dispose();}
    private static Win32Exception Error(string stage){var e=new Win32Exception(Marshal.GetLastWin32Error());e.Data["Stage"]=stage;return e;}
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("iphlpapi.dll",ExactSpelling=true)] private static extern uint GetExtendedTcpTable(IntPtr table,ref uint size,[MarshalAs(UnmanagedType.Bool)] bool sorted,uint family,int tableClass,uint reserved);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)] bool inherit,uint pid);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetProcessTimes(SafeProcessHandle process,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll",EntryPoint="QueryFullProcessImageNameW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder path,ref uint length);
}
