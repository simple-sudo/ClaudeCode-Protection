using System.ComponentModel;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed record TlsValidationObservation(int PolicyErrors,int[] ChainStatus,bool CertificatePresent,bool ChainPresent);
internal sealed record TlsCertificateObservation(string SHA256,int[] ChainStatus,string[] CrlDistributionPoints,string? ExtensionFailure);
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
    private ProxyChannelLease(SafeProcessHandle process,PathLease directory,FileStream image,uint pid,object evidence)
    {this.process=process;this.directory=directory;this.image=image;this.pid=pid;Evidence=evidence;}
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
            var evidence=new {Pid=pid,ImagePath=ExpectedImage,CreatedUtc=DateTime.FromFileTimeUtc(created).ToString("o"),DiskImageSHA256=hash,
                FileIdentity=WindowsPathSeal.Identity(image.SafeFileHandle),MappedImageBytesQualified=false,Endpoint="127.0.0.1:7890"};
            var lease=new ProxyChannelLease(process,directory,image,pid,evidence);lease.AssertHealthy();
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
    internal static async Task<int> CheckTransport(Action<TlsValidationObservation>? observe=null,Action<TlsCertificateObservation[]>? observeCertificates=null,Action<RevocationSupply>? observeRevocation=null)
    {
        using var handler=new HttpClientHandler{UseProxy=true,Proxy=new WebProxy("http://127.0.0.1:7890"),AllowAutoRedirect=false,
            UseCookies=false,UseDefaultCredentials=false,CheckCertificateRevocationList=true};
        if(observe is not null || observeCertificates is not null || observeRevocation is not null)handler.ServerCertificateCustomValidationCallback=(request,certificate,chain,errors)=>
        {
            var result=new TlsValidationObservation((int)errors,chain?.ChainStatus.Select(s=>(int)s.Status).ToArray()??Array.Empty<int>(),certificate is not null,chain is not null);
            observe?.Invoke(result);observeCertificates?.Invoke(ObserveCertificates(chain));
            if(AcceptObservedTls(result))return true;
            if(observeRevocation is null || request.RequestUri?.AbsoluteUri!="https://www.microsoft.com/" || !ProcessLocalRevocation.Eligible(result))return false;
            var verified=ProcessLocalRevocation.Validate(certificate,chain,result);observeRevocation(verified);return verified.Accepted;
        };
        using var client=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(20)};
        using var response=await client.GetAsync("https://www.microsoft.com/",HttpCompletionOption.ResponseHeadersRead);
        return (int)response.StatusCode;
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
    private static uint ReadLoopbackOwner(int localPort,int? remotePort)
    {
        uint size=0;var first=GetExtendedTcpTable(IntPtr.Zero,ref size,false,2,5,0);
        if(first!=122 || size is <4 or >1024*1024)throw new WfpFailure("SizeProxyOwnerTable",first);
        for(var attempt=0;attempt<4;attempt++)
        {
            var capacity=size;var buffer=Marshal.AllocHGlobal(checked((int)capacity));
            try
            {
                var status=GetExtendedTcpTable(buffer,ref size,false,2,5,0);
                if(status==122){if(size is <4 or >1024*1024)throw WfpNative.Contract("ProxyOwnerTableCapacity");continue;}
                WfpNative.Check(status,"ReadProxyOwnerTable");var count=Marshal.ReadInt32(buffer);
                if(count<0 || count>(capacity-4)/24)throw WfpNative.Contract("ProxyOwnerTableBounds");
                var owners=new List<uint>();
                for(var i=0;i<count;i++)
                {
                    var row=buffer+4+i*24;var port=unchecked((uint)Marshal.ReadInt32(row,8));
                    var decoded=((port&255)<<8)|((port>>8)&255);
                    var remote=unchecked((uint)Marshal.ReadInt32(row,16));
                    var remoteDecoded=((remote&255)<<8)|((remote>>8)&255);
                    if(Marshal.ReadInt32(row)==(remotePort is null?2:5) && unchecked((uint)Marshal.ReadInt32(row,4))==0x0100007f && decoded==localPort &&
                        (remotePort is null || unchecked((uint)Marshal.ReadInt32(row,12))==0x0100007f && remoteDecoded==remotePort))
                        owners.Add(unchecked((uint)Marshal.ReadInt32(row,20)));
                }
                if(owners.Count!=1 || owners[0]==0)throw WfpNative.Contract("UniqueLoopbackProxyListenerRequired");return owners[0];
            }
            finally{Marshal.FreeHGlobal(buffer);}
        }
        throw WfpNative.Contract("ProxyOwnerTableChangedRepeatedly");
    }
    public void Dispose(){if(disposed)return;disposed=true;image.Dispose();directory.Dispose();process.Dispose();}
    private static Win32Exception Error(string stage){var e=new Win32Exception(Marshal.GetLastWin32Error());e.Data["Stage"]=stage;return e;}
    [DllImport("iphlpapi.dll",ExactSpelling=true)] private static extern uint GetExtendedTcpTable(IntPtr table,ref uint size,[MarshalAs(UnmanagedType.Bool)] bool sorted,uint family,int tableClass,uint reserved);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)] bool inherit,uint pid);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetProcessTimes(SafeProcessHandle process,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll",EntryPoint="QueryFullProcessImageNameW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder path,ref uint length);
}

internal sealed record LoopbackEntry(string Sid,uint Attributes);

// The Windows CLI receives one derived owned SID, never a global-list restore.
// Snapshot comparisons detect unrelated drift; cleanup removes only our SID.
// An external concurrent writer cannot be atomically locked by this API.
internal sealed class InstallationLoopbackLease : IDisposable
{
    private readonly ProtectedState state;
    private readonly string sid,id;
    private readonly LoopbackEntry[] prior;
    private bool disposed,toolStopped=true;
    internal static void AssertClosedHistory(ProtectedState state)
    {
        state.AssertHeld();using var target=new InstallationPackageSid(state);using var control=InstallationPackageSid.ForNetworkControl(state);
        foreach(var leaf in state.ListLeaves("loopback-intent-"))
        {
            if(leaf.Length!=53)throw WfpNative.Contract("LoopbackIntentLeafShape");
            var id=Identifiers.Hex32(leaf.Substring(16,32));
            using var before=JsonDocument.Parse(state.Read(leaf).Bytes);var b=before.RootElement;
            if(b.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(b,"InstallationId")!=state.InstallationId ||
                StrictJson.Text(b,"Sid") is not string sid || (sid!=target.Value && sid!=control.Value))throw WfpNative.Contract("LoopbackIntentScopeMismatch");
            var closed=state.ReadOptional("loopback-cleanup-"+id+".json");if(closed is null)throw WfpNative.Contract("PendingOwnedLoopbackOperationRequiresRecovery");
            using var doc=JsonDocument.Parse(closed.Bytes);var c=doc.RootElement;
            if(c.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(c,"InstallationId")!=state.InstallationId || StrictJson.Text(c,"Sid")!=sid ||
                !c.GetProperty("ExactSidAbsent").GetBoolean() || !c.GetProperty("UnrelatedEntriesPreserved").GetBoolean())throw WfpNative.Contract("OwnedLoopbackCleanupNotConfirmed");
        }
    }
    private InstallationLoopbackLease(ProtectedState state,string sid,string id,LoopbackEntry[] prior)
    {this.state=state;this.sid=sid;this.id=id;this.prior=prior;}
    internal static InstallationLoopbackLease Enable(ProtectedState state,bool control)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();
        using var package=control?InstallationPackageSid.ForNetworkControl(state):new InstallationPackageSid(state);
        var before=Read();if(before.Any(e=>e.Sid==package.Value))throw WfpNative.Contract("ExistingLoopbackExemptionNotAdopted");
        var id=Guid.NewGuid().ToString("N");
        state.WriteNew("loopback-intent-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,Sid=package.Value,
            Before=before,Operation="ADD_EXACT_OWNED_SID",ExternalConcurrentWritersSerialized=false,AtUtc=DateTime.UtcNow.ToString("o")}));
        var lease=new InstallationLoopbackLease(state,package.Value,id,before);
        try
        {
            Invoke("-a",package.Value,ref lease.toolStopped);var after=Read();
            if(after.Count(e=>e.Sid==package.Value)!=1 || !Others(after,package.Value).SequenceEqual(before))throw WfpNative.Contract("LoopbackAddOrOtherEntriesChanged");
            state.WriteNew("loopback-added-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,Sid=package.Value,Status="EXACT_SID_PRESENT_OTHERS_UNCHANGED"}));
            return lease;
        }
        catch(Exception failure){try{lease.Dispose();}catch(Exception cleanup){throw new AggregateException(failure,cleanup);}throw;}
    }
    public void Dispose()
    {
        if(disposed)return;disposed=true;state.AssertHeld();
        if(!toolStopped)throw WfpNative.Contract("LoopbackUtilityLifetimeUnknownNoCleanupProof");
        var before=Read();if(before.Any(e=>e.Sid==sid))Invoke("-d",sid,ref toolStopped);
        var after=Read();var absent=after.All(e=>e.Sid!=sid);var othersSame=Others(before,sid).SequenceEqual(after);
        state.WriteNew("loopback-cleanup-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,Sid=sid,
            ExactSidAbsent=absent,UnrelatedEntriesPreserved=othersSame,OriginalOthersUnchanged=after.SequenceEqual(prior),AtUtc=DateTime.UtcNow.ToString("o")}));
        if(!absent || !othersSame)throw WfpNative.Contract("LoopbackCleanupOrUnrelatedEntriesNotConfirmed");
    }
    private static LoopbackEntry[] Others(IEnumerable<LoopbackEntry> rows,string sid)=>rows.Where(e=>e.Sid!=sid).OrderBy(e=>e.Sid,StringComparer.Ordinal).ToArray();
    private static LoopbackEntry[] Read()
    {
        WfpNative.Check(NetworkIsolationGetAppContainerConfig(out var count,out var pointer),"ReadLoopbackExemptions");
        try
        {
            if(count>4096 || (count>0 && pointer==IntPtr.Zero))throw WfpNative.Contract("LoopbackSnapshotBounds");
            var result=new List<LoopbackEntry>();var size=Marshal.SizeOf<SidAttributes>();
            for(var i=0;i<count;i++)
            {
                var row=Marshal.PtrToStructure<SidAttributes>(pointer+checked((int)i)*size);
                if(row.Sid==IntPtr.Zero || !WfpNative.IsValidSid(row.Sid))throw WfpNative.Contract("InvalidLoopbackSid");
                result.Add(new(new SecurityIdentifier(row.Sid).Value,row.Attributes));
            }
            if(result.Select(e=>e.Sid).Distinct().Count()!=result.Count)throw WfpNative.Contract("DuplicateLoopbackSid");
            return result.OrderBy(e=>e.Sid,StringComparer.Ordinal).ToArray();
        }
        finally
        {
            if(pointer!=IntPtr.Zero)
            {
                if(count<=4096)for(var i=0;i<count;i++){var p=Marshal.ReadIntPtr(pointer+checked((int)i)*Marshal.SizeOf<SidAttributes>());if(p!=IntPtr.Zero)HeapFree(GetProcessHeap(),0,p);}
                HeapFree(GetProcessHeap(),0,pointer);
            }
        }
    }
    private static void Invoke(string operation,string sid,ref bool stopped)
    {
        if(operation is not ("-a" or "-d") || !sid.StartsWith("S-1-15-2-",StringComparison.Ordinal))throw WfpNative.Contract("ExactLoopbackCommandRequired");
        var system=Environment.GetFolderPath(Environment.SpecialFolder.System);using var path=WindowsPathSeal.LockDirectory(system,PathPolicy.TrustedAncestor);
        using var executable=WindowsPathSeal.OpenCheckNetIsolation();
        var start=new ProcessStartInfo(Path.Combine(system,"CheckNetIsolation.exe")){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=system,
            RedirectStandardOutput=true,RedirectStandardError=true};
        start.Environment.Clear();foreach(var name in new[]{"SystemRoot","windir","SystemDrive","USERPROFILE","LOCALAPPDATA"})
        {var value=Environment.GetEnvironmentVariable(name);if(value is not null)start.Environment[name]=value;}
        start.ArgumentList.Add("LoopbackExempt");start.ArgumentList.Add(operation);start.ArgumentList.Add("-p="+sid);
        using var process=Process.Start(start)??throw WfpNative.Contract("LoopbackCommandNotStarted");
        stopped=false;
        var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
        if(!process.WaitForExit(10000))
        {process.Kill();stopped=process.WaitForExit(5000);throw new TimeoutException("Exact loopback command timeout; termination status retained");}
        stopped=true;
        _=output.GetAwaiter().GetResult();_=error.GetAwaiter().GetResult();
        if(process.ExitCode!=0)throw WfpNative.Contract("ExactLoopbackCommandFailed");
    }
    [StructLayout(LayoutKind.Sequential)] private struct SidAttributes {internal IntPtr Sid;internal uint Attributes;}
    [DllImport("FirewallAPI.dll",ExactSpelling=true)] private static extern uint NetworkIsolationGetAppContainerConfig(out uint count,out IntPtr entries);
    [DllImport("kernel32.dll")] private static extern IntPtr GetProcessHeap();
    [DllImport("kernel32.dll")] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool HeapFree(IntPtr heap,uint flags,IntPtr memory);
}
