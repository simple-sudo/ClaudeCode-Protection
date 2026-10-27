using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

internal enum NetworkProbeKind { Control,Quarantine,Proxy,ProxyDenied }
internal sealed record NetworkProbePlan(NetworkProbeKind Kind,int TcpPort,int OtherAddressPort,int Tcp6Port,int UdpPort,int Udp6Port,string Nonce)
{
    internal void Validate()
    {
        if(!Enum.IsDefined(Kind) || new[]{TcpPort,OtherAddressPort,Tcp6Port,UdpPort,Udp6Port}.Any(p=>p is <1024 or >65535 || p==CompiledFencePolicy.ProxyPort))
            throw WfpNative.Contract("BoundedOwnedLoopbackEndpointsRequired");
        _=Identifiers.Hex32(Nonce);
    }
    internal byte[] Payload=>Encoding.ASCII.GetBytes("CPC-NET:"+Nonce);
    internal byte[] DnsQuery
    {
        get
        {
            var data=new List<byte>{0x43,0x50,1,0,0,1,0,0,0,0,0,0};
            foreach(var part in ("cpc-"+Nonce+".invalid").Split('.')){data.Add(checked((byte)part.Length));data.AddRange(Encoding.ASCII.GetBytes(part));}
            data.AddRange(new byte[]{0,0,1,0,1});return data.ToArray();
        }
    }
}
internal sealed record SocketProbe(string Role,bool SocketCallSucceeded,int? SocketError,string? FailureType);
internal sealed record NetworkTransportFailure(string Type,int Code,string? HttpError,int? SocketError,string? InnerType,int? InnerCode)
{
    internal static NetworkTransportFailure From(Exception error)
    {
        SocketException? socket=null;for(Exception? e=error;e is not null;e=e.InnerException)if(e is SocketException s){socket=s;break;}
        return new(error.GetType().Name,error.HResult,(error as HttpRequestException)?.HttpRequestError.ToString(),
            socket is null?null:(int)socket.SocketErrorCode,error.InnerException?.GetType().Name,error.InnerException?.HResult);
    }
}
internal sealed record NetworkChildReport(int SchemaVersion,int Pid,NetworkProbeKind Kind,string Nonce,SocketProbe[] Cases,int? ProxyHttpStatus,
    SocketProbe? ProxySocket,NetworkTransportFailure? ProxyFailure,TlsValidationObservation? TlsValidation,int FailureMask,bool SystemResolverQualified);
internal sealed record NetworkPhaseReport(NetworkProbeKind Kind,string JobId,NetworkChildReport? Child,int[]? IndependentReceiverCounts,
    int ReceiptObservationMs,bool Matched,WfpErrorEvidence[] Failures,bool ProfileDeleteAbsenceQualified);

// Receiver-side nonce receipts are independent of child Send return values.
// All listeners are freshly bound, exclusive, and loopback-only. Port 53 is
// used only on 127.0.0.2; an existing binding fails instead of being replaced.
internal sealed class NetworkReceivers : IDisposable
{
    internal static readonly string[] Roles={"tcp4-other-port","tcp4-other-address","tcp6","udp4","udp6","raw-dns-udp53"};
    private readonly List<Socket> sockets=new();
    private readonly List<Task> collectors=new();
    private readonly ConcurrentBag<(string Role,byte[] Data)> receipts=new();
    private readonly CancellationTokenSource stop=new();
    private readonly int[] ports=new int[5];
    internal NetworkReceivers()
    {
        try
        {
            ports[0]=Tcp(IPAddress.Loopback,Roles[0]);ports[1]=Tcp(IPAddress.Parse("127.0.0.2"),Roles[1]);ports[2]=Tcp(IPAddress.IPv6Loopback,Roles[2]);
            ports[3]=Udp(IPAddress.Loopback,0,Roles[3]);ports[4]=Udp(IPAddress.IPv6Loopback,0,Roles[4]);_=Udp(IPAddress.Parse("127.0.0.2"),53,Roles[5]);
        }
        catch(Exception failure){try{Dispose();}catch(Exception cleanup){throw new AggregateException(failure,cleanup);}throw;}
    }
    internal NetworkProbePlan Plan(NetworkProbeKind kind)=>new(kind,ports[0],ports[1],ports[2],ports[3],ports[4],Guid.NewGuid().ToString("N"));
    private Socket Bound(IPAddress address,SocketType type,ProtocolType protocol,int port)
    {
        var socket=new Socket(address.AddressFamily,type,protocol){ExclusiveAddressUse=true};sockets.Add(socket);
        if(address.AddressFamily==AddressFamily.InterNetworkV6)socket.DualMode=false;
        socket.Bind(new IPEndPoint(address,port));return socket;
    }
    private int Tcp(IPAddress address,string role)
    {
        var socket=Bound(address,SocketType.Stream,ProtocolType.Tcp,0);socket.Listen(8);collectors.Add(CollectTcp(socket,role));return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }
    private int Udp(IPAddress address,int port,string role)
    {
        var socket=Bound(address,SocketType.Dgram,ProtocolType.Udp,port);collectors.Add(CollectUdp(socket,role));return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }
    private async Task CollectTcp(Socket listener,string role)
    {
        try
        {
            while(!stop.IsCancellationRequested)
            {
                using var client=await listener.AcceptAsync(stop.Token);var bytes=new byte[128];
                using var timeout=CancellationTokenSource.CreateLinkedTokenSource(stop.Token);timeout.CancelAfter(2000);
                try
                {
                    var total=0;
                    while(total<bytes.Length){var count=await client.ReceiveAsync(bytes.AsMemory(total),SocketFlags.None,timeout.Token);if(count==0)break;total+=count;}
                    if(total>0)receipts.Add((role,bytes[..total]));
                }
                catch(OperationCanceledException) when(!stop.IsCancellationRequested){}
            }
        }
        catch(OperationCanceledException) when(stop.IsCancellationRequested){}
        catch(ObjectDisposedException) when(stop.IsCancellationRequested){}
        catch(SocketException) when(stop.IsCancellationRequested){}
    }
    private async Task CollectUdp(Socket socket,string role)
    {
        try
        {
            var bytes=new byte[512];
            while(!stop.IsCancellationRequested)
            {var count=await socket.ReceiveAsync(bytes,SocketFlags.None,stop.Token);if(count>0)receipts.Add((role,bytes[..count]));}
        }
        catch(OperationCanceledException) when(stop.IsCancellationRequested){}
        catch(ObjectDisposedException) when(stop.IsCancellationRequested){}
        catch(SocketException) when(stop.IsCancellationRequested){}
    }
    internal int[] ReceiptCounts(NetworkProbePlan plan)=>Roles.Select(role=>receipts.Count(r=>r.Role==role &&
        r.Data.AsSpan().SequenceEqual(role==Roles[5]?plan.DnsQuery:plan.Payload))).ToArray();
    internal void AssertCollecting()
    {
        if(stop.IsCancellationRequested || collectors.Count!=Roles.Length || collectors.Any(t=>t.IsCompleted))
            throw WfpNative.Contract("NetworkReceiverCollectorNotHealthy");
    }
    public void Dispose()
    {
        stop.Cancel();foreach(var socket in sockets)socket.Dispose();
        try{Task.WhenAll(collectors).GetAwaiter().GetResult();}finally{stop.Dispose();}
    }
}

internal static class NetworkQualification
{
    internal static async Task<SocketProbe[]> RawCases(NetworkProbePlan plan)
    {
        plan.Validate();return new[]{
            await Probe(NetworkReceivers.Roles[0],IPAddress.Loopback,plan.TcpPort,false,plan.Payload),
            await Probe(NetworkReceivers.Roles[1],IPAddress.Parse("127.0.0.2"),plan.OtherAddressPort,false,plan.Payload),
            await Probe(NetworkReceivers.Roles[2],IPAddress.IPv6Loopback,plan.Tcp6Port,false,plan.Payload),
            await Probe(NetworkReceivers.Roles[3],IPAddress.Loopback,plan.UdpPort,true,plan.Payload),
            await Probe(NetworkReceivers.Roles[4],IPAddress.IPv6Loopback,plan.Udp6Port,true,plan.Payload),
            await Probe(NetworkReceivers.Roles[5],IPAddress.Parse("127.0.0.2"),53,true,plan.DnsQuery)};
    }
    private static async Task<SocketProbe> Probe(string role,IPAddress address,int port,bool udp,byte[] bytes)
    {
        using var socket=new Socket(address.AddressFamily,udp?SocketType.Dgram:SocketType.Stream,udp?ProtocolType.Udp:ProtocolType.Tcp);
        using var timeout=new CancellationTokenSource(1500);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address,port),timeout.Token);
            var sent=0;
            while(sent<bytes.Length)
            {
                var count=await socket.SendAsync(bytes.AsMemory(sent),SocketFlags.None,timeout.Token);
                if(count<=0 || (udp && count!=bytes.Length))return new(role,false,null,"PartialSocketSend");sent+=count;
            }
            return new(role,true,null,null);
        }
        catch(SocketException ex){return new(role,false,(int)ex.SocketErrorCode,ex.GetType().Name);}
        catch(OperationCanceledException ex){return new(role,false,null,ex.GetType().Name);}
    }
    internal static async Task<NetworkChildReport> RunChild(NetworkProbePlan plan)
    {
        var cases=await RawCases(plan);var mask=0;
        for(var i=0;i<cases.Length;i++)if(plan.Kind==NetworkProbeKind.Control?!cases[i].SocketCallSucceeded:!EligibleNegative(cases[i],i))mask|=1<<i;
        int? http=null;SocketProbe? proxy=null;NetworkTransportFailure? failure=null;TlsValidationObservation? tls=null;
        if(plan.Kind==NetworkProbeKind.Proxy)
        {
            proxy=await Probe("compiled-proxy-port",IPAddress.Loopback,CompiledFencePolicy.ProxyPort,false,Array.Empty<byte>());
            if(!proxy.SocketCallSucceeded)mask|=64;
            try{http=await ProxyChannelLease.CheckTransport(result=>tls=result);if(http is <200 or >=400)mask|=64;}
            catch(Exception ex) when(ex is HttpRequestException or OperationCanceledException){failure=NetworkTransportFailure.From(ex);mask|=64;}
        }
        else if(plan.Kind!=NetworkProbeKind.Control)
        {proxy=await Probe("compiled-proxy-port",IPAddress.Loopback,CompiledFencePolicy.ProxyPort,false,Array.Empty<byte>());if(!Denied(proxy))mask|=64;}
        return new(1,Environment.ProcessId,plan.Kind,plan.Nonce,cases,http,proxy,failure,tls,mask,false);
    }
    private static bool Denied(SocketProbe probe)=>!probe.SocketCallSucceeded && probe.SocketError==(int)System.Net.Sockets.SocketError.AccessDenied;
    // UDP send completion only means the local call accepted the datagram. It
    // neither proves delivery nor denial. The trusted parent must independently
    // observe zero nonce receipts with healthy, positively controlled receivers.
    // Unknown errors/timeouts remain failures; TCP still requires AccessDenied.
    private static bool EligibleNegative(SocketProbe probe,int index)=>Denied(probe) ||
        (index>=3 && probe.SocketCallSucceeded && probe.SocketError is null && probe.FailureType is null);

    internal static (int ExitCode,string Report) Run(FixedLayout layout,ProtectedState state,VerifiedVersion version)
    {
        state.AssertHeld();version.AssertHeld(state);LifecycleRecovery.AssertNoPending(state);InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var intent in OwnedJobIntent.ReadAll(state))if(AtomicJobCompletion.ReadClosed(state,intent) is null)throw WfpNative.Contract("NetworkQualificationRequiresAllPriorAdmissionsClosed");
        var plans=FencePlan.ReadAll(state);if(plans.Count==0)throw WfpNative.Contract("NetworkQualificationRequiresFence");
        var fences=new List<PersistentFence>();var results=new List<object>();var protectedPlans=new List<NetworkProbePlan>();Exception? failure=null;
        var id=Guid.NewGuid().ToString("N");
        state.WriteNew("network-before-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,version.Package.Release,
            Scope="OWNED_LOOPBACK_CONTROLS_AND_EXPLICIT_FLCLASH_HTTPS",Target="https://www.microsoft.com/",ClaudeLaunchAllowed=false,AtUtc=DateTime.UtcNow.ToString("o")}));
        try
        {
            foreach(var plan in plans)
            {
                var fence=PersistentFence.OpenExisting(state,plan.Data.FenceId);fences.Add(fence);
                if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("NetworkQualificationRequiresInitialFullQuarantine");
            }
            using var proxy=ProxyChannelLease.Open(state);
            var transport=ProxyChannelLease.CheckTransport().GetAwaiter().GetResult();proxy.AssertHealthy();
            if(transport is <200 or >=400)throw WfpNative.Contract("HostExplicitProxyTransportNotQualified");
            using var receivers=new NetworkReceivers();
            var host=receivers.Plan(NetworkProbeKind.Control);var baseline=RawCases(host).GetAwaiter().GetResult();Thread.Sleep(150);
            receivers.AssertCollecting();var hostReceipts=receivers.ReceiptCounts(host);
            state.WriteNew("network-host-control-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {Cases=baseline,ReceiptCounts=hostReceipts,ProxyHttpStatus=transport,ProxyIdentity=proxy.Evidence}));
            if(baseline.Any(c=>!c.SocketCallSucceeded) || hostReceipts.Any(c=>c<1))throw WfpNative.Contract("OwnedNetworkReceiversNotReachableFromHost");
            foreach(var kind in new[]{NetworkProbeKind.Control,NetworkProbeKind.Quarantine,NetworkProbeKind.Proxy,NetworkProbeKind.ProxyDenied})
            {
                var result=RunPhase(kind,receivers,proxy);results.Add(result);
                state.WriteNew("network-phase-"+id+"-"+((int)kind)+".json",JsonSerializer.SerializeToUtf8Bytes(result));
                if(!result.Matched)throw WfpNative.Contract("NetworkChildOrIndependentReceiptsDidNotMatch");
            }
            // Verify receivers still deliver after the negative phases and
            // reject any late protected nonce receipt before ending the scope.
            var finalHost=receivers.Plan(NetworkProbeKind.Control);var finalCases=RawCases(finalHost).GetAwaiter().GetResult();Thread.Sleep(250);
            receivers.AssertCollecting();var finalCounts=receivers.ReceiptCounts(finalHost);
            var late=protectedPlans.Select(p=>new {p.Kind,p.Nonce,ReceiptCounts=receivers.ReceiptCounts(p)}).ToArray();
            state.WriteNew("network-final-control-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {Cases=finalCases,ReceiptCounts=finalCounts,ProtectedReceipts=late}));
            if(finalCases.Any(c=>!c.SocketCallSucceeded) || finalCounts.Any(c=>c<1) || late.Any(p=>p.ReceiptCounts.Any(c=>c!=0)))
                throw WfpNative.Contract("NetworkFinalReceiverControlOrLateReceiptsFailed");
        }
        catch(Exception ex){failure=ex;}
        finally
        {
            foreach(var fence in fences)
            {
                try{if(!fence.Observe().FullQuarantineObserved)_=fence.ReinstateQuarantine();if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("NetworkFinalQuarantineNotObserved");}
                catch(Exception ex){failure=Combine(failure,ex);}
            }
            foreach(var fence in fences)fence.Dispose();
        }
        var report=JsonSerializer.Serialize(new {SchemaVersion=1,state.InstallationId,RequestId=id,Status=failure is null?"BOUNDED_NETWORK_MATRIX_OBSERVED":"NETWORK_MATRIX_NOT_CONFIRMED",
            Results=results,Failures=failure is null?Array.Empty<WfpErrorEvidence>():WfpNative.Describe(failure),
            SystemResolverQualified=false,ExternalPhysicalEgressQualified=false,ProxyProcessCrashQualified=false,ControllerCrashQualified=false,ClaudeLaunched=false});
        state.WriteNew("network-after-"+id+".json",Encoding.UTF8.GetBytes(report));return(failure is null?0:3,report);

        NetworkPhaseReport RunPhase(NetworkProbeKind kind,NetworkReceivers receivers,ProxyChannelLease proxy)
        {
            var control=kind==NetworkProbeKind.Control;var plan=receivers.Plan(kind);
            using var profile=InstallationProfileLease.Create(state,control);
            using var loopback=InstallationLoopbackLease.Enable(state,control);
            using var job=OwnedKernelJob.CreateEmpty(state,version);
            using var pipe=new AnonymousPipeServerStream(PipeDirection.In,HandleInheritability.Inheritable);
            using var reader=new StreamReader(pipe,Encoding.UTF8,false,4096,true);
            var text=ReadBounded(reader);Exception? phaseFailure=null;NetworkChildReport? observed=null;int[]? delivered=null;Task<uint>? exited=null;
            try
            {
                using var child=AtomicChild.CreateCanary(layout,state,version,job,profile,plan,pipe.ClientSafePipeHandle.DangerousGetHandle());
                pipe.DisposeLocalCopyOfClientHandle();
                if(kind==NetworkProbeKind.Proxy)foreach(var fence in fences)_=fence.OpenQualifiedIPv4Proxy(proxy);
                _=child.ResumeQuarantined(proxy);exited=Task.Run(child.WaitForCanaryExit);
                while(!exited.Wait(250))
                {
                    if(kind==NetworkProbeKind.Proxy)
                    {
                        proxy.AssertHealthy();foreach(var fence in fences)if(!fence.Observe().IPv4ProxyOnlyObserved)throw WfpNative.Contract("NetworkWatchdogFenceDrift");
                    }
                }
                var exit=exited.GetAwaiter().GetResult();
                var json=text.WaitAsync(TimeSpan.FromSeconds(3)).GetAwaiter().GetResult();
                observed=JsonSerializer.Deserialize<NetworkChildReport>(json)??throw WfpNative.Contract("MissingNetworkChildReport");
                if(observed.SchemaVersion!=1 || observed.Pid!=child.Pid || observed.Kind!=kind || observed.Nonce!=plan.Nonce || observed.Cases is null ||
                    !observed.Cases.Select(c=>c.Role).SequenceEqual(NetworkReceivers.Roles))throw WfpNative.Contract("NetworkReportIdentityOrCasesMismatch");
                var observationMs=control?250:2000;Thread.Sleep(observationMs);receivers.AssertCollecting();delivered=receivers.ReceiptCounts(plan);
                if(!control)protectedPlans.Add(plan);
                state.WriteNew("network-observed-"+job.JobId+".json",JsonSerializer.SerializeToUtf8Bytes(new {Child=observed,ExitCode=exit,ReceiverCounts=delivered,
                    ReceiptObservationMs=observationMs,ReceiverCollectorsHealthy=true,UdpSendSuccessIsDeliveryProof=false,ExternalEgressQualified=false}));
                var rawMatched=control?observed.Cases.All(c=>c.SocketCallSucceeded):observed.Cases.Select(EligibleNegative).All(v=>v);
                var proxyMatched=control || (kind==NetworkProbeKind.Proxy?observed.ProxyHttpStatus is >=200 and <400 && observed.ProxySocket?.SocketCallSucceeded==true:
                    observed.ProxySocket is not null && Denied(observed.ProxySocket));
                if(exit!=0 || observed.FailureMask!=0 || !rawMatched || !proxyMatched ||
                    (control?delivered.Any(c=>c<1):delivered.Any(c=>c!=0)))throw WfpNative.Contract("NetworkChildOrIndependentReceiptsDidNotMatch");
            }
            catch(Exception ex){phaseFailure=ex;}
            finally
            {
                // Restore deny before stopping processes or removing the exact
                // exemption. Continue exact Job stop even if WFP restore fails.
                if(kind==NetworkProbeKind.Proxy)foreach(var fence in fences)
                {try{_=fence.ReinstateQuarantine();}catch(Exception ex){phaseFailure=Combine(phaseFailure,ex);}}
                try
                {
                    if(job.AtomicAdmissionReserved){var zero=job.CloseAtomicAdmissionAndStop();profile.AfterOwnedJobZero(zero);}
                    else{_=job.StopAndVerifyZero();throw WfpNative.Contract("NetworkAdmissionReservationUnknown");}
                }
                catch(Exception ex){phaseFailure=Combine(phaseFailure,ex);}
                if(exited is not null)
                {try{_=exited.WaitAsync(TimeSpan.FromSeconds(3)).GetAwaiter().GetResult();}catch(Exception ex){phaseFailure=Combine(phaseFailure,ex);}}
                pipe.DisposeLocalCopyOfClientHandle();
            }
            return new(kind,job.JobId,observed,delivered,control?250:2000,phaseFailure is null,
                phaseFailure is null?Array.Empty<WfpErrorEvidence>():WfpNative.Describe(phaseFailure),false);
        }
    }
    private static async Task<string> ReadBounded(StreamReader reader)
    {
        var buffer=new char[16385];var total=0;
        while(total<buffer.Length){var count=await reader.ReadAsync(buffer.AsMemory(total));if(count==0)return new string(buffer,0,total);total+=count;}
        throw WfpNative.Contract("NetworkReportCapacityExceeded");
    }
    private static Exception Combine(Exception? a,Exception b)=>a is null?b:new AggregateException(a,b);
}
