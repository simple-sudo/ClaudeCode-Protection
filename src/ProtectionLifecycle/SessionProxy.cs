using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Security;

namespace ProtectionLifecycle;

internal sealed partial class SessionProxy : IDisposable
{
    internal const int Port = 17891;
    internal const string Target = "www.microsoft.com";
    internal static readonly string PolicySHA256 = Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(
        "CPC-SESSION-NET3;host-target=refuse-current-unicast-v4-v6+bounded-private-snapshot+drift-fail-closed;listen=127.0.0.1:17891;upstream=127.0.0.1:7890+held-reverse-established-tuple;connect=www.microsoft.com:443;doh=1.1.1.1:443/cloudflare-dns.com;A-only;ipv6=deny;no-direct-fallback;tls=offline-no-download;auth=per-session+held-job-peer+AC-low-zero;max-connections=4;accepted=32;max-bytes=8MiB-per-direction+64MiB-total;connection-seconds=20;session-seconds=60;half-close=send-fin+drain-peer;fault=cancel+drain-both;forward=bound-admission+runtime-health-2s+per-write;client-hello=visible-matching-SNI+http-ALPN;hello=32KiB+8records;no-ECH")));
    private readonly TcpListener listener = new(IPAddress.Loopback, Port);
    private readonly CancellationTokenSource stop = new(TimeSpan.FromSeconds(60));
    private readonly ConcurrentDictionary<int, (TcpClient Client, Task Work)> clients = new();
    private readonly OwnedKernelJob job;
    private readonly ProxyChannelLease upstream;
    private readonly GatewayDestinationGuard destinations;
    private readonly string packageSid, sessionId;
    private readonly LpacCapabilityProfile capabilityProfile;
    private readonly bool fixedNoContentHttpsCanary;
    private readonly bool localManagementBoundary;
    private readonly bool requireFreshProxyRoute;
    private readonly FixedResolverTrust? fixedResolverTrust;
    private ResolverTlsEvidence? resolverTlsEvidence;
    private UpstreamTunnelEvidence? upstreamTunnelEvidence;
    private int activeControllerHealthChecks,resolverBeforeConnect,resolverAfterReply,targetBeforeConnect,targetAfterReply;
    private readonly object routeMonitorSync=new();
    private readonly TaskCompletionSource routeReady=new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task? routeMonitor;
    private long lastVerifiedRoute;
    private int verifiedRouteSnapshots;
    internal ResolverTlsEvidence? ResolverTls=>Volatile.Read(ref resolverTlsEvidence);
    internal UpstreamTunnelEvidence? TargetTunnel=>Volatile.Read(ref upstreamTunnelEvidence);
    internal ReviewedProxyRouteEvidence? ReviewedRouteEvidence=>requireFreshProxyRoute
        ?new(Volatile.Read(ref activeControllerHealthChecks),Volatile.Read(ref resolverBeforeConnect),Volatile.Read(ref resolverAfterReply),
            Volatile.Read(ref targetBeforeConnect),Volatile.Read(ref targetAfterReply),Volatile.Read(ref verifiedRouteSnapshots)):null;
    // The retained base hash identifies the existing compiled endpoint/WFP
    // policy. Bind the candidate identity separately, rather than pretending
    // an internetClient token is the historical zero-capability identity.
    internal string EffectivePolicySHA256 {get;}
    private readonly byte[] authorization;
    private readonly Task accept;
    private readonly TaskCompletionSource<(uint Pid,long CreatedFileTime)> fixedExchange=new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<(uint Pid,long CreatedFileTime)> localAcknowledged=new(TaskCreationOptions.RunContinuationsAsynchronously);
    private sealed record GatewayFailure(Exception Cause,string Phase);
    private GatewayFailure? failure;
    internal GatewayFailureFeedback? FailureFeedback
    {
        get{var f=Volatile.Read(ref failure);return f is null?null:new(f.Phase,GatewayChildReport.Describe(f.Cause));}
    }
    private ProtectedSession.Admission? admission;
    private int fixedRootTunnelConsumed;
    private int sequence;
    private long transferred;
    private volatile bool disposed;
    internal string Secret { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    internal string SessionId => sessionId;
    internal SessionProxy(OwnedKernelJob job, ProxyChannelLease upstream, string packageSid, string sessionId,
        LpacCapabilityProfile? capabilities=null,bool fixedNoContentHttpsCanary=false,FixedResolverTrust? fixedResolverTrust=null,
        bool localManagementBoundary=false,bool requireFreshProxyRoute=true)
    {
        capabilityProfile=capabilities??LpacCapabilityProfile.None;
        if(fixedNoContentHttpsCanary && !capabilityProfile.IsInternetClientQualification)throw WfpNative.Contract("NoContentHttpsGatewayRequiresFixedInternetClient");
        if(fixedResolverTrust is not null && !fixedNoContentHttpsCanary)throw WfpNative.Contract("ResolverTlsTrustRequiresFixedHead");
        if(localManagementBoundary && (!capabilityProfile.IsInternetClientQualification || fixedNoContentHttpsCanary))
            throw WfpNative.Contract("LocalManagementGatewayPlanDiffers");
        this.fixedNoContentHttpsCanary=fixedNoContentHttpsCanary;
        this.localManagementBoundary=localManagementBoundary;
        this.requireFreshProxyRoute=requireFreshProxyRoute;
        this.fixedResolverTrust=fixedResolverTrust;
        var effective="CPC-GATEWAY-EFFECTIVE-V3;"+PolicySHA256+";"+capabilityProfile.SHA256+
            ";resolver-freshness=authenticated-request-stream;fixed-no-content-https-canary="+fixedNoContentHttpsCanary;
        if(fixedResolverTrust is not null)effective+=";fixed-openssl-head-resolver-explicit-offline-revocation;request=HEAD "+
            FixedOpenSslHead.RequestPath+";client="+FixedOpenSslHead.UserAgent;
        if(localManagementBoundary)effective+=";fixed-local-management-boundary;relay=never";
        if(requireFreshProxyRoute)effective+=";controller-listener-required;controller-route-readback-before-connect-and-after-reply;active-route-snapshots";
        EffectivePolicySHA256=Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(effective)));
        this.job = job; this.upstream = upstream; this.packageSid = packageSid; this.sessionId = Identifiers.Hex32(sessionId);
        authorization = Encoding.ASCII.GetBytes("Basic " + Convert.ToBase64String(Encoding.ASCII.GetBytes(sessionId + ":" + Secret)));
        listener.Server.ExclusiveAddressUse = true;
        try { destinations=GatewayDestinationGuard.CaptureCurrent();upstream.AssertHealthy(); listener.Start(8); accept = Accept(); }
        catch { CryptographicOperations.ZeroMemory(authorization);listener.Stop(); stop.Dispose(); throw; }
    }
    internal void AssertHealthy()
    {
        if (disposed || stop.IsCancellationRequested || failure is not null || accept.IsCompleted || clients.Values.Any(entry=>entry.Work.IsFaulted))
            throw WfpNative.Contract("SessionGatewayStoppedExpiredOrFailed");
        if(ProxyChannelLease.SessionListenerOwner()!=unchecked((uint)Environment.ProcessId))throw WfpNative.Contract("SessionGatewayListenerOwnerDrift");
        if(requireFreshProxyRoute)upstream.AssertControllerListener();
        else upstream.AssertHealthy();
        destinations.AssertCurrent();
    }
    internal void AssertRuntimeHealthy(bool active)
    {
        AssertHealthy();
        if(active && requireFreshProxyRoute)
        {
            AssertRouteCurrent();
            Interlocked.Increment(ref activeControllerHealthChecks);
        }
    }
    internal void BindAdmission(ProtectedSession.Admission permit)
    {
        if(!ReferenceEquals(permit.Gateway,this) || !ReferenceEquals(permit.CapabilityProfile,capabilityProfile) || permit.FixedNoContentHttpsCanary!=fixedNoContentHttpsCanary ||
            permit.UsesFixedOpenSslHead!=(fixedResolverTrust is not null) ||
            permit.IsLocalManagementBoundary!=localManagementBoundary || permit.RequiresReviewedProxyRoute!=requireFreshProxyRoute ||
            capabilityProfile.IsInternetClientQualification && !permit.IsFixedGatewayQualification)throw WfpNative.Contract("GatewayAdmissionOwnerOrCapabilitiesMismatch");
        permit.AssertCurrent();
        if(Interlocked.CompareExchange(ref admission,permit,null) is not null)throw WfpNative.Contract("GatewayAdmissionAlreadyBound");
    }
    internal void AssertReadyToOpen()
    {
        AssertHealthy();
        (Volatile.Read(ref admission)??throw WfpNative.Contract("GatewayAdmissionMissing")).AssertGatewayOpening();
        if(!requireFreshProxyRoute)return;
        lock(routeMonitorSync)
        {
            if(disposed || stop.IsCancellationRequested)throw WfpNative.Contract("GatewayRouteMonitorStopped");
            routeMonitor??=MonitorRoute();
        }
        routeReady.Task.WaitAsync(TimeSpan.FromSeconds(4),stop.Token).GetAwaiter().GetResult();
        AssertHealthy();
        (Volatile.Read(ref admission)??throw WfpNative.Contract("GatewayAdmissionMissing")).AssertGatewayOpening();
        AssertRouteCurrent();
    }

    private async Task MonitorRoute()
    {
        try
        {
            await ProxyRouteObservation.Supervise(token=>ProxyRouteObservation.Capture(upstream,token),()=>
            {
                Volatile.Write(ref lastVerifiedRoute,Stopwatch.GetTimestamp());
                Interlocked.Increment(ref verifiedRouteSnapshots);
                routeReady.TrySetResult();
            },TimeSpan.FromMilliseconds(500),stop.Token).ConfigureAwait(false);
        }
        catch(OperationCanceledException) when(stop.IsCancellationRequested){routeReady.TrySetCanceled(stop.Token);}
        catch(Exception error)
        {
            routeReady.TrySetException(error);
            if(!stop.IsCancellationRequested)Fail(error,"ACTIVE_ROUTE");
        }
    }

    private void AssertRouteCurrent()
    {
        var timestamp=Volatile.Read(ref lastVerifiedRoute);
        if(timestamp==0 || Stopwatch.GetElapsedTime(timestamp)>TimeSpan.FromSeconds(4))
            throw WfpNative.Contract("UpstreamRouteObservationExpired");
    }
    internal void RequireFixedExchange(uint pid,long createdFileTime)
    {
        // The child can receive the final write before the gateway continuation
        // records it. Wait briefly for that observation without another request.
        var peer=fixedExchange.Task.WaitAsync(TimeSpan.FromMilliseconds(500)).GetAwaiter().GetResult();
        if(peer!=(pid,createdFileTime))throw WfpNative.Contract("FixedGatewayExchangeRootIdentityDiffers");
    }
    internal bool FixedExchangeObserved(uint pid,long createdFileTime)
        =>fixedExchange.Task.IsCompletedSuccessfully && fixedExchange.Task.Result==(pid,createdFileTime);
    internal void RequireLocalAcknowledgement(uint pid,long createdFileTime)
    {
        if(!localManagementBoundary ||
            localAcknowledged.Task.WaitAsync(TimeSpan.FromMilliseconds(500)).GetAwaiter().GetResult()!=(pid,createdFileTime))
            throw WfpNative.Contract("LocalGatewayAcknowledgementOwnerDiffers");
    }
    private void AssertForwardingCurrent()
    {
        (Volatile.Read(ref admission)??throw WfpNative.Contract("GatewayAdmissionMissing")).AssertForwardingCurrent();
        if(disposed || stop.IsCancellationRequested || failure is not null)throw WfpNative.Contract("GatewayForwardingStopped");
        if(requireFreshProxyRoute)AssertRouteCurrent();
        destinations.AssertCurrent();
    }

    internal void Revoke()
    {
        stop.Cancel(); listener.Stop();
        foreach (var entry in clients.Values) entry.Client.Dispose();
    }
    public void Dispose()
    {
        if (disposed) return; disposed = true; Revoke();
        var drained = false;
        try
        {
            if (!accept.Wait(TimeSpan.FromSeconds(3))) throw new TimeoutException("GatewayAcceptDrainUnknown");
            Task? monitor;
            lock(routeMonitorSync)monitor=routeMonitor;
            var tasks = clients.Values.Select(entry => entry.Work);
            if(monitor is not null)tasks=tasks.Append(monitor);
            drained = Task.WhenAll(tasks).Wait(TimeSpan.FromSeconds(3));
            if (!drained) throw new TimeoutException("GatewayTunnelDrainUnknown");
        }
        finally { if (drained) { CryptographicOperations.ZeroMemory(authorization); stop.Dispose(); } }
    }
}
