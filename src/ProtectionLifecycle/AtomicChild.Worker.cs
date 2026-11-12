using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;

using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Fixed code paths executed by the already-admitted restricted child.
// This file owns no admission decision, process handle, Job handle, or lease.
internal sealed partial class AtomicChild
{
    internal static void AssertOfflineConsoleWorkerIdentity()
    {
        using var self=new SafeProcessHandle((IntPtr)(-1),false);
        var token=ReadToken(self);
        if(!token.IsAppContainer || !token.LpacAccessCheckObserved || token.ApplicationPackageAccessMask!=2 ||
            token.PackageSid is null || token.IntegritySid!="S-1-16-4096" || !LpacCapabilityProfile.None.Matches(token.CapabilityCount,token.Capabilities))
            throw WfpNative.Contract("OfflineConsoleWorkerIdentityRefused");
        AssertNoChildCreation(self);
    }
    internal static int RunOfflineTlsChild(OfflineTlsProbe probe)
    {
        var id=Identifiers.Hex32(Environment.GetEnvironmentVariable(OfflineTlsQualification.SessionVariable(probe))??"");
        if(new[]{"CPC_SESSION_ID","CPC_SESSION_SECRET","CPC_NETWORK_PLAN","CPC_RESOURCE_PLAN","CPC_GPU_PLAN",
            "HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","OPENSSL_CONF","OPENSSL_MODULES","SSL_CERT_FILE","SSL_CERT_DIR"}
            .Any(name=>Environment.GetEnvironmentVariable(name) is not null))
            throw WfpNative.Contract("OfflineTlsWorkerCannotBorrowOtherAuthority");
        using var self=new SafeProcessHandle((IntPtr)(-1),false);
        var token=ReadToken(self,false);
        if(!token.IsAppContainer || token.PackageSid is null || token.IntegritySid!="S-1-16-4096" ||
            !FixedCapabilities(true).Matches(token.CapabilityCount,token.Capabilities))
            throw WfpNative.Contract("OfflineTlsWorkerIdentityRefused");
        if(probe==OfflineTlsProbe.Schannel)
        {
            if(Environment.GetEnvironmentVariable(OpenSslModuleLease.ReleaseVariable) is not null)
                throw WfpNative.Contract("SchannelWorkerCannotBorrowOpenSslBinding");
            Console.WriteLine(JsonSerializer.Serialize(SchannelAcquisition.Observe(id)));
            return 0;
        }
        var witness=OpenSslOfflineWitness.Observe(id,release:Environment.GetEnvironmentVariable(OpenSslModuleLease.ReleaseVariable));
        Console.WriteLine(JsonSerializer.Serialize(witness));
        return witness.Complete?0:3;
    }
    internal static void SetPrivateRuntimeDirectories(IDictionary<string,string> environment,string ownedDirectory)
    {
        // Pure mapping only. The creation owner supplies its bound profile or
        // resource workspace; this helper accepts no path operation or grant.
        if(string.IsNullOrEmpty(ownedDirectory) || ownedDirectory.Contains('\0'))
            throw new InvalidDataException("OwnedRuntimeDirectoryRequired");
        foreach(var name in new[]{"TEMP","TMP","LOCALAPPDATA","USERPROFILE"})environment[name]=ownedDirectory;
    }
    internal static void ConfigureFixedChildCulture()
    {
        // Only this fixed worker opts in. Do not alter the owner, GUI, Windows
        // locale/time zone or grant registry access for framework localization.
        var invariant=System.Globalization.CultureInfo.InvariantCulture;
        System.Globalization.CultureInfo.DefaultThreadCurrentCulture=invariant;
        System.Globalization.CultureInfo.DefaultThreadCurrentUICulture=invariant;
        System.Globalization.CultureInfo.CurrentCulture=invariant;
        System.Globalization.CultureInfo.CurrentUICulture=invariant;
    }
    internal static int RunGatewayQualificationCanary()
        =>RunGatewayQualificationCanaryCore(LpacCapabilityProfile.None,false);
    internal static int RunInternetClientGatewayQualificationCanary()
        =>RunGatewayQualificationCanaryCore(LpacCapabilityProfile.InternetClientQualification,true);
    internal static int RunNoContentHttpsCanary()
        =>RunGatewayQualificationCanaryCore(LpacCapabilityProfile.InternetClientQualification,true,true);
    internal static int RunFixedOpenSslHeadCanary()
        =>RunGatewayQualificationCanaryCore(LpacCapabilityProfile.InternetClientQualification,true,true,useOpenSsl:true);
    internal static int RunZeroCapabilityComparisonCanary()
        =>RunGatewayQualificationCanaryCore(LpacCapabilityProfile.None,true);
    internal static int RunLocalManagementBoundaryCanary()
        =>RunGatewayQualificationCanaryCore(LpacCapabilityProfile.InternetClientQualification,false,localManagementBoundary:true);
    private static int RunGatewayQualificationCanaryCore(LpacCapabilityProfile expectedCapabilities,bool captureCapabilityContent,
        bool fixedNoContentHttpsCanary=false,bool useOpenSsl=false,bool localManagementBoundary=false)
    {
        var phase="ENVIRONMENT";var id=Environment.GetEnvironmentVariable("CPC_SESSION_ID")??"";GatewayChildReport result;
        GatewayNetworkContent? networkContent=null;
        GatewayCapabilityEndpoint? endpoint=null;
        try
        {
            ConfigureFixedChildCulture();
            var secret=Environment.GetEnvironmentVariable("CPC_SESSION_SECRET");
            var publicTimeZone=Environment.GetEnvironmentVariable("CPC_PUBLIC_TIMEZONE_ID")??throw new InvalidDataException("FixedPublicTimeZoneMissing");
            _=PublicTimeZoneDefinition.PathFor(publicTimeZone,"ZONE_DEFINITION");
            if(id.Length==0 || secret is null || new[]{"CPC_RESOURCE_PLAN","CPC_NETWORK_PLAN","CPC_GPU_PLAN"}.Any(name=>Environment.GetEnvironmentVariable(name) is not null))
                throw new InvalidDataException("FixedGatewayEnvironmentRefused");
            _=Identifiers.Hex32(id);_=Identifiers.Hash(secret);
            var openSslRelease=Environment.GetEnvironmentVariable(OpenSslModuleLease.ReleaseVariable);
            if(useOpenSsl)
            {
                _=Identifiers.Hex32(openSslRelease??"");
                if(new[]{"OPENSSL_CONF","OPENSSL_MODULES","SSL_CERT_FILE","SSL_CERT_DIR"}
                    .Any(name=>Environment.GetEnvironmentVariable(name) is not null))
                    throw new InvalidDataException("FixedOpenSslEnvironmentRefused");
            }
            else if(openSslRelease is not null)throw new InvalidDataException("UnrelatedOpenSslReleaseBindingRefused");
            // As in the verified resource worker, query basic self identity
            // without token duplication. The original Broker checks the exact
            // held LPAC before resume and on every admitted member inspection.
            phase="IDENTITY";using var current=new SafeProcessHandle((IntPtr)(-1),false);var token=ReadToken(current,false);
            if(!token.IsAppContainer || token.PackageSid is null || !expectedCapabilities.Matches(token.CapabilityCount,token.Capabilities) || token.IntegritySid!="S-1-16-4096")
                result=GatewayChildReport.Result(id,phase,125);
            else
            {
                if(localManagementBoundary)
                {
                    phase="SOCKET_INITIALIZATION";
                    var local=LocalManagementBoundary.RunWorker(id,secret).GetAwaiter().GetResult();
                    Console.WriteLine(JsonSerializer.Serialize(local));
                    return local.ExitCode;
                }
                if(captureCapabilityContent)
                {
                    // One unbound socket is created and immediately closed;
                    // no connect/bind/listen/IOCTL or external request. Continue
                    // the real reads even when endpoint creation is refused.
                    phase="NETWORK_CONTENT_READS";endpoint=GatewayCapabilityEndpoint.Observe();networkContent=GatewayCapabilityContent.Capture();
                    if(!(fixedNoContentHttpsCanary?networkContent.FixedNoContentHttpsCanaryEligible:networkContent.AllThreeDenied))
                    {
                        phase="NETWORK_CONTENT_REQUIRES_ANALYSIS";
                        throw new InvalidDataException("FixedNetworkCapabilityReadRequiresOwnerAnalysis");
                    }
                    if(endpoint is not {Created:true,OwnedHandleClosed:true,Phase:"SOCKET_CLOSED"})
                    {
                        phase=endpoint.Phase=="SOCKET_INITIALIZATION"?"HTTPS_SOCKET_INITIALIZATION":"HTTPS_SOCKET_CREATE";
                        throw new InvalidDataException("FixedNetworkCapabilityEndpointNotConfirmed");
                    }
                }
                // The historical leaf-only lease did not repair predefined
                // hive mapping. Use the original owner's public calendar
                // with a pinned managed compatibility adapter; never add
                // registryRead or treat the adapter as a privacy boundary.
                phase="TIMEZONE_PUBLIC_CACHE";
                PublicTimeZoneSnapshot.ApplyForFixedWorker(
                    Environment.GetEnvironmentVariable("CPC_PUBLIC_TIMEZONE_SNAPSHOT")??throw new InvalidDataException("FixedPublicTimeZoneSnapshotMissing"),
                    Environment.GetEnvironmentVariable("CPC_PUBLIC_TIMEZONE_SHA256")??throw new InvalidDataException("FixedPublicTimeZoneDigestMissing"),id,publicTimeZone);
                phase="TIMEZONE_LOCAL_BINDING";var localZone=TimeZoneInfo.Local;
                // Keep the OS's current daylight-saving setting. A public
                // definition's default rules do not override local settings.
                if(localZone.Id!=publicTimeZone)
                    throw new InvalidDataException("FixedGatewayLocalTimeZoneDefinitionDiffers");
                phase="HTTPS_SETTINGS";
                var status=useOpenSsl?RunFixedOpenSslHead(id,secret,openSslRelease!,p=>phase=p).GetAwaiter().GetResult():
                    RunFixedSessionHead(id,secret,p=>phase=p);
                result=GatewayChildReport.Result(id,status is >=200 and <400?"COMPLETE":"HTTPS",status is >=200 and <400?42:126,status);
            }
        }
        catch(Exception ex){result=GatewayChildReport.Result(id,phase,125,failure:ex);}
        if(localManagementBoundary)
        {
            Console.WriteLine(JsonSerializer.Serialize(new LocalManagementBoundaryReport(1,result.SessionId,result.Pid,result.Phase,
                result.ExitCode,result.Errors[0].Code,[])));
            return result.ExitCode;
        }
        Console.WriteLine(captureCapabilityContent?
            JsonSerializer.Serialize(new GatewayCapabilityChildReport(1,result,endpoint,networkContent)):JsonSerializer.Serialize(result));return result.ExitCode;
    }
    private static async Task<int> RunFixedOpenSslHead(string sessionId,string sessionSecret,string release,Action<string> phase)
    {
        phase("HTTPS_TLS_POLICY");
        var trust=FixedOpenSslHeadTrust.ForWorker(release);
        using var modules=OpenSslModuleLease.OpenForInstalledWorker(release);
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var tunnel=await SessionProxy.OpenFixedClientTunnel(sessionId,sessionSecret,deadline.Token,phase).ConfigureAwait(false);
        FixedOpenSslHeadTrust.RequireCurrent(DateTimeOffset.UtcNow);
        return await FixedOpenSslHead.SendAsync(modules,tunnel,trust.Root,trust.Crls,deadline.Token,phase).ConfigureAwait(false);
    }
    private static int RunFixedSessionHead(string sessionId,string sessionSecret,Action<string>? phase=null)
    {
        phase?.Invoke("HTTPS_SETTINGS");
        var tunnelConsumed=0;
        using var handler=new SocketsHttpHandler {UseProxy=false,AllowAutoRedirect=false,UseCookies=false,
            ConnectCallback=async (context,cancel)=>
            {
                if(context.DnsEndPoint.Host!=SessionProxy.Target || context.DnsEndPoint.Port!=443)throw WfpNative.Contract("FixedSessionHttpTargetRefused");
                SessionProxy.ConsumeFixedTunnelAttempt(ref tunnelConsumed);
                var tunnel=await SessionProxy.OpenFixedClientTunnel(sessionId,sessionSecret,cancel,phase).ConfigureAwait(false);
                phase?.Invoke("HTTPS_TLS_HANDSHAKE");
                return tunnel;
            }};
        if(phase is not null)
            handler.PlaintextStreamFilter=(context,_)=>
            {
                phase("HTTPS_HTTP_EXCHANGE");
                return ValueTask.FromResult(context.PlaintextStream);
            };
        phase?.Invoke("HTTPS_TLS_POLICY");handler.SslOptions=SessionProxy.OfflineTls();
        phase?.Invoke("HTTPS_CLIENT");
        using var client=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(10)};
        // Headers only; an unread GET body would abort its own TLS tunnel.
        using var request=new HttpRequestMessage(HttpMethod.Head,"https://"+SessionProxy.Target+"/") {
            Version=System.Net.HttpVersion.Version11,VersionPolicy=HttpVersionPolicy.RequestVersionExact};
        phase?.Invoke("HTTPS_SEND");
        using var response=client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();
        return (int)response.StatusCode;
    }
    internal static int RunCanary()
    {
        using var current=new SafeProcessHandle((IntPtr)(-1),false);var token=ReadToken(current);
        if(!token.IsAppContainer || token.CapabilityCount!=0 || token.IntegritySid!="S-1-16-4096")return 125;
        var plan=Environment.GetEnvironmentVariable("CPC_NETWORK_PLAN");
        var gpuPlan=Environment.GetEnvironmentVariable("CPC_GPU_PLAN");if(plan is not null && gpuPlan is not null)return 125;
        var sessionId=Environment.GetEnvironmentVariable("CPC_SESSION_ID");
        var sessionSecret=Environment.GetEnvironmentVariable("CPC_SESSION_SECRET");
        if(sessionId is not null || sessionSecret is not null)
        {
            if(!token.LpacAccessCheckObserved)return 125;
            if(plan is not null || gpuPlan is not null || sessionId is null || sessionSecret is null)return 125;
            _=Identifiers.Hex32(sessionId);_=Identifiers.Hash(sessionSecret);
            return RunFixedSessionHead(sessionId,sessionSecret) is >=200 and <400?42:126;
        }
        if(gpuPlan is not null)
        {
            if(gpuPlan.Length>256 || !token.LpacAccessCheckObserved || token.ApplicationPackageAccessMask!=2)
                throw WfpNative.Contract("GpuPlanOrLpacIdentityRefused");
            var gpu=JsonSerializer.Deserialize<GpuProbePlan>(gpuPlan)??throw WfpNative.Contract("GpuPlanMissing");gpu.Validate();
            var progress=gpu.ProgressProtocol==1?new GpuCallProgressWriter(Console.Out,gpu.Nonce,Environment.ProcessId):null;
            var computed=GpuQualification.Compute(gpu,GpuQualification.LpacScope,progress);Console.WriteLine(JsonSerializer.Serialize(computed));return GpuQualification.Qualified(computed)?0:3;
        }
        if(plan is not null)
        {
            if(plan.Length>8192)throw WfpNative.Contract("NetworkPlanSizeRefused");
            var network=JsonSerializer.Deserialize<NetworkProbePlan>(plan)??throw WfpNative.Contract("MissingNetworkPlan");network.Validate();
            var report=NetworkQualification.RunChild(network).GetAwaiter().GetResult();Console.WriteLine(JsonSerializer.Serialize(report));
            if(network.Kind==NetworkProbeKind.ProxySession && report.FailureMask==0)
            {
                // Fixed owned-loopback attempts keep the admitted child alive
                // during watchdog qualification. No children or extra targets.
                var clock=Stopwatch.StartNew();while(clock.ElapsedMilliseconds<60000)
                {Thread.Sleep(100);if(!NetworkQualification.NegativeCasesEligible(NetworkQualification.RawCases(network).GetAwaiter().GetResult()))return 126;}
                return 124; // Finite fallback is not watchdog success.
            }
            return report.FailureMask;
        }
        Thread.Sleep(200);return 42; // No network, state, file writes or children.
    }
    internal static int RunResourceCanary()
    {
        var phase="self-token";
        try
        {
            // The trusted manager MUST have checked LPAC on this exact held
            // process before ResumeQuarantined. A child cannot issue admission;
            // it only queries its basic identity, then attempts real resource
            // denial. Do not require token duplication inside the restricted
            // worker merely to repeat a privileged management observation.
            using var current=new SafeProcessHandle((IntPtr)(-1),false);var token=ReadToken(current,false);
            if(!token.IsAppContainer || token.CapabilityCount!=0 || token.IntegritySid!="S-1-16-4096" || token.PackageSid is null)
                throw WfpNative.Contract("RestrictedResourceChildTokenMismatch");
            phase="resource-input";return ResourceChildRunner.RunChild(token.PackageSid);
        }
        catch(Exception ex)
        {
            var native=ex.Data["Stage"] as string;
            if(native is not null && (native.Length>80 || native.Any(c=>!char.IsAsciiLetterOrDigit(c))))native=null;
            Console.WriteLine(JsonSerializer.Serialize(new ResourceBootstrapFailure(1,"RESOURCE_BOOTSTRAP_FAILURE",phase,ex.GetType().Name,
                ex is Win32Exception win32?win32.NativeErrorCode:ex.HResult,native)));return 125;
        }
    }
}
