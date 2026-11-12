using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Security;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

// The installed Broker's session owner. Diagnostic JSON, supplied targets and
// serialized permits are deliberately absent from this API. Both request kinds
// use this owner; only its fixed installed synthetic workload is implemented.
internal sealed partial class ProtectedSession
{
    // Current artifact still needs bounded runtime/install qualification.
    // Renewed human authorization permits that work, not a positive clearance.
    // There is no caller flag/environment/config override.
    internal static bool SystemTestingBlocked => true;
    internal static void AssertSystemTestingAllowed()
    {if(SystemTestingBlocked)throw new InvalidOperationException("SYSTEM_ARTIFACT_NOT_QUALIFIED: bounded artifact/runtime/install qualification required");}
    private const string ResourceScope = "INSTALLED_BROKER_CANARY_ONLY;workspace=none;tools=none;gpu=none;no-breakaway";
    internal const int GitWorkflowTimeoutMs=60000;
    private readonly FixedLayout layout;
    private readonly ProtectedState state;
    private readonly VerifiedVersion version;
    // Chosen only by the compiled fixed gateway operation, never by data,
    // environment, persisted evidence or a formal-launch caller.
    private readonly GatewayQualification? qualification;
    private bool IsGatewayQualification=>qualification is not null;
    private LpacCapabilityProfile CapabilityProfile=>qualification?.Capabilities??LpacCapabilityProfile.None;
    private bool CaptureCapabilityContent=>qualification?.CaptureContent==true;
    private bool FixedNoContentHttpsCanary=>qualification?.NoContentHttps==true;
    private bool UsesFixedOpenSslHead=>qualification?.UsesFixedOpenSslHead==true;
    private bool IsLocalManagementBoundary=>qualification?.LocalManagement==true;
    private bool RequiresReviewedProxyRoute=>!IsGatewayQualification || qualification?.ReviewedProxyRoute==true;
    private SessionWinsockReadAccess? winsockAccess;
    private const long GatewayQualificationLimitMs=30000;
    private readonly string id = Guid.NewGuid().ToString("N"), pointerSHA256;
    private readonly Stopwatch clock = Stopwatch.StartNew();
    private readonly DateTimeOffset startedUtc=DateTimeOffset.UtcNow;
    private int resourceDurationMs=30000;
    private IReadOnlyList<EnvironmentEvidence> environment;
    private readonly EnvironmentExpectations? expectations;
    private readonly string? expectationsSHA256;
    private readonly string expectationsReason;
    private long lastCollectionMs=-1;
    private readonly IReadOnlyList<EnvironmentEvidence> systemSafety;
    private static readonly string[] SystemRequirements={"current-trusted-installation","current-gateway-kernel-enforcement",
        "host-sensitive-resource-denial","authorized-workspace-toolchain-device-grants"};
    private readonly List<PersistentFence> fences = new();
    private OwnedKernelJob? job;
    private SessionProxy? gateway;
    private string? sid;
    private Admission? admission;
    private Preparation? preparation;
    private GatewayChildReport? gatewayChildFeedback;
    private GatewayCapabilityChildReport? gatewayCapabilityFeedback;
    private LocalManagementBoundaryReport? localManagementFeedback;
    private object? localManagementReference;
    private ProxyRouteObservation? proxyRoute;
    private bool localManagementPositiveControl;
    private ProtectionRuntimeLease? runtime;
    private SessionResources? resources;
    private ProtectedSession(FixedLayout layout,ProtectedState state,VerifiedVersion version,GatewayMode gatewayMode=GatewayMode.None)
    {
        qualification=GatewayQualification.For(gatewayMode);
        this.layout=layout;this.state=state;this.version=version;
        pointerSHA256=state.Read("current.json",4096).SHA256;
        (expectations,expectationsSHA256,expectationsReason)=ReadExpectations();
        environment=MissingEnvironment();
        // Separate, mandatory security evidence. Environmental consistency
        // cannot stand in for any of these unqualified system properties.
        version.AssertHeld(state);
        systemSafety=Array.AsReadOnly(SystemRequirements.Select(name=>new EnvironmentEvidence(name,
            name=="current-trusted-installation"?"PASS":"UNKNOWN",
            name=="current-trusted-installation"?"HELD_CURRENT_INSTALLATION_ASSETS":
                name=="current-gateway-kernel-enforcement"?"CURRENT_KERNEL_FUNCTIONALITY_AND_UPSTREAM_LITERAL_NON_DIRECT_ROUTE_NOT_QUALIFIED":
                "CURRENT_ARTIFACT_SECURITY_QUALIFICATION_OR_RESOURCE_GRANT_MISSING",clock.ElapsedMilliseconds,120000)).ToArray());
    }

}
