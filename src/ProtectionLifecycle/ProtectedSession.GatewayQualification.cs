namespace ProtectionLifecycle;

// Deterministic compiled gateway qualification modes. No request data,
// environment values, persisted evidence, or LLM output can select a mode.
internal sealed partial class ProtectedSession
{
    private enum GatewayMode { None, Basic, Winsock, Transport, Provider, InternetClient, ZeroCapabilityComparison, NoContentHttps, OpenSslHead,
        LocalManagement, ReviewedRouteOpenSslHead }
    private enum WinsockScope { None, Catalog, Transport, Provider }
    private sealed record GatewayQualification(WinsockScope Winsock,LpacCapabilityProfile Capabilities,bool CaptureContent,bool NoContentHttps,
        string ChildCommand,bool UsesFixedOpenSslHead=false,bool LocalManagement=false,bool ReviewedProxyRoute=false)
    {
        internal static GatewayQualification? For(GatewayMode mode)=>mode switch {
            GatewayMode.None=>null,
            GatewayMode.Basic=>new(WinsockScope.None,LpacCapabilityProfile.None,false,false,"gateway-qualification-child"),
            GatewayMode.Winsock=>new(WinsockScope.Catalog,LpacCapabilityProfile.None,false,false,"gateway-qualification-child"),
            GatewayMode.Transport=>new(WinsockScope.Transport,LpacCapabilityProfile.None,false,false,"gateway-qualification-child"),
            GatewayMode.Provider=>new(WinsockScope.Provider,LpacCapabilityProfile.None,false,false,"gateway-qualification-child"),
            GatewayMode.InternetClient=>new(WinsockScope.Provider,LpacCapabilityProfile.InternetClientQualification,true,false,"internet-client-gateway-qualification-child"),
            GatewayMode.ZeroCapabilityComparison=>new(WinsockScope.Provider,LpacCapabilityProfile.None,true,false,"zero-capability-comparison-child"),
            GatewayMode.NoContentHttps=>new(WinsockScope.Provider,LpacCapabilityProfile.InternetClientQualification,true,true,"no-content-https-canary-child"),
            GatewayMode.OpenSslHead=>new(WinsockScope.Provider,LpacCapabilityProfile.InternetClientQualification,true,true,"fixed-openssl-head-child",true),
            GatewayMode.ReviewedRouteOpenSslHead=>new(WinsockScope.Provider,LpacCapabilityProfile.InternetClientQualification,true,true,
                "fixed-openssl-head-child",UsesFixedOpenSslHead:true,ReviewedProxyRoute:true),
            GatewayMode.LocalManagement=>new(WinsockScope.Provider,LpacCapabilityProfile.InternetClientQualification,false,false,
                LocalManagementBoundary.WorkerCommand,LocalManagement:true),
            _=>throw WfpNative.Contract("UnknownFixedGatewayMode")
        };
    }
}
