using ClaudeCodeProtection.Security;

namespace ClaudeProtection;

// Applies only to this application's two immutable diagnostic HTTP requests.
// It does NOT filter arbitrary Claude/tool traffic or proxy-side DNS resolution.
internal static class DiagnosticNetworkTargetPolicy
{
    private const string ExpectedProxy="http://127.0.0.1:7890/";

    internal static bool IsApprovedDiagnostic(string target,string proxy)
    {
        if(!Uri.TryCreate(proxy,UriKind.Absolute,out var via) ||
           !string.Equals(via.AbsoluteUri,ExpectedProxy,StringComparison.Ordinal) ||
           !Uri.TryCreate(target,UriKind.Absolute,out var destination) ||
           destination.Scheme!=Uri.UriSchemeHttps || destination.Port!=443 ||
           !string.IsNullOrEmpty(destination.UserInfo) ||
           !string.IsNullOrEmpty(destination.Query) ||
           !string.IsNullOrEmpty(destination.Fragment) ||
           !ProxyDestinationPolicy.IsPublicHostnameCandidate(destination.IdnHost))
            return false;

        return (destination.IdnHost=="api.anthropic.com" && destination.AbsolutePath=="/v1/models") ||
               (destination.IdnHost=="www.cloudflare.com" && destination.AbsolutePath=="/cdn-cgi/trace");
    }

    // Compatibility shim for consumers/tests of this bounded diagnostic.
    // A syntactically public hostname is *never* DNS-rebinding evidence.
    internal static bool DestinationRequiresRestriction(string? host)=>
        !ProxyDestinationPolicy.IsPublicHostnameCandidate(host);
}
