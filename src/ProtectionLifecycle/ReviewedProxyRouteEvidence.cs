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

internal sealed record ReviewedProxyRouteEvidence(int ActiveControllerHealthChecks,int ResolverBeforeConnect,int ResolverAfterReply,
    int TargetBeforeConnect,int TargetAfterReply,int VerifiedRouteSnapshots)
{
    internal bool FixedExchangeCovered=>ActiveControllerHealthChecks>0 && VerifiedRouteSnapshots>0 && ResolverBeforeConnect==1 && ResolverAfterReply==1 &&
        TargetBeforeConnect==1 && TargetAfterReply==1;
}

// Owned by ProtectedSession, never a machine proxy or an independently usable
// launch service. The initial compiled policy authorizes one synthetic target.
