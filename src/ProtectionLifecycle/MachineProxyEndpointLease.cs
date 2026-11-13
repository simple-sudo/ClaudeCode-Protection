using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using ClaudeCodeProtection.Security;

namespace ProtectionLifecycle;

internal sealed record ProxyProcessIdentity(uint Pid, long CreatedFileTime, string DiskImageSHA256, string FileIdentity);
internal sealed record MachineProxyEndpoint(string Address, ushort Port, ProtocolType Protocol, ulong InterfaceLuid);

// Internal authorization input for a future kernel enforcement owner. All
// times must come from its same monotonic clock. A listener or observed flow
// alone cannot issue or renew this lease.
internal sealed class MachineProxyEndpointLease
{
    private readonly Guid quarantine;
    private readonly ProxyProcessIdentity process;
    private readonly string selectedRouteDigest;
    private readonly HashSet<MachineProxyEndpoint> endpoints;
    private readonly long issued, expires;
    private long lastCheck;
    private bool revoked;

    internal MachineProxyEndpointLease(Guid quarantine, ProxyProcessIdentity process, string selectedRouteDigest,
        IReadOnlyCollection<MachineProxyEndpoint> endpoints, long issued, long expires)
    {
        if (quarantine == Guid.Empty || process.Pid == 0 || process.CreatedFileTime <= 0 ||
            !Digest(process.DiskImageSHA256) || string.IsNullOrWhiteSpace(process.FileIdentity) ||
            !Digest(selectedRouteDigest) || endpoints.Count is <1 or >32 || issued < 0 || expires <= issued ||
            expires - issued > 30 * Stopwatch.Frequency)
            throw new ArgumentException("MachineProxyEndpointLeaseBindingInvalid");
        this.endpoints = new(endpoints);
        if (this.endpoints.Count != endpoints.Count || this.endpoints.Any(e => !ValidEndpoint(e)))
            throw new ArgumentException("MachineProxyEndpointLeaseEndpointsInvalid");
        this.quarantine = quarantine;
        this.process = process;
        this.selectedRouteDigest = selectedRouteDigest;
        this.issued = lastCheck = issued;
        this.expires = expires;
    }

    // Caller holds the trusted network owner lock. A different current
    // identity, generation or route invalidates the whole lease irreversibly.
    internal bool Allows(Guid currentQuarantine, ProxyProcessIdentity? currentProcess, string? currentRouteDigest,
        MachineProxyEndpoint endpoint, long now)
    {
        if (revoked) return false;
        if (now < issued || now < lastCheck || now >= expires || currentQuarantine != quarantine ||
            currentProcess != process || currentRouteDigest != selectedRouteDigest)
        {
            revoked = true;
            return false;
        }
        lastCheck = now;
        return endpoints.Contains(endpoint);
    }

    private static bool ValidEndpoint(MachineProxyEndpoint endpoint) =>
        endpoint.Port != 0 && endpoint.InterfaceLuid != 0 &&
        endpoint.Protocol is ProtocolType.Tcp or ProtocolType.Udp &&
        IPAddress.TryParse(endpoint.Address, out var address) &&
        address.ToString() == endpoint.Address &&
        (address.AddressFamily != AddressFamily.InterNetworkV6 || address.ScopeId == 0) &&
        ProxyDestinationPolicy.IsPublicAddressCandidate(address);

    private static bool Digest(string? value) =>
        value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
}
