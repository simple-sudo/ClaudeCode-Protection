using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ProtectionLifecycle;

// Private to the original session gateway. This never exports adapter names,
// physical addresses, IPs or identifiers, and never changes a network setting.
// An incomplete read or any address-set drift revokes use of the snapshot.
internal sealed class GatewayDestinationGuard
{
    private readonly Func<IPAddress[]> capture;
    private readonly Func<long> clock;
    private readonly string[] addresses;
    private readonly object sync=new();
    private long lastChecked;
    private bool revoked;
    internal static GatewayDestinationGuard CaptureCurrent()=>new(ReadHostAddresses,()=>Environment.TickCount64);
    internal GatewayDestinationGuard(Func<IPAddress[]> capture,Func<long> clock)
    {
        this.capture=capture??throw new ArgumentNullException(nameof(capture));
        this.clock=clock??throw new ArgumentNullException(nameof(clock));
        addresses=Snapshot();lastChecked=clock();
        if(lastChecked<0)throw new InvalidDataException("GatewayAddressClockUnconfirmed");
    }
    private static IPAddress[] ReadHostAddresses()
    {
        // Include down, loopback and virtual interfaces: an address is still
        // local even when its adapter is not selected for the default route.
        var adapters=NetworkInterface.GetAllNetworkInterfaces();
        if(adapters.Length is <1 or >256)throw new InvalidDataException("GatewayAddressInventoryUnconfirmed");
        var result=new List<IPAddress>();
        foreach(var adapter in adapters)
            foreach(var entry in adapter.GetIPProperties().UnicastAddresses)
            {
                if(result.Count==4096)throw new InvalidDataException("GatewayAddressInventoryUnconfirmed");
                result.Add(entry.Address);
            }
        return result.ToArray();
    }
    private static string Key(IPAddress address)
    {
        if(address is null || address.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
            throw new InvalidDataException("GatewayAddressInventoryUnconfirmed");
        if(address.IsIPv4MappedToIPv6)address=address.MapToIPv4();
        // Compare address bytes, including scoped local IPv6 aliases without
        // allowing scope IDs to disguise the same endpoint as a remote host.
        return Convert.ToHexString(address.GetAddressBytes());
    }
    private string[] Snapshot()
    {
        try
        {
            var values=capture();
            if(values is null || values.Length is <1 or >4096)throw new InvalidDataException("GatewayAddressInventoryUnconfirmed");
            return values.Select(Key).Distinct(StringComparer.Ordinal).OrderBy(x=>x,StringComparer.Ordinal).ToArray();
        }
        catch(Exception error)when(error is NetworkInformationException or SocketException or PlatformNotSupportedException or
            System.Security.SecurityException or InvalidOperationException or ArgumentException)
        {
            // Fixed refusal only. Native messages can contain host details.
            throw new InvalidDataException("GatewayAddressInventoryUnconfirmed");
        }
    }
    internal void AssertCurrent(bool force=false)
    {
        lock(sync)
        {
            if(revoked)throw new InvalidDataException("GatewayAddressSnapshotRevoked");
            try
            {
                var now=clock();
                if(now<lastChecked)throw new InvalidDataException("GatewayAddressClockUnconfirmed");
                if(!force && now-lastChecked<1000)return;
                if(!addresses.SequenceEqual(Snapshot(),StringComparer.Ordinal))throw new InvalidDataException("GatewayHostAddressSetChanged");
                lastChecked=now;
            }
            catch{revoked=true;throw;}
        }
    }
    internal void RequireRemotePublicAddress(IPAddress destination)
    {
        AssertCurrent(true);
        if(!ClaudeCodeProtection.Security.ProxyDestinationPolicy.IsPublicAddressCandidate(destination) ||
            Array.BinarySearch(addresses,Key(destination),StringComparer.Ordinal)>=0)
            throw new InvalidDataException("GatewayLocalOrSpecialDestinationRefused");
    }
}
