using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace ProtectionLifecycle;

internal sealed record MachineEgressRoute(uint InterfaceIndex, ulong InterfaceLuid, IPAddress Source,
    IPAddress Prefix, byte PrefixLength, IPAddress NextHop, uint Metric);

internal static class MachineEgressRouteReader
{
    internal static MachineEgressRoute Read(MachineEgressTrialEndpoint endpoint)
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess)
            throw new PlatformNotSupportedException("Windows x64 route ABI required");

        var source = Address.From(endpoint.Source);
        var destination = Address.From(endpoint.Receiver);
        var assignment = new UnicastRow { Address = source, Index = endpoint.InterfaceIndex };
        Check(GetUnicastIpAddressEntry(ref assignment), "GetUnicastIpAddressEntry");
        if (assignment.Index != endpoint.InterfaceIndex || assignment.Luid == 0 ||
            !assignment.Address.ToAddress().Equals(endpoint.Source) ||
            assignment.DadState != 4 || assignment.ValidLifetime == 0)
            throw new InvalidDataException("MachineEgressSourceAssignmentChanged");

        var luid = assignment.Luid;
        Check(GetBestRoute2(in luid, endpoint.InterfaceIndex, in source, in destination, 0,
            out var route, out var selectedSource), "GetBestRoute2");
        if (route.Index != endpoint.InterfaceIndex || route.Luid != luid ||
            !selectedSource.ToAddress().Equals(endpoint.Source) || route.Prefix.Family != destination.Family ||
            route.NextHop.Family != destination.Family)
            throw new InvalidDataException("MachineEgressRouteDoesNotMatchBoundSender");

        var prefix = route.Prefix.ToAddress();
        if (!Contains(prefix, route.PrefixLength, endpoint.Receiver))
            throw new InvalidDataException("MachineEgressRoutePrefixDoesNotCoverReceiver");
        return new(route.Index, route.Luid, selectedSource.ToAddress(), prefix,
            route.PrefixLength, route.NextHop.ToAddress(), route.Metric);
    }

    private static bool Contains(IPAddress prefix, byte length, IPAddress receiver)
    {
        var network = prefix.GetAddressBytes();
        var address = receiver.GetAddressBytes();
        if (network.Length != address.Length || length > network.Length * 8) return false;
        var octets = length / 8;
        var bits = length % 8;
        return network.AsSpan(0, octets).SequenceEqual(address.AsSpan(0, octets)) &&
            (bits == 0 || ((network[octets] ^ address[octets]) >> (8 - bits)) == 0);
    }

    private static void Check(uint status, string stage)
    {
        if (status != 0) throw new Win32Exception(unchecked((int)status), stage);
    }

    // Windows SDK SOCKADDR_INET, MIB_UNICASTIPADDRESS_ROW and MIB_IPFORWARD_ROW2.
    [StructLayout(LayoutKind.Explicit, Size = 28)]
    private struct Address
    {
        [FieldOffset(0)] internal ushort Family;
        [FieldOffset(4)] private uint v4;
        [FieldOffset(8)] private ulong v6Low;
        [FieldOffset(16)] private ulong v6High;
        [FieldOffset(24)] private uint scope;

        internal static Address From(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            return ip.AddressFamily switch
            {
                AddressFamily.InterNetwork => new() { Family = (ushort)ip.AddressFamily, v4 = BitConverter.ToUInt32(bytes) },
                AddressFamily.InterNetworkV6 => new()
                {
                    Family = (ushort)ip.AddressFamily, v6Low = BitConverter.ToUInt64(bytes),
                    v6High = BitConverter.ToUInt64(bytes, 8), scope = checked((uint)ip.ScopeId)
                },
                _ => throw new ArgumentException("MachineEgressAddressFamilyInvalid")
            };
        }

        internal readonly IPAddress ToAddress()
        {
            if (Family == (ushort)AddressFamily.InterNetwork) return new(BitConverter.GetBytes(v4));
            if (Family != (ushort)AddressFamily.InterNetworkV6)
                throw new InvalidDataException("MachineEgressNativeAddressFamilyInvalid");
            Span<byte> bytes = stackalloc byte[16];
            BitConverter.TryWriteBytes(bytes, v6Low);
            BitConverter.TryWriteBytes(bytes[8..], v6High);
            return new(bytes, scope);
        }
    }

    [StructLayout(LayoutKind.Explicit, Size = 80)]
    private struct UnicastRow
    {
        [FieldOffset(0)] internal Address Address;
        [FieldOffset(32)] internal ulong Luid;
        [FieldOffset(40)] internal uint Index;
        [FieldOffset(52)] internal uint ValidLifetime;
        [FieldOffset(64)] internal uint DadState;
    }

    [StructLayout(LayoutKind.Explicit, Size = 104)]
    private struct RouteRow
    {
        [FieldOffset(0)] internal ulong Luid;
        [FieldOffset(8)] internal uint Index;
        [FieldOffset(12)] internal Address Prefix;
        [FieldOffset(40)] internal byte PrefixLength;
        [FieldOffset(44)] internal Address NextHop;
        [FieldOffset(84)] internal uint Metric;
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetUnicastIpAddressEntry(ref UnicastRow row);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetBestRoute2(in ulong luid, uint index, in Address source, in Address destination,
        uint sortOptions, out RouteRow bestRoute, out Address bestSource);
}
