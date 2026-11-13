using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace WfpExistingEvents;

// The owner must hold the original socket and filter generation throughout
// this window. Runtime IDs recovered later are not historical proof.
internal sealed class MachineEgressDropSelection
{
    private const uint RequiredHeaderFlags = 0x11f;
    private const uint OutboundDirection = 0x3901;
    private readonly byte[] localAddress, remoteAddress;
    private readonly ushort localPort, remotePort, layer;
    private readonly uint version;
    private readonly byte protocol;
    private readonly ulong filter;
    internal long Start { get; }
    internal long End { get; }
    internal ulong FilterId => filter;

    internal MachineEgressDropSelection(IPEndPoint local, IPEndPoint remote, ProtocolType protocol,
        ushort layer, ulong filter, long start, long end)
    {
        if (local.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6) ||
            local.AddressFamily != remote.AddressFamily || local.Port == 0 || remote.Port == 0 ||
            IPAddress.IsLoopback(local.Address) || IPAddress.IsLoopback(remote.Address) ||
            local.Address.Equals(IPAddress.Any) || local.Address.Equals(IPAddress.IPv6Any) ||
            remote.Address.Equals(IPAddress.Any) || remote.Address.Equals(IPAddress.IPv6Any) ||
            (local.AddressFamily == AddressFamily.InterNetworkV6 &&
                (local.Address.ScopeId != 0 || remote.Address.ScopeId != 0 ||
                 local.Address.IsIPv4MappedToIPv6 || remote.Address.IsIPv4MappedToIPv6)) ||
            protocol is not (ProtocolType.Tcp or ProtocolType.Udp) || layer == 0 || filter == 0 ||
            start <= 0 || end <= start || end - start > 5 * TimeSpan.TicksPerSecond)
            throw new ArgumentException("MachineEgressDropSelectionInvalid");

        localAddress = local.Address.GetAddressBytes();
        remoteAddress = remote.Address.GetAddressBytes();
        localPort = checked((ushort)local.Port);
        remotePort = checked((ushort)remote.Port);
        version = local.AddressFamily == AddressFamily.InterNetwork ? 0u : 1u;
        this.protocol = (byte)protocol;
        this.layer = layer;
        this.filter = filter;
        Start = start;
        End = end;
    }

    internal bool Matches(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero) throw new InvalidDataException("MachineEgressEventMissing");
        var item = Marshal.PtrToStructure<Native.Event>(pointer);
        if (item.Timestamp < Start || item.Timestamp > End || item.Type != 3 ||
            (item.Flags & RequiredHeaderFlags) != RequiredHeaderFlags || item.IpVersion != version ||
            item.Protocol != protocol || item.LocalPort != localPort || item.RemotePort != remotePort)
            return false;

        if (item.Data == IntPtr.Zero) throw new InvalidDataException("MachineEgressDropMissing");
        var drop = Marshal.PtrToStructure<Native.ClassifyDrop>(item.Data);
        if (drop.Filter != filter || drop.Layer != layer || drop.Direction != OutboundDirection || drop.Loopback != 0)
            return false;

        if (version == 0)
            return item.LocalV4 == BinaryPrimitives.ReadUInt32BigEndian(localAddress) &&
                item.RemoteV4 == BinaryPrimitives.ReadUInt32BigEndian(remoteAddress);

        var address = new byte[16];
        Marshal.Copy(pointer + Native.Event.LocalAddressOffset, address, 0, address.Length);
        if (!address.AsSpan().SequenceEqual(localAddress)) return false;
        Marshal.Copy(pointer + Native.Event.RemoteAddressOffset, address, 0, address.Length);
        return address.AsSpan().SequenceEqual(remoteAddress);
    }
}

internal sealed record MachineEgressDropRead(ulong? MatchedFilterId, bool CollectionEnabled, bool Exhausted,
    int EventsExamined, string? Failure, uint? Status);

internal static class MachineEgressDropReader
{
    // Existing history can corroborate a drop. It cannot prove that none
    // occurred, even if enumeration reaches its final page.
    internal static MachineEgressDropRead Read(MachineEgressDropSelection selection)
    {
        Native.Layout();
        var timer = Stopwatch.StartNew();
        var examined = 0;
        var collectionEnabled = false;
        IntPtr engine = IntPtr.Zero, enumerator = IntPtr.Zero;
        MachineEgressDropRead Result(ulong? matchedFilterId = null, bool exhausted = false, string? failure = null, uint? status = null)
            => new(matchedFilterId, collectionEnabled, exhausted, examined, failure, status);
        try
        {
            var status = Native.FwpmEngineOpen0(null, 10, IntPtr.Zero, IntPtr.Zero, out var opened);
            if (status != 0 || opened == IntPtr.Zero) return Result(failure: "Open", status: status);
            engine = opened;
            status = Native.FwpmEngineGetOption0(engine, 0, out var option);
            try
            {
                if (status != 0 || option == IntPtr.Zero) return Result(failure: "CollectionOption", status: status);
                var value = Marshal.PtrToStructure<Native.Value>(option);
                if (value.Type != 3 || value.U32 > 1) return Result(failure: "CollectionOptionValue");
                collectionEnabled = value.U32 == 1;
                if (!collectionEnabled) return Result();
            }
            finally
            {
                if (option != IntPtr.Zero) Native.FwpmFreeMemory0(ref option);
            }

            var template = new Native.Template { Start = selection.Start, End = selection.End };
            status = Native.FwpmNetEventCreateEnumHandle0(engine, ref template, out var created);
            if (status != 0 || created == IntPtr.Zero) return Result(failure: "CreateEnumeration", status: status);
            enumerator = created;
            for (var page = 0; page < Reader.MaximumPages && timer.ElapsedMilliseconds < 15000; page++)
            {
                status = Native.FwpmNetEventEnum2(engine, enumerator, Reader.PageSize, out var entries, out var count);
                try
                {
                    if (status != 0) return Result(failure: "Enumerate", status: status);
                    if (count > Reader.PageSize || (count != 0 && entries == IntPtr.Zero))
                        return Result(failure: "InvalidPage");
                    for (var index = 0; index < count; index++)
                    {
                        examined++;
                        if (selection.Matches(Marshal.ReadIntPtr(entries, index * IntPtr.Size)))
                            return Result(matchedFilterId: selection.FilterId);
                    }
                    if (count < Reader.PageSize) return Result(exhausted: true);
                }
                finally
                {
                    if (entries != IntPtr.Zero) Native.FwpmFreeMemory0(ref entries);
                }
            }
            return Result(failure: "ObservationBound");
        }
        catch (InvalidDataException)
        {
            return Result(failure: "InvalidEvent");
        }
        finally
        {
            if (enumerator != IntPtr.Zero && engine != IntPtr.Zero)
                _ = Native.FwpmNetEventDestroyEnumHandle0(engine, enumerator);
            if (engine != IntPtr.Zero)
                _ = Native.FwpmEngineClose0(engine);
        }
    }
}
