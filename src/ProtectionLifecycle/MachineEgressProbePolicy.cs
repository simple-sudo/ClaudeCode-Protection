using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ProtectionLifecycle;

// First packet-layer qualification contract. Both filters target only the
// supplied test receivers on one observed egress interface per IP family.
internal sealed class MachineEgressProbePolicy
{
    private const string Scope = "CPC-MACHINE-EGRESS-PROBE-1";
    private const ulong FilterWeight = ulong.MaxValue;
    private static readonly Guid OutboundPacketV4 = new("1e5c9fae-8a84-4135-a331-950b54229ecd");
    private static readonly Guid OutboundPacketV6 = new("a3b3ab6b-3564-488c-9117-f34e82142763");
    private static readonly Guid InterfaceIndex = new("667fd755-d695-434a-8af5-d3835a1259bc");
    private const uint ByteArray16 = 11;

    private readonly Guid v4Key, v6Key;
    private readonly uint v4Interface, v6Interface;
    private readonly byte[] v4Address, v6Address;
    private readonly byte[] marker;

    internal Guid SubLayerKey { get; }

    internal MachineEgressProbePolicy(Guid subLayerKey, Guid v4Key, Guid v6Key,
        uint v4Interface, IPAddress v4Receiver, uint v6Interface, IPAddress v6Receiver)
    {
        if (subLayerKey == Guid.Empty || v4Key == Guid.Empty || v6Key == Guid.Empty ||
            subLayerKey == v4Key || subLayerKey == v6Key || v4Key == v6Key)
            throw new ArgumentException("MachineEgressProbeKeysInvalid");
        ArgumentNullException.ThrowIfNull(v4Receiver);
        ArgumentNullException.ThrowIfNull(v6Receiver);
        if (v4Interface == 0 || v6Interface == 0)
            throw new ArgumentException("MachineEgressProbeInterfacesInvalid");

        v4Address = v4Receiver.GetAddressBytes();
        v6Address = v6Receiver.GetAddressBytes();
        if (v4Receiver.AddressFamily != AddressFamily.InterNetwork || v4Address[0] is 0 or 127 or >= 224 ||
            (v4Address[0] == 169 && v4Address[1] == 254))
            throw new ArgumentException("MachineEgressProbeV4ReceiverInvalid", nameof(v4Receiver));
        // Global unicast or ULA, with no link scope or IPv4-mapped alias.
        if (v6Receiver.AddressFamily != AddressFamily.InterNetworkV6 || v6Receiver.ScopeId != 0 ||
            ((v6Address[0] & 0xe0) != 0x20 && (v6Address[0] & 0xfe) != 0xfc))
            throw new ArgumentException("MachineEgressProbeV6ReceiverInvalid", nameof(v6Receiver));

        SubLayerKey = subLayerKey;
        this.v4Key = v4Key;
        this.v6Key = v6Key;
        this.v4Interface = v4Interface;
        this.v6Interface = v6Interface;
        var canonical = FormattableString.Invariant(
            $"{Scope}|{subLayerKey:N}|{v4Key:N}|{v6Key:N}|{v4Interface}|{Convert.ToHexString(v4Address)}|{v6Interface}|{Convert.ToHexString(v6Address)}");
        marker = SHA256.HashData(Encoding.ASCII.GetBytes(canonical));
    }

    private string Name(string role) => $"{Scope}:{SubLayerKey:N}:{role}";

    internal static (ushort LayerId, uint InterfaceType, uint RemoteAddressType) ReadPacketLayer(SafeWfpEngine engine, AddressFamily family)
    {
        var (key, addressType) = family switch
        {
            AddressFamily.InterNetwork => (OutboundPacketV4, WfpNative.UInt32),
            AddressFamily.InterNetworkV6 => (OutboundPacketV6, ByteArray16),
            _ => throw new ArgumentOutOfRangeException(nameof(family))
        };
        var status = WfpNative.FwpmLayerGetByKey0(engine, in key, out var pointer);
        try
        {
            WfpNative.Check(status, "ReadMachineEgressPacketLayer");
            if (pointer == IntPtr.Zero)
                throw WfpNative.Contract("MachineEgressPacketLayerMissing");
            var layer = Marshal.PtrToStructure<WfpNative.Layer>(pointer);
            if (layer.Key != key || layer.FieldCount is 0 or > 128 || layer.Fields == IntPtr.Zero)
                throw WfpNative.Contract("MachineEgressPacketLayerFieldsInvalid");

            uint? interfaceType = null, remoteAddressType = null;
            var size = Marshal.SizeOf<WfpNative.LayerField>();
            for (var i = 0; i < layer.FieldCount; i++)
            {
                var field = Marshal.PtrToStructure<WfpNative.LayerField>(layer.Fields + i * size);
                if (field.Key == IntPtr.Zero)
                    throw WfpNative.Contract("MachineEgressPacketLayerFieldKeyMissing");
                var fieldKey = Marshal.PtrToStructure<Guid>(field.Key);
                if (fieldKey == InterfaceIndex)
                {
                    if (interfaceType.HasValue) throw WfpNative.Contract("MachineEgressInterfaceFieldRepeated");
                    interfaceType = field.DataType;
                }
                if (fieldKey == WfpNative.RemoteAddress)
                {
                    if (remoteAddressType.HasValue) throw WfpNative.Contract("MachineEgressAddressFieldRepeated");
                    remoteAddressType = field.DataType;
                }
            }
            if (interfaceType != WfpNative.UInt32 || remoteAddressType != addressType)
                throw WfpNative.Contract("MachineEgressPacketLayerDataTypesDiffer");
            return (layer.Id, interfaceType.Value, remoteAddressType.Value);
        }
        finally
        {
            if (pointer != IntPtr.Zero) WfpNative.FwpmFreeMemory0(ref pointer);
        }
    }

    internal WfpNative.SubLayer DefineSubLayer(WfpNative.Arena arena) => new()
    {
        Key = SubLayerKey,
        Display = new() { Name = arena.Text(Name("layer")) },
        Flags = WfpNative.Persistent,
        Data = arena.Bytes(marker),
        Weight = ushort.MaxValue
    };

    internal WfpNative.Filter DefineFilter(AddressFamily family, WfpNative.Arena arena)
    {
        var (key, layer, index, address, role) = FilterScope(family);
        var destination = family == AddressFamily.InterNetwork
            ? new WfpNative.Value { Type = WfpNative.UInt32, U32 = BinaryPrimitives.ReadUInt32BigEndian(address) }
            : new WfpNative.Value { Type = ByteArray16, Pointer = arena.Bytes(address).Data };
        return new()
        {
            Key = key,
            Display = new() { Name = arena.Text(Name(role)) },
            Flags = WfpNative.Persistent,
            Data = arena.Bytes(marker),
            Layer = layer,
            SubLayer = SubLayerKey,
            Weight = new() { Type = WfpNative.UInt64, Pointer = arena.Struct(FilterWeight) },
            ConditionCount = 2,
            Conditions = arena.Conditions(new[]
            {
                new WfpNative.Condition { Field = InterfaceIndex, Match = WfpNative.Equal,
                    Value = new() { Type = WfpNative.UInt32, U32 = index } },
                new WfpNative.Condition { Field = WfpNative.RemoteAddress, Match = WfpNative.Equal, Value = destination }
            }),
            Action = new() { Type = WfpNative.Block }
        };
    }

    // BFE can assign a different sublayer weight. The actual priority and
    // competing sublayers must be evaluated separately before qualification.
    internal bool MatchesSubLayer(WfpNative.SubLayer observed) =>
        observed.Key == SubLayerKey && observed.Flags == WfpNative.Persistent &&
        observed.Provider == IntPtr.Zero && WfpNative.Name(observed.Display.Name) == Name("layer") &&
        WfpNative.BlobMatches(observed.Data, marker);

    internal bool MatchesFilter(AddressFamily family, WfpNative.Filter observed)
    {
        var (key, layer, index, address, role) = FilterScope(family);
        if (observed.Key != key || observed.Layer != layer || observed.SubLayer != SubLayerKey ||
            observed.Provider != IntPtr.Zero || !WfpNative.ExpectedPersistentFilterFlags(observed.Flags) ||
            observed.Action.Type != WfpNative.Block || observed.Action.Key != Guid.Empty ||
            observed.Context.Key != Guid.Empty || observed.Reserved != IntPtr.Zero ||
            observed.Weight.Type != WfpNative.UInt64 || observed.Weight.Pointer == IntPtr.Zero ||
            unchecked((ulong)Marshal.ReadInt64(observed.Weight.Pointer)) != FilterWeight ||
            observed.ConditionCount != 2 || observed.Conditions == IntPtr.Zero ||
            WfpNative.Name(observed.Display.Name) != Name(role) || !WfpNative.BlobMatches(observed.Data, marker))
            return false;

        var first = Marshal.PtrToStructure<WfpNative.Condition>(observed.Conditions);
        var second = Marshal.PtrToStructure<WfpNative.Condition>(observed.Conditions + Marshal.SizeOf<WfpNative.Condition>());
        if (first.Field == WfpNative.RemoteAddress)
            (first, second) = (second, first);
        return first.Field == InterfaceIndex && first.Match == WfpNative.Equal &&
            first.Value.Type == WfpNative.UInt32 && first.Value.U32 == index &&
            second.Field == WfpNative.RemoteAddress && second.Match == WfpNative.Equal &&
            (family == AddressFamily.InterNetwork
                ? second.Value.Type == WfpNative.UInt32 && second.Value.U32 == BinaryPrimitives.ReadUInt32BigEndian(address)
                : second.Value.Type == ByteArray16 &&
                    WfpNative.BlobMatches(new() { Size = 16, Data = second.Value.Pointer }, address));
    }

    private (Guid Key, Guid Layer, uint Interface, byte[] Address, string Role) FilterScope(AddressFamily family) => family switch
    {
        AddressFamily.InterNetwork => (v4Key, OutboundPacketV4, v4Interface, v4Address, "out-v4"),
        AddressFamily.InterNetworkV6 => (v6Key, OutboundPacketV6, v6Interface, v6Address, "out-v6"),
        _ => throw new ArgumentOutOfRangeException(nameof(family))
    };
}
