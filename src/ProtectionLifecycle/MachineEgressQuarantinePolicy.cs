using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ProtectionLifecycle;

// The deny-only PREPARING/DEGRADED policy. No interface or address inventory
// is used, so new adapters and routed private networks do not become exceptions.
internal sealed class MachineEgressQuarantinePolicy
{
    private const string Scope = "CPC-MACHINE-QUARANTINE-1";
    private const uint FlagsNoneSet = 8, IsLoopback = 1;
    private static readonly Guid ConditionFlags = new("632ce23b-5167-435c-86d7-e903684aa80c");
    private static readonly Guid ForwardV4 = new("a82acc24-4ee1-4ee1-b465-fd1d25cb10a4");
    private static readonly Guid ForwardV6 = new("7b964818-19c7-493a-b71f-832c3684d28c");
    private readonly byte[] marker;
    private readonly Rule[] rules;

    internal Guid SubLayerKey { get; }
    internal int FilterCount => rules.Length;
    internal Guid FilterKey(int role) => rules[role].Key;

    internal MachineEgressQuarantinePolicy(Guid installationId, Guid subLayerKey,
        Guid outboundV4, Guid outboundV6, Guid forwardV4, Guid forwardV6)
    {
        var keys = new[] { subLayerKey, outboundV4, outboundV6, forwardV4, forwardV6 };
        if (installationId == Guid.Empty || keys.Contains(Guid.Empty) || keys.Distinct().Count() != keys.Length)
            throw new ArgumentException("MachineEgressQuarantineIdentityInvalid");
        SubLayerKey = subLayerKey;
        rules =
        [
            new(outboundV4, WfpNative.OutboundPacketV4, "out-v4", true),
            new(outboundV6, WfpNative.OutboundPacketV6, "out-v6", true),
            new(forwardV4, ForwardV4, "forward-v4", false),
            new(forwardV6, ForwardV6, "forward-v6", false)
        ];
        var binding = Scope + "|" + installationId.ToString("N") + "|" + string.Join("|", keys.Select(key => key.ToString("N")));
        marker = SHA256.HashData(Encoding.ASCII.GetBytes(binding));
    }

    internal WfpNative.SubLayer DefineSubLayer(WfpNative.Arena arena) => new()
    {
        Key = SubLayerKey,
        Display = new() { Name = arena.Text(Name("layer")) },
        Flags = WfpNative.Persistent,
        Data = arena.Bytes(marker),
        Weight = ushort.MaxValue
    };

    internal WfpNative.Filter DefineFilter(int role, WfpNative.Arena arena)
    {
        var rule = rules[role];
        return new()
        {
            Key = rule.Key,
            Display = new() { Name = arena.Text(Name(rule.Name)) },
            Flags = WfpNative.Persistent,
            Data = arena.Bytes(marker),
            Layer = rule.Layer,
            SubLayer = SubLayerKey,
            Weight = new() { Type = WfpNative.UInt64, Pointer = arena.Struct(ulong.MaxValue) },
            ConditionCount = rule.ExcludeLoopback ? 1u : 0u,
            Conditions = rule.ExcludeLoopback ? arena.Conditions(
            [
                new() { Field = ConditionFlags, Match = FlagsNoneSet, Value = new() { Type = WfpNative.UInt32, U32 = IsLoopback } }
            ]) : IntPtr.Zero,
            Action = new() { Type = WfpNative.Block }
        };
    }

    // Assigned sublayer weight is a separate native observation.
    internal bool MatchesSubLayer(WfpNative.SubLayer layer) =>
        layer.Key == SubLayerKey && layer.Provider == IntPtr.Zero && layer.Flags == WfpNative.Persistent &&
        WfpNative.Name(layer.Display.Name) == Name("layer") && WfpNative.BlobMatches(layer.Data, marker);

    internal bool MatchesFilter(int role, WfpNative.Filter filter)
    {
        var rule = rules[role];
        if (filter.Key != rule.Key || filter.Layer != rule.Layer || filter.SubLayer != SubLayerKey ||
            filter.Provider != IntPtr.Zero || !WfpNative.ExpectedPersistentFilterFlags(filter.Flags) ||
            filter.Action.Type != WfpNative.Block || filter.Action.Key != Guid.Empty ||
            filter.Context.Key != Guid.Empty || filter.Reserved != IntPtr.Zero ||
            filter.Weight.Type != WfpNative.UInt64 || filter.Weight.Pointer == IntPtr.Zero ||
            unchecked((ulong)Marshal.ReadInt64(filter.Weight.Pointer)) != ulong.MaxValue ||
            WfpNative.Name(filter.Display.Name) != Name(rule.Name) || !WfpNative.BlobMatches(filter.Data, marker))
            return false;
        if (!rule.ExcludeLoopback)
            return filter.ConditionCount == 0 && filter.Conditions == IntPtr.Zero;
        if (filter.ConditionCount != 1 || filter.Conditions == IntPtr.Zero) return false;
        var condition = Marshal.PtrToStructure<WfpNative.Condition>(filter.Conditions);
        return condition.Field == ConditionFlags && condition.Match == FlagsNoneSet &&
            condition.Value.Type == WfpNative.UInt32 && condition.Value.U32 == IsLoopback;
    }

    private string Name(string role) => $"{Scope}:{SubLayerKey:N}:{role}";

    private sealed record Rule(Guid Key, Guid Layer, string Name, bool ExcludeLoopback);
}
