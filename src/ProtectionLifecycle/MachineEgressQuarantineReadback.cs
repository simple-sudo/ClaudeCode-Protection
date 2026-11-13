using System.Runtime.InteropServices;

namespace ProtectionLifecycle;

internal sealed record MachineEgressQuarantineObservation(ushort SubLayerWeight, IReadOnlyList<ulong> FilterIds);

internal static class MachineEgressQuarantineReadback
{
    // Caller holds the original plan. Read in one BFE snapshot and retain
    // assigned weight/IDs for arbitration and packet-evidence correlation.
    internal static MachineEgressQuarantineObservation? Read(SafeWfpEngine engine, MachineEgressQuarantinePolicy policy) =>
        WfpNative.Transaction(engine, true, () => ReadInTransaction(engine, policy));

    private static MachineEgressQuarantineObservation? ReadInTransaction(SafeWfpEngine engine, MachineEgressQuarantinePolicy policy)
    {
        var key = policy.SubLayerKey;
        var status = WfpNative.FwpmSubLayerGetByKey0(engine, in key, out var pointer);
        ushort? weight = null;
        try
        {
            if (status != WfpNative.SubLayerNotFound || pointer != IntPtr.Zero)
            {
                WfpNative.Check(status, "ReadMachineQuarantineSubLayer");
                if (pointer == IntPtr.Zero) throw WfpNative.Contract("MachineQuarantineSubLayerMissing");
                var layer = Marshal.PtrToStructure<WfpNative.SubLayer>(pointer);
                if (!policy.MatchesSubLayer(layer)) throw WfpNative.Contract("MachineQuarantineSubLayerDiffers");
                WfpNative.AssertSecurity(engine, key, WfpNative.FwpmSubLayerGetSecurityInfoByKey0);
                weight = layer.Weight;
            }
        }
        finally
        {
            if (pointer != IntPtr.Zero) WfpNative.FwpmFreeMemory0(ref pointer);
        }

        var ids = new List<ulong>(policy.FilterCount);
        for (var role = 0; role < policy.FilterCount; role++)
        {
            key = policy.FilterKey(role);
            status = WfpNative.FwpmFilterGetByKey0(engine, in key, out pointer);
            try
            {
                if (status == WfpNative.FilterNotFound && pointer == IntPtr.Zero) continue;
                WfpNative.Check(status, "ReadMachineQuarantineFilter");
                if (pointer == IntPtr.Zero) throw WfpNative.Contract("MachineQuarantineFilterMissing");
                var filter = Marshal.PtrToStructure<WfpNative.Filter>(pointer);
                if (!policy.MatchesFilter(role, filter)) throw WfpNative.Contract("MachineQuarantineFilterDiffers");
                WfpNative.AssertSecurity(engine, key, WfpNative.FwpmFilterGetSecurityInfoByKey0);
                ids.Add(filter.Id);
            }
            finally
            {
                if (pointer != IntPtr.Zero) WfpNative.FwpmFreeMemory0(ref pointer);
            }
        }
        if (!weight.HasValue && ids.Count == 0) return null;
        if (!weight.HasValue || ids.Count != policy.FilterCount || ids.Contains(0) || ids.Distinct().Count() != ids.Count)
            throw WfpNative.Contract("MachineQuarantineInventoryIncomplete");
        return new(weight.Value, ids.AsReadOnly());
    }
}
