using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ProtectionLifecycle;

// Qualifies only the object contract. This transaction is always aborted.
// Committed delivery tests need a separate bounded owner and recovery record.
internal static class MachineEgressProbeTransaction
{
    internal static ushort VerifyUncommitted(MachineEgressProbePolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ProtectedSession.AssertSystemTestingAllowed();
        ProtectedState.RequireAdministrator();
        using var engine = WfpNative.Open();
        _ = MachineEgressProbePolicy.ReadPacketLayer(engine, AddressFamily.InterNetwork);
        _ = MachineEgressProbePolicy.ReadPacketLayer(engine, AddressFamily.InterNetworkV6);
        ushort observedWeight;
        WfpNative.Check(WfpNative.FwpmTransactionBegin0(engine, 0), "BeginUncommittedMachineEgressProbe");
        Exception? transactionFailure = null;
        try
        {
            AssertAbsentInTransaction(engine, policy);
            observedWeight = AddAndReadInTransaction(engine, policy).Weight;
        }
        catch (Exception error)
        {
            transactionFailure = error;
            throw;
        }
        finally
        {
            try
            {
                WfpNative.Check(WfpNative.FwpmTransactionAbort0(engine), "AbortUncommittedMachineEgressProbe");
                WfpNative.Transaction(engine, true, () => AssertAbsentInTransaction(engine, policy));
            }
            catch (Exception cleanupFailure) when (transactionFailure is not null)
            {
                throw new AggregateException(transactionFailure, cleanupFailure);
            }
        }

        return observedWeight;
    }

    internal static MachineEgressObjects AddAndReadInTransaction(SafeWfpEngine engine, MachineEgressProbePolicy policy)
    {
        using var arena = new WfpNative.Arena();
        using var descriptor = new WfpNative.Descriptor();
        var layer = policy.DefineSubLayer(arena);
        var v4 = policy.DefineFilter(AddressFamily.InterNetwork, arena);
        var v6 = policy.DefineFilter(AddressFamily.InterNetworkV6, arena);
        WfpNative.Check(WfpNative.FwpmSubLayerAdd0(engine, in layer, descriptor.Pointer), "AddMachineEgressSubLayer");
        WfpNative.Check(WfpNative.FwpmFilterAdd0(engine, in v4, descriptor.Pointer, out var v4Id), "AddMachineEgressV4");
        WfpNative.Check(WfpNative.FwpmFilterAdd0(engine, in v6, descriptor.Pointer, out var v6Id), "AddMachineEgressV6");
        if (ReadOwnedInTransaction(engine, policy) is not { } observed ||
            v4Id == 0 || v6Id == 0 || v4Id == v6Id || observed.V4Id != v4Id || observed.V6Id != v6Id)
            throw WfpNative.Contract("MachineEgressProbeObjectIdsDiffer");
        return observed;
    }

    internal static MachineEgressObjects? ReadOwnedInTransaction(SafeWfpEngine engine, MachineEgressProbePolicy policy)
    {
        var layer = ReadLayer(engine, policy);
        var v4 = ReadFilter(engine, policy, AddressFamily.InterNetwork);
        var v6 = ReadFilter(engine, policy, AddressFamily.InterNetworkV6);
        return MachineEgressRecoveryState.Select(layer.HasValue, v4.HasValue, v6.HasValue)
            ? new(layer!.Value.Weight, v4!.Value.Id, v6!.Value.Id,
                layer.Value.Security, v4.Value.Security, v6.Value.Security) : null;
    }

    private static (ushort Weight, string Security)? ReadLayer(SafeWfpEngine engine, MachineEgressProbePolicy policy)
    {
        var key = policy.SubLayerKey;
        var status = WfpNative.FwpmSubLayerGetByKey0(engine, in key, out var pointer);
        try
        {
            if (status == WfpNative.SubLayerNotFound && pointer == IntPtr.Zero) return null;
            WfpNative.Check(status, "ReadMachineEgressSubLayer");
            if (pointer == IntPtr.Zero)
                throw WfpNative.Contract("MachineEgressProbeSubLayerResponseMissing");
            var actual = Marshal.PtrToStructure<WfpNative.SubLayer>(pointer);
            if (!policy.MatchesSubLayer(actual))
                throw WfpNative.Contract("MachineEgressProbeSubLayerMismatch");
            var security = WfpNative.ReadTrustedSecurity(engine, key, WfpNative.FwpmSubLayerGetSecurityInfoByKey0);
            return (actual.Weight, Convert.ToHexString(SHA256.HashData(security)));
        }
        finally
        {
            if (pointer != IntPtr.Zero) WfpNative.FwpmFreeMemory0(ref pointer);
        }
    }

    private static (ulong Id, string Security)? ReadFilter(SafeWfpEngine engine, MachineEgressProbePolicy policy, AddressFamily family)
    {
        var key = policy.FilterKey(family);
        var status = WfpNative.FwpmFilterGetByKey0(engine, in key, out var pointer);
        try
        {
            if (status == WfpNative.FilterNotFound && pointer == IntPtr.Zero) return null;
            WfpNative.Check(status, "ReadMachineEgressFilter");
            if (pointer == IntPtr.Zero)
                throw WfpNative.Contract("MachineEgressProbeFilterResponseMissing");
            var filter = Marshal.PtrToStructure<WfpNative.Filter>(pointer);
            if (!policy.MatchesFilter(family, filter))
                throw WfpNative.Contract("MachineEgressProbeFilterMismatch");
            var security = WfpNative.ReadTrustedSecurity(engine, key, WfpNative.FwpmFilterGetSecurityInfoByKey0);
            return (filter.Id, Convert.ToHexString(SHA256.HashData(security)));
        }
        finally
        {
            if (pointer != IntPtr.Zero) WfpNative.FwpmFreeMemory0(ref pointer);
        }
    }

    internal static bool AssertAbsentInTransaction(SafeWfpEngine engine, MachineEgressProbePolicy policy)
    {
        var layerKey = policy.SubLayerKey;
        var status = WfpNative.FwpmSubLayerGetByKey0(engine, in layerKey, out var pointer);
        RequireAbsent(status, WfpNative.SubLayerNotFound, pointer, "MachineEgressProbeSubLayerAbsenceUnconfirmed");
        foreach (var family in new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 })
        {
            var key = policy.FilterKey(family);
            status = WfpNative.FwpmFilterGetByKey0(engine, in key, out pointer);
            RequireAbsent(status, WfpNative.FilterNotFound, pointer, "MachineEgressProbeFilterAbsenceUnconfirmed");
        }
        return true;
    }

    private static void RequireAbsent(uint status, uint notFound, IntPtr pointer, string stage)
    {
        var returnedObject = pointer != IntPtr.Zero;
        if (returnedObject) WfpNative.FwpmFreeMemory0(ref pointer);
        if (status != notFound && status != 0) WfpNative.Check(status, stage);
        if (status != notFound || returnedObject) throw WfpNative.Contract(stage);
    }
}
