using System.Net.Sockets;
using System.Runtime.InteropServices;

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
        using var arena = new WfpNative.Arena();
        using var descriptor = new WfpNative.Descriptor();
        var layer = policy.DefineSubLayer(arena);
        var v4 = policy.DefineFilter(AddressFamily.InterNetwork, arena);
        var v6 = policy.DefineFilter(AddressFamily.InterNetworkV6, arena);
        AssertAbsent(engine, layer.Key, v4.Key, v6.Key);

        ushort observedWeight;
        WfpNative.Check(WfpNative.FwpmTransactionBegin0(engine, 0), "BeginUncommittedMachineEgressProbe");
        Exception? transactionFailure = null;
        try
        {
            // Repeat absence inside the writer transaction to reject races.
            AssertAbsentInTransaction(engine, layer.Key, v4.Key, v6.Key);
            WfpNative.Check(WfpNative.FwpmSubLayerAdd0(engine, in layer, descriptor.Pointer), "AddUncommittedMachineEgressSubLayer");
            WfpNative.Check(WfpNative.FwpmFilterAdd0(engine, in v4, descriptor.Pointer, out _), "AddUncommittedMachineEgressV4");
            WfpNative.Check(WfpNative.FwpmFilterAdd0(engine, in v6, descriptor.Pointer, out _), "AddUncommittedMachineEgressV6");
            observedWeight = ReadLayer(engine, policy);
            ReadFilter(engine, policy, AddressFamily.InterNetwork, v4.Key);
            ReadFilter(engine, policy, AddressFamily.InterNetworkV6, v6.Key);
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
                AssertAbsent(engine, layer.Key, v4.Key, v6.Key);
            }
            catch (Exception cleanupFailure) when (transactionFailure is not null)
            {
                throw new AggregateException(transactionFailure, cleanupFailure);
            }
        }

        return observedWeight;
    }

    private static ushort ReadLayer(SafeWfpEngine engine, MachineEgressProbePolicy policy)
    {
        var key = policy.SubLayerKey;
        var status = WfpNative.FwpmSubLayerGetByKey0(engine, in key, out var pointer);
        try
        {
            WfpNative.Check(status, "ReadUncommittedMachineEgressSubLayer");
            if (pointer == IntPtr.Zero)
                throw WfpNative.Contract("MachineEgressProbeSubLayerResponseMissing");
            var actual = Marshal.PtrToStructure<WfpNative.SubLayer>(pointer);
            if (!policy.MatchesSubLayer(actual))
                throw WfpNative.Contract("MachineEgressProbeSubLayerMismatch");
            WfpNative.AssertSecurity(engine, key, WfpNative.FwpmSubLayerGetSecurityInfoByKey0);
            return actual.Weight;
        }
        finally
        {
            if (pointer != IntPtr.Zero) WfpNative.FwpmFreeMemory0(ref pointer);
        }
    }

    private static void ReadFilter(SafeWfpEngine engine, MachineEgressProbePolicy policy, AddressFamily family, Guid key)
    {
        var status = WfpNative.FwpmFilterGetByKey0(engine, in key, out var pointer);
        try
        {
            WfpNative.Check(status, "ReadUncommittedMachineEgressFilter");
            if (pointer == IntPtr.Zero || !policy.MatchesFilter(family, Marshal.PtrToStructure<WfpNative.Filter>(pointer)))
                throw WfpNative.Contract("MachineEgressProbeFilterMismatch");
            WfpNative.AssertSecurity(engine, key, WfpNative.FwpmFilterGetSecurityInfoByKey0);
        }
        finally
        {
            if (pointer != IntPtr.Zero) WfpNative.FwpmFreeMemory0(ref pointer);
        }
    }

    private static void AssertAbsent(SafeWfpEngine engine, Guid layerKey, Guid v4Key, Guid v6Key) =>
        WfpNative.Transaction(engine, true, () =>
        {
            AssertAbsentInTransaction(engine, layerKey, v4Key, v6Key);
            return true;
        });

    private static void AssertAbsentInTransaction(SafeWfpEngine engine, Guid layerKey, Guid v4Key, Guid v6Key)
    {
        var status = WfpNative.FwpmSubLayerGetByKey0(engine, in layerKey, out var pointer);
        RequireAbsent(status, WfpNative.SubLayerNotFound, pointer, "MachineEgressProbeSubLayerAbsenceUnconfirmed");
        foreach (var key in new[] { v4Key, v6Key })
        {
            status = WfpNative.FwpmFilterGetByKey0(engine, in key, out pointer);
            RequireAbsent(status, WfpNative.FilterNotFound, pointer, "MachineEgressProbeFilterAbsenceUnconfirmed");
        }
    }

    private static void RequireAbsent(uint status, uint notFound, IntPtr pointer, string stage)
    {
        var returnedObject = pointer != IntPtr.Zero;
        if (returnedObject) WfpNative.FwpmFreeMemory0(ref pointer);
        if (status != notFound && status != 0) WfpNative.Check(status, stage);
        if (status != notFound || returnedObject) throw WfpNative.Contract(stage);
    }
}
