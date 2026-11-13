using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ProtectionLifecycle;

// Observe changes for the short qualification window. Any delivered change
// invalidates it, including changes that reverse before the next snapshot.
internal sealed class MachineEgressRouteWatch : IDisposable
{
    private const uint InitialNotification = 3;
    private readonly List<IntPtr> handles = new(3);
    private GCHandle context;
    private int ready;
    private int changed;
    private bool disposed;

    internal MachineEgressRouteWatch()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        context = GCHandle.Alloc(this);
        try
        {
            var pointer = GCHandle.ToIntPtr(context);
            Add(NotifyRouteChange2(0, RouteCallback, pointer, 1, out var route), route, "NotifyRouteChange2");
            Add(NotifyUnicastIpAddressChange(0, AddressCallback, pointer, 1, out var address), address, "NotifyUnicastIpAddressChange");
            Add(NotifyIpInterfaceChange(0, InterfaceCallback, pointer, 1, out var adapter), adapter, "NotifyIpInterfaceChange");
            if (!SpinWait.SpinUntil(() => Volatile.Read(ref ready) == 7, TimeSpan.FromSeconds(2)))
                throw new IOException($"MachineEgressRouteNotificationsNotReady (mask {Volatile.Read(ref ready)})");
            AssertUnchanged();
        }
        catch (Exception error)
        {
            try { Dispose(); }
            catch (Exception cleanup) { throw new AggregateException(error, cleanup); }
            throw;
        }
    }

    internal void AssertUnchanged()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        CheckChange();
    }

    internal void Complete()
    {
        Dispose();
        CheckChange();
    }

    private void CheckChange()
    {
        if (Volatile.Read(ref changed) != 0)
            throw new InvalidDataException("MachineEgressNetworkChangeObserved");
    }

    private void Add(uint status, IntPtr handle, string stage)
    {
        if (status != 0) throw new Win32Exception(unchecked((int)status), stage);
        if (handle == IntPtr.Zero) throw new IOException(stage + " returned no handle");
        handles.Add(handle);
    }

    private static readonly ChangeCallback RouteCallback = (context, _, kind) => OnChange(context, kind, 1);
    private static readonly ChangeCallback AddressCallback = (context, _, kind) => OnChange(context, kind, 2);
    private static readonly ChangeCallback InterfaceCallback = (context, _, kind) => OnChange(context, kind, 4);

    private static void OnChange(IntPtr context, uint kind, int source)
    {
        var watch = (MachineEgressRouteWatch)GCHandle.FromIntPtr(context).Target!;
        if (kind == InitialNotification) Interlocked.Or(ref watch.ready, source);
        else Volatile.Write(ref watch.changed, 1);
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        var failures = new List<Win32Exception>();
        foreach (var handle in handles)
        {
            var status = CancelMibChangeNotify2(handle);
            if (status != 0) failures.Add(new(unchecked((int)status), "CancelMibChangeNotify2"));
        }
        // A failed cancellation may leave native callbacks registered.
        // Retain their context until process exit rather than freeing it.
        if (failures.Count != 0) throw new AggregateException(failures);
        if (context.IsAllocated) context.Free();
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ChangeCallback(IntPtr context, IntPtr row, uint kind);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint NotifyRouteChange2(ushort family, ChangeCallback callback, IntPtr context,
        byte initialNotification, out IntPtr handle);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint NotifyUnicastIpAddressChange(ushort family, ChangeCallback callback, IntPtr context,
        byte initialNotification, out IntPtr handle);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint NotifyIpInterfaceChange(ushort family, ChangeCallback callback, IntPtr context,
        byte initialNotification, out IntPtr handle);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint CancelMibChangeNotify2(IntPtr handle);
}
