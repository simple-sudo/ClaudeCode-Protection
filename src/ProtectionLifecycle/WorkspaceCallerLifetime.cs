using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Holds only the already authenticated ordinary caller. A signalled process
// object is terminal even when its exit code happens to be STILL_ACTIVE (259).
// The query/synchronize handle cannot stop, modify, impersonate or launch it.
internal sealed class WorkspaceCallerLifetime : IDisposable
{
    internal const uint CallerProcessAccess=0x1000|0x00100000;
    private SafeProcessHandle? process;
    private bool disposed;
    internal bool IsBound=>process is not null;
    internal void Bind(SafeProcessHandle authenticatedCaller)
    {
        if(disposed || process is not null)throw WfpNative.Contract("WorkspaceCallerCannotRebind");
        process=authenticatedCaller;AssertAlive();
    }
    internal void AssertAlive()
    {
        if(disposed || process is null || process.IsClosed || process.IsInvalid)throw WfpNative.Contract("WorkspaceCallerUnavailable");
        var observed=WaitForSingleObject(process,0);var error=observed==uint.MaxValue?Marshal.GetLastWin32Error():0;
        RequireAliveObservation(observed,error);
    }
    internal static void RequireAliveObservation(uint observed,int error)
    {
        if(observed==258 && error==0)return; // WAIT_TIMEOUT: the held object is not signalled.
        if(observed==0 && error==0)throw WfpNative.Contract("WorkspaceCallerExited");
        if(observed==uint.MaxValue && error>0)throw new Win32Exception(error,"Workspace caller wait failed");
        throw WfpNative.Contract("WorkspaceCallerWaitUnconfirmed");
    }
    public void Dispose(){if(disposed)return;disposed=true;process?.Dispose();}
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",SetLastError=true)]
    private static extern uint WaitForSingleObject(SafeProcessHandle handle,uint milliseconds);
}
