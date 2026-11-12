using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed class SafeWfpEngine : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeWfpEngine():base(true){}
    protected override bool ReleaseHandle()=>WfpNative.FwpmEngineClose0(handle)==0;
}
