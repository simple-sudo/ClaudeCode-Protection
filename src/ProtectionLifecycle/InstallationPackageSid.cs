using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ProtectionLifecycle;

internal sealed class InstallationPackageSid : IDisposable
{
    internal IntPtr Pointer { get; private set; }
    internal string Value { get; }
    internal string Name { get; }
    internal InstallationPackageSid(ProtectedState state):this(NameFor(state)){}
    private static string NameFor(ProtectedState state)
    {
        state.AssertHeld();return "ClaudeCodeProtection."+Identifiers.Hex32(state.InstallationId);
    }
    internal static InstallationPackageSid ForObjectContractQualification()=>new("ClaudeCodeProtection.ObjectContractQualification.20261027");
    internal static InstallationPackageSid FromInstallationId(string id)=>new("ClaudeCodeProtection."+Identifiers.Hex32(id));
    internal static InstallationPackageSid ForNetworkControl(ProtectedState state)
    {state.AssertHeld();return new("CPC.NetControl."+Identifiers.Hex32(state.InstallationId));}
    private InstallationPackageSid(string name)
    {
        Name=name;
        var status=DeriveAppContainerSidFromAppContainerName(name,out var pointer);
        if(status!=0){if(pointer!=IntPtr.Zero)FreeSid(pointer);throw new WfpFailure("DeriveFixedInstallationPackageSid",unchecked((uint)status));}
        Pointer=pointer;
        try{if(pointer==IntPtr.Zero || !WfpNative.IsValidSid(pointer))throw new InvalidDataException("Derived package SID invalid");Value=new SecurityIdentifier(pointer).Value;}
        catch{Dispose();throw;}
    }
    public void Dispose(){if(Pointer!=IntPtr.Zero){FreeSid(Pointer);Pointer=IntPtr.Zero;}}
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] private static extern int DeriveAppContainerSidFromAppContainerName(string name,out IntPtr sid);
    [DllImport("advapi32.dll")] private static extern IntPtr FreeSid(IntPtr sid);
}

// x64 Win32 declarations, not a native-layout qualification. The size/offset
// assertions run only if this source is eventually compiled and invoked.
