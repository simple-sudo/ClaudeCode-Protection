using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace ProtectionLifecycle;

// Compiled owner selections only. There is no parser, caller capability list,
// environment override, token setter or production-launch profile switch.
internal sealed class LpacCapabilityProfile
{
    internal static readonly LpacCapabilityProfile None=new(false);
    internal static readonly LpacCapabilityProfile InternetClientQualification=new(true);
    internal bool IsInternetClientQualification {get;}
    internal uint NativeCount=>IsInternetClientQualification?1u:0u;
    internal string Id=>IsInternetClientQualification?"FIXED_GATEWAY_INTERNET_CLIENT_ONLY":"ORIGINAL_ZERO_CAPABILITIES";
    internal string SHA256 {get;}
    private LpacCapabilityProfile(bool internet)
    {
        IsInternetClientQualification=internet;
        SHA256=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.ASCII.GetBytes(
            "CPC-LPAC-CAPABILITIES-V1;"+(internet?"S-1-15-3-1:00000004;fixed-gateway-only;no-tools":"empty")+";no-caller-selection;lpac-mask=2;integrity=low")));
    }
    internal bool Matches(int count,TokenCapabilitySnapshot? actual)=>IsInternetClientQualification?
        count==1 && actual is {Count:1,IsExactInternetClient:true}:
        count==0 && (actual is null || actual.IsEmpty);

    internal CapabilityAttributes AllocateAttributes()=>new(this);
    internal sealed class CapabilityAttributes : IDisposable
    {
        private IntPtr sid,entries;
        private bool disposed;
        internal IntPtr Pointer=>!disposed?entries:throw new ObjectDisposedException(nameof(CapabilityAttributes));
        internal uint Count {get;}
        internal CapabilityAttributes(LpacCapabilityProfile profile)
        {
            ArgumentNullException.ThrowIfNull(profile);
            if(!OperatingSystem.IsWindows() || !Environment.Is64BitProcess || RuntimeInformation.ProcessArchitecture!=Architecture.X64)throw new PlatformNotSupportedException("CapabilityAttributesRequireX64");
            Count=profile.NativeCount;
            if(Count==0)return;
            try
            {
                var identity=new SecurityIdentifier(TokenCapabilitySnapshot.InternetClientSid);var bytes=new byte[identity.BinaryLength];identity.GetBinaryForm(bytes,0);
                sid=Marshal.AllocHGlobal(bytes.Length);Marshal.Copy(bytes,0,sid,bytes.Length);
                // One x64 SID_AND_ATTRIBUTES; reserved alignment bytes zero.
                entries=Marshal.AllocHGlobal(16);Marshal.Copy(new byte[16],0,entries,16);
                Marshal.WriteIntPtr(entries,sid);Marshal.WriteInt32(entries,8,4);
            }
            catch{Dispose();throw;}
        }
        public void Dispose()
        {
            if(disposed)return;disposed=true;
            if(entries!=IntPtr.Zero){Marshal.FreeHGlobal(entries);entries=IntPtr.Zero;}
            if(sid!=IntPtr.Zero){Marshal.FreeHGlobal(sid);sid=IntPtr.Zero;}
        }
    }
}
