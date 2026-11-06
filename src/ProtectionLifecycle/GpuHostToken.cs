using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed record GpuHostTokenFacts(int Type,int AppContainer,int Elevated,int ElevationType,int RestrictedSidCount,
    int UiAccess,int SessionId,string UserSid,string IntegritySid,string AuthenticationId,bool Administrator,string PrivilegesSHA256);

// A lower-only token for this fixed host GPU reference, never a supplied token,
// credential, parent PID, capability set or general process-launch service.
internal sealed class GpuHostToken : IDisposable
{
    private readonly WindowsIdentity owner;
    private readonly GpuHostTokenFacts before;
    private readonly byte[] privileges;
    internal SafeAccessTokenHandle Primary {get;}
    internal GpuHostTokenFacts Expected {get;}
    private GpuHostToken(WindowsIdentity owner,GpuHostTokenFacts before,byte[] privileges,SafeAccessTokenHandle primary,GpuHostTokenFacts expected)
    {this.owner=owner;this.before=before;this.privileges=privileges;Primary=primary;Expected=expected;}
    internal static GpuHostToken OpenOwnLinkedNormalToken()
    {
        if(!Environment.Is64BitProcess)throw Refuse();
        MaintenanceIdentity.RequireCurrentAdministrator();
        var owner=WindowsIdentity.GetCurrent(TokenAccessLevels.Query|TokenAccessLevels.Duplicate);SafeAccessTokenHandle? primary=null;
        try
        {
            var source=Capture(owner.AccessToken);var original=Data(owner.AccessToken,3);
            RequireSource(source);
            using var linked=ReadOwnLinked(owner.AccessToken);
            var linkedFacts=Capture(linked);RequireLinked(source,linkedFacts);
            // TOKEN_ASSIGN_PRIMARY|TOKEN_DUPLICATE|TOKEN_QUERY only. No ADJUST,
            // impersonation, new privilege or change to either existing token.
            if(!DuplicateTokenEx(linked,0x0b,IntPtr.Zero,2,1,out primary))throw Error();
            var expected=Capture(primary);RequireLinked(source,expected);RequireCreated(linkedFacts,expected);
            var result=new GpuHostToken(owner,source,original,primary,expected);result.AssertOwnerUnchanged();return result;
        }
        catch{primary?.Dispose();owner.Dispose();throw;}
    }
    internal static void RequireNormal(GpuHostTokenFacts token)
    {
        if(token.Type!=1 || token.AppContainer!=0 || token.Elevated!=0 || token.ElevationType!=3 || token.Administrator ||
            token.RestrictedSidCount!=0 || token.UiAccess!=0 || token.SessionId<0 || token.IntegritySid!="S-1-16-8192" ||
            !ValidSid(token.UserSid) || !Hex(token.AuthenticationId,16) || !Hex(token.PrivilegesSHA256,64))throw Refuse("HostGpuNormalTokenRoleMismatch");
    }
    internal static void RequireSource(GpuHostTokenFacts source)
    {
        if(source.Type!=1 || source.AppContainer!=0 || source.Elevated!=1 || source.ElevationType!=2 || !source.Administrator ||
            source.RestrictedSidCount!=0 || source.UiAccess!=0 || source.IntegritySid!="S-1-16-12288" || source.SessionId<0 ||
            !ValidSid(source.UserSid) || !Hex(source.AuthenticationId,16) || !Hex(source.PrivilegesSHA256,64))throw Refuse("HostGpuSourceTokenRoleMismatch");
    }
    internal static void RequireLinked(GpuHostTokenFacts source,GpuHostTokenFacts linked)
    {
        RequireSource(source);RequireNormal(linked);
        // UAC's full/limited tokens may belong to distinct linked LSA logon
        // sessions. Link provenance comes from querying our own kernel token;
        // only the limited token's Auth ID must survive duplication/creation.
        if(linked.UserSid!=source.UserSid || linked.SessionId!=source.SessionId)throw Refuse("HostGpuLinkedTokenIdentityMismatch");
    }
    internal static void RequireCreated(GpuHostTokenFacts expected,GpuHostTokenFacts actual)
    {RequireNormal(actual);if(actual!=expected)throw Refuse("HostGpuCreatedTokenFactsMismatch");}
    private static SafeAccessTokenHandle ReadOwnLinked(SafeAccessTokenHandle token)
    {
        // TOKEN_LINKED_TOKEN has exactly one HANDLE. On this Windows build its
        // zero-buffer query returns ERROR_BAD_LENGTH (24), not 122. Query the
        // documented fixed structure directly; do not relax variable bounds.
        if(!GetLinkedToken(token,19,out var value,IntPtr.Size,out var used))throw Error("HostGpuLinkedTokenRead");
        var linked=new SafeAccessTokenHandle(value);
        try{if(used!=IntPtr.Size || linked.IsInvalid)throw Refuse("HostGpuLinkedTokenSize");return linked;}
        catch{linked.Dispose();throw;}
    }
    private static bool ValidSid(string value)
    {try{return new SecurityIdentifier(value).Value==value;}catch(ArgumentException){return false;}}
    private static bool Hex(string? value,int count)=>value is not null && value.Length==count && value.All(c=>c is >= '0' and <= '9' or >= 'A' and <= 'F');
    internal void AssertOwnerUnchanged()
    {
        // CreateProcessAsUser may temporarily enable existing privileges for
        // its call. Never repair drift here or retry with an elevated child.
        using var current=WindowsIdentity.GetCurrent(TokenAccessLevels.Query|TokenAccessLevels.Duplicate);
        if(Capture(current.AccessToken)!=before || !Data(current.AccessToken,3).AsSpan().SequenceEqual(privileges))
        {var error=new InvalidDataException("GpuHostOwnerTokenOrPrivilegeDrift");error.Data["Stage"]="HostGpuOwnerTokenOrPrivilegeDrift";throw error;}
    }
    internal static GpuHostTokenFacts Capture(SafeAccessTokenHandle token)
    {
        var facts=MaintenanceIdentity.ReadFacts(token);
        using var identity=new WindowsIdentity(token.DangerousGetHandle());
        var statistics=Data(token,10);if(statistics.Length!=56)throw Refuse("HostGpuTokenStatisticsLength");
        return new(facts.Type,facts.AppContainer,facts.Elevated,Number(token,18),facts.RestrictedSidCount,Number(token,26),Number(token,12),
            identity.User?.Value??throw Refuse(),Sid(token,25),Convert.ToHexString(statistics.AsSpan(8,8)),
            new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator),Convert.ToHexString(SHA256.HashData(Data(token,3))));
    }
    private static string Sid(SafeAccessTokenHandle token,int kind)
    {
        if(GetTokenInformation(token,kind,IntPtr.Zero,0,out var size) || Marshal.GetLastWin32Error()!=122 || size is <16 or >65536)throw Refuse();
        var buffer=Marshal.AllocHGlobal(size);
        try
        {
            if(!GetTokenInformation(token,kind,buffer,size,out var used))throw Error();
            if(used<16 || used>size)throw Refuse();var sid=Marshal.ReadIntPtr(buffer);var offset=sid.ToInt64()-buffer.ToInt64();
            if(offset<0 || offset>used-8 || Marshal.ReadByte(sid)!=1 || Marshal.ReadByte(sid,1)>15 || 8+4*Marshal.ReadByte(sid,1)>used-offset)throw Refuse();
            return new SecurityIdentifier(sid).Value;
        }
        finally{Marshal.FreeHGlobal(buffer);}
    }
    private static int Number(SafeAccessTokenHandle token,int kind)
    {var bytes=Data(token,kind);return bytes.Length==4?BitConverter.ToInt32(bytes):throw Refuse();}
    private static byte[] Data(SafeAccessTokenHandle token,int kind)
    {
        if(GetTokenInformation(token,kind,IntPtr.Zero,0,out var size) || Marshal.GetLastWin32Error()!=122 || size is <4 or >65536)throw Refuse();
        var buffer=Marshal.AllocHGlobal(size);
        try
        {
            if(!GetTokenInformation(token,kind,buffer,size,out var used))throw Error();if(used<4 || used>size)throw Refuse();
            var bytes=new byte[used];Marshal.Copy(buffer,bytes,0,used);return bytes;
        }
        finally{Marshal.FreeHGlobal(buffer);}
    }
    private static InvalidDataException Refuse(string stage="HostGpuLinkedOrdinaryTokenRequired"){var error=new InvalidDataException("GpuHostRequiresOwnLinkedOrdinaryPrimaryToken");error.Data["Stage"]=stage;return error;}
    private static Win32Exception Error(string stage="HostGpuTokenQueryOrDuplicate"){var error=new Win32Exception(Marshal.GetLastWin32Error(),"Query or duplicate fixed GPU host token");error.Data["Stage"]=stage;return error;}
    public void Dispose(){Primary.Dispose();owner.Dispose();}
    [DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetTokenInformation(SafeAccessTokenHandle token,int kind,IntPtr data,int size,out int used);
    [DllImport("advapi32.dll",EntryPoint="GetTokenInformation",ExactSpelling=true,SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetLinkedToken(SafeAccessTokenHandle token,int kind,out IntPtr linked,int size,out int used);
    [DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool DuplicateTokenEx(SafeAccessTokenHandle token,uint access,IntPtr attributes,int level,int type,out SafeAccessTokenHandle duplicate);
}
