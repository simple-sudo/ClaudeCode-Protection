using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Qualification evidence only. Each actor queries itself and the same fixed
// local registry value. Returned paths and identities never become inputs.
internal sealed record OfflineConsoleHostIdentity(int SchemaVersion,string SessionId,int Pid,
    OfflineConsoleIdentityRead TokenUser,OfflineConsoleIdentityRead LogonName,OfflineConsoleIdentityRead ProfileDirectory,
    OfflineConsoleIdentityRead ComputerName,OfflineConsoleIdentityRead MachineGuid)
{
    private const int MaximumCharacters=1024,MaximumReportBytes=32768;
    private const string Leaf="offline-console-host-identity.json";
    private const int AccessDenied=5,InvalidData=13;
    private const int PhysicalDnsHostname=5;
    private static readonly IntPtr LocalMachine=new(unchecked((int)0x80000002));
    private const uint RegistryString=0x2,Registry64BitView=0x10000;

    internal static OfflineConsoleHostIdentity Capture(string session)
    {
        using var identity=WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        var sid=identity.User?.Value;
        return new(1,session,Environment.ProcessId,
            sid is null?new(InvalidData,null):new(0,sid),
            ReadNative(GetUserName),
            ReadNative((StringBuilder buffer,ref int length)=>GetUserProfileDirectory(identity.AccessToken,buffer,ref length)),
            ReadNative((StringBuilder buffer,ref int length)=>GetComputerNameEx(PhysicalDnsHostname,buffer,ref length)),
            ReadMachineGuid());
    }

    internal void Write(string workspace)
    {
        AssertReads();
        var bytes=JsonSerializer.SerializeToUtf8Bytes(this);
        AssertSize(bytes.Length);
        using var file=new FileStream(WindowsPathSeal.Child(workspace,Leaf),FileMode.CreateNew,FileAccess.Write,FileShare.None);
        file.Write(bytes);
        file.Flush(true);
    }

    internal static OfflineConsoleHostIdentity Read(string workspace,string session,uint pid)
    {
        using var file=new FileStream(WindowsPathSeal.Open(WindowsPathSeal.Child(workspace,Leaf),false,true),FileAccess.Read);
        AssertSize(file.Length);
        var bytes=new byte[(int)file.Length];
        file.ReadExactly(bytes);
        return Parse(bytes,session,pid);
    }

    internal static OfflineConsoleHostIdentity Parse(byte[] bytes,string session,uint pid)
    {
        AssertSize(bytes.Length);
        using var document=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=3});
        var root=document.RootElement;
        StrictJson.Fields(root,nameof(SchemaVersion),nameof(SessionId),nameof(Pid),nameof(TokenUser),nameof(LogonName),
            nameof(ProfileDirectory),nameof(ComputerName),nameof(MachineGuid));
        foreach(var field in new[]{nameof(TokenUser),nameof(LogonName),nameof(ProfileDirectory),nameof(ComputerName),nameof(MachineGuid)})
            StrictJson.Fields(root.GetProperty(field),nameof(OfflineConsoleIdentityRead.Error),nameof(OfflineConsoleIdentityRead.Value));
        var result=JsonSerializer.Deserialize<OfflineConsoleHostIdentity>(bytes)??throw WfpNative.Contract("OfflineHostIdentityMissing");
        if(result.SchemaVersion!=1 || result.SessionId!=session || pid==0 || result.Pid!=pid)
            throw WfpNative.Contract("OfflineHostIdentityActorMismatch");
        result.AssertReads();
        return result;
    }

    internal OfflineConsoleHostIdentitySummary Seal(ProtectedState state,VerifiedVersion version,string jobId,OfflineConsoleHostIdentity host,
        SecurityIdentifier? suspendedUser)
    {
        if(SessionId!=host.SessionId || Pid==host.Pid)throw WfpNative.Contract("OfflineHostIdentityReferenceMismatch");
        AssertTokenUser(suspendedUser);
        var hash=state.WriteNew("offline-console-host-identity-"+SessionId+".json",JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,state.InstallationId,SessionId,JobId=jobId,version.Package.Release,version.Package.ManifestHash,
            Restricted=this,TrustedOwner=host
        }));
        return new(hash,Compare(TokenUser,host.TokenUser),Compare(LogonName,host.LogonName),
            Compare(ProfileDirectory,host.ProfileDirectory),Compare(ComputerName,host.ComputerName),Compare(MachineGuid,host.MachineGuid));
    }

    internal void AssertTokenUser(SecurityIdentifier? suspendedUser)
    {
        if(suspendedUser is null || TokenUser.Error!=0 || TokenUser.Value!=suspendedUser.Value)
            throw WfpNative.Contract("OfflineHostIdentityDoesNotMatchHeldProcessToken");
    }

    internal static string Compare(OfflineConsoleIdentityRead restricted,OfflineConsoleIdentityRead host)
    {
        if(host.Error!=0)return "REFERENCE_UNAVAILABLE";
        if(restricted.Error==AccessDenied)return "DENIED";
        if(restricted.Error!=0)return "UNAVAILABLE";
        return string.Equals(restricted.Value,host.Value,StringComparison.OrdinalIgnoreCase)?"MATCHES_HOST":"DIFFERS_FROM_HOST";
    }

    private void AssertReads()
    {
        foreach(var reading in new[]{TokenUser,LogonName,ProfileDirectory,ComputerName,MachineGuid})
            if(reading.Error<0 || (reading.Error==0
                ? reading.Value is not {Length:>0 and <MaximumCharacters} || reading.Value.Any(char.IsControl)
                : reading.Value is not null))
                throw WfpNative.Contract("OfflineHostIdentityFieldBounds");
    }

    private static void AssertSize(long length)
    {
        if(length is <1 or >MaximumReportBytes)throw WfpNative.Contract("OfflineHostIdentitySize");
    }

    private delegate bool NativeRead(StringBuilder buffer,ref int length);
    private static OfflineConsoleIdentityRead ReadNative(NativeRead read)
    {
        var buffer=new StringBuilder(MaximumCharacters);
        var length=buffer.Capacity;
        if(!read(buffer,ref length))
        {
            var error=Marshal.GetLastWin32Error();
            return new(error>0?error:InvalidData,null);
        }
        return buffer.Length>0?new(0,buffer.ToString()):new(InvalidData,null);
    }

    private static OfflineConsoleIdentityRead ReadMachineGuid()
    {
        var buffer=new byte[MaximumCharacters*sizeof(char)];
        var bytes=buffer.Length;
        var error=RegGetValue(LocalMachine,@"SOFTWARE\Microsoft\Cryptography","MachineGuid",RegistryString|Registry64BitView,
            IntPtr.Zero,buffer,ref bytes);
        if(error!=0)return new(error,null);
        if(bytes<4 || bytes>buffer.Length || bytes%2!=0 || buffer[bytes-2]!=0 || buffer[bytes-1]!=0)
            return new(InvalidData,null);
        return new(0,Encoding.Unicode.GetString(buffer,0,bytes-2));
    }

    [DllImport("advapi32.dll",EntryPoint="GetUserNameW",ExactSpelling=true,CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern bool GetUserName(StringBuilder buffer,ref int length);
    [DllImport("userenv.dll",EntryPoint="GetUserProfileDirectoryW",ExactSpelling=true,CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern bool GetUserProfileDirectory(SafeAccessTokenHandle token,StringBuilder buffer,ref int length);
    [DllImport("kernel32.dll",EntryPoint="GetComputerNameExW",ExactSpelling=true,CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern bool GetComputerNameEx(int format,StringBuilder buffer,ref int length);
    [DllImport("advapi32.dll",EntryPoint="RegGetValueW",ExactSpelling=true,CharSet=CharSet.Unicode)]
    private static extern int RegGetValue(IntPtr key,string subkey,string value,uint flags,IntPtr type,[Out] byte[] buffer,ref int bytes);
}

internal readonly record struct OfflineConsoleIdentityRead(int Error,string? Value);
internal sealed record OfflineConsoleHostIdentitySummary(string ReceiptSHA256,string TokenUser,string LogonName,
    string ProfileDirectory,string ComputerName,string MachineGuid);
