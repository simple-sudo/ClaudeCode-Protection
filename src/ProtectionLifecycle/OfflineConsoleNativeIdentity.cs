using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed record OfflineConsoleNativeIdentity(OfflineConsoleIdentityRead LsaName,OfflineConsoleIdentityRead LsaDomain,
    OfflineConsoleIdentityRead FirmwareUuid,OfflineConsoleIdentityRead FirmwareSerial)
{
    private const int InvalidData=13,NotFound=1168,MaximumFirmwareBytes=1024*1024;
    private const uint RawSmbios=0x52534d42;

    internal static OfflineConsoleNativeIdentity Capture(SafeAccessTokenHandle token)
    {
        var (name,domain)=ReadOwnLogon(token);
        var (uuid,serial)=ReadFirmware();
        return new(name,domain,uuid,serial);
    }

    private static (OfflineConsoleIdentityRead,OfflineConsoleIdentityRead) ReadOwnLogon(SafeAccessTokenHandle token)
    {
        ulong authenticationId;
        try{authenticationId=WindowsTokenInformation.ReadAuthenticationId(token);}
        catch(Win32Exception error){return Failure(error.NativeErrorCode);}
        var status=LsaGetLogonSessionData(in authenticationId,out var buffer);
        if(status!=0)return Failure(unchecked((int)LsaNtStatusToWinError(status)));
        if(buffer==IntPtr.Zero)return Failure(InvalidData);
        try
        {
            if(Marshal.ReadInt32(buffer)<Marshal.SizeOf<LogonPrefix>())return Failure(InvalidData);
            var logon=Marshal.PtrToStructure<LogonPrefix>(buffer);
            if(logon.IdLow!=(uint)authenticationId || logon.IdHigh!=(uint)(authenticationId>>32))
                return Failure(InvalidData);
            return (ReadLsaText(logon.Name),ReadLsaText(logon.Domain));
        }
        finally{_=LsaFreeReturnBuffer(buffer);}
    }

    private static OfflineConsoleIdentityRead ReadLsaText(LsaText text)
    {
        if(text.Length==0)return new(NotFound,null);
        if(text.Length>text.MaximumLength || text.Length>=2048 || text.Length%2!=0 || text.Buffer==IntPtr.Zero)
            return new(InvalidData,null);
        var value=Marshal.PtrToStringUni(text.Buffer,text.Length/2)!;
        return value.Any(char.IsControl)?new(InvalidData,null):new(0,value);
    }

    private static (OfflineConsoleIdentityRead,OfflineConsoleIdentityRead) ReadFirmware()
    {
        var length=GetSystemFirmwareTable(RawSmbios,0,null,0);
        if(length==0)return Failure(Marshal.GetLastWin32Error());
        if(length is <8 or >MaximumFirmwareBytes)return Failure(InvalidData);
        var buffer=new byte[length];
        var count=GetSystemFirmwareTable(RawSmbios,0,buffer,length);
        if(count==0)return Failure(Marshal.GetLastWin32Error());
        return count==length?ParseFirmware(buffer):Failure(InvalidData);
    }

    // RSMB returns an eight-byte Windows header followed by SMBIOS structures.
    // Retain the exact 16 UUID bytes and serial bytes for same-source comparison.
    internal static (OfflineConsoleIdentityRead,OfflineConsoleIdentityRead) ParseFirmware(byte[] bytes)
    {
        ReadOnlySpan<byte> data=bytes;
        if(data.Length<8 || BinaryPrimitives.ReadUInt32LittleEndian(data[4..])!=data.Length-8)
            return Failure(InvalidData);
        var table=data[8..];
        while(table.Length>=4)
        {
            var type=table[0];
            var length=table[1];
            if(length<4 || length>table.Length)return Failure(InvalidData);
            var strings=table[length..];
            var end=strings.IndexOf((ReadOnlySpan<byte>)[0,0]);
            if(end<0)return Failure(InvalidData);
            if(type==1)
            {
                if(length<8)return Failure(InvalidData);
                var uuid=length>=24?Uuid(table.Slice(8,16)):new(NotFound,null);
                return (uuid,Serial(strings[..end],table[7]));
            }
            if(type==127)return Failure(NotFound);
            table=strings[(end+2)..];
        }
        return Failure(InvalidData);
    }

    private static OfflineConsoleIdentityRead Uuid(ReadOnlySpan<byte> bytes) =>
        bytes.IndexOfAnyExcept((byte)0)<0 || bytes.IndexOfAnyExcept((byte)255)<0
            ?new(NotFound,null):new(0,Convert.ToHexString(bytes));

    private static OfflineConsoleIdentityRead Serial(ReadOnlySpan<byte> strings,int index)
    {
        if(index==0)return new(NotFound,null);
        while(index>1)
        {
            var separator=strings.IndexOf((byte)0);
            if(separator<0)return new(InvalidData,null);
            strings=strings[(separator+1)..];
            index--;
        }
        var next=strings.IndexOf((byte)0);
        var value=next<0?strings:strings[..next];
        return value.Length is >0 and <=128?new(0,Convert.ToHexString(value)):new(InvalidData,null);
    }

    private static (OfflineConsoleIdentityRead,OfflineConsoleIdentityRead) Failure(int error)
    {
        var read=new OfflineConsoleIdentityRead(error>0?error:InvalidData,null);
        return (read,read);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LsaText
    {
        internal ushort Length,MaximumLength;
        internal IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LogonPrefix
    {
        internal uint Size,IdLow,IdHigh;
        internal LsaText Name,Domain;
    }

    [DllImport("secur32.dll",ExactSpelling=true)]
    private static extern uint LsaGetLogonSessionData(in ulong id,out IntPtr data);
    [DllImport("secur32.dll",ExactSpelling=true)]
    private static extern uint LsaFreeReturnBuffer(IntPtr data);
    [DllImport("advapi32.dll",ExactSpelling=true)]
    private static extern uint LsaNtStatusToWinError(uint status);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]
    private static extern uint GetSystemFirmwareTable(uint provider,uint table,[Out] byte[]? buffer,uint size);
}
