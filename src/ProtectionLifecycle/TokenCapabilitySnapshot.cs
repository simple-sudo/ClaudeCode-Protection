using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ProtectionLifecycle;

internal sealed record TokenCapability(string Sid,uint Attributes);

// Query only. Existing normal admission paths continue to require Count==0. The
// explicit singleton comparison is for fixed qualification code, not a
// way to grant a capability or select a launch profile from caller data.
internal sealed class TokenCapabilitySnapshot
{
    internal const string InternetClientSid="S-1-15-3-1";
    private readonly TokenCapability[] entries;
    private TokenCapabilitySnapshot(TokenCapability[] entries){this.entries=entries;}
    internal int Count=>entries.Length;
    internal bool IsEmpty=>entries.Length==0;
    internal bool IsExactInternetClient=>entries.Length==1 && entries[0].Sid==InternetClientSid && entries[0].Attributes==4;
    internal TokenCapability[] CopyEntries()=>entries.ToArray();

    internal static TokenCapabilitySnapshot Read(IntPtr token)
    {
        if(token==IntPtr.Zero)throw new InvalidDataException("CapabilityQueryTokenMissing");
        var sized=GetTokenInformation(token,30,IntPtr.Zero,0,out var required);
        if(sized || Marshal.GetLastWin32Error()!=122 || required is <4 or >65536)
            throw new Win32Exception(Marshal.GetLastWin32Error(),"CapabilityQuerySizeInvalid");
        var buffer=Marshal.AllocHGlobal(required);
        try
        {
            if(!GetTokenInformation(token,30,buffer,required,out var used))throw new Win32Exception(Marshal.GetLastWin32Error());
            if(used!=required)throw new InvalidDataException("CapabilityQueryLengthChanged");
            return Parse(buffer,used);
        }
        finally{Marshal.FreeHGlobal(buffer);}
    }
    internal static TokenCapabilitySnapshot Parse(IntPtr buffer,int bytes)
    {
        if(!OperatingSystem.IsWindows() || !Environment.Is64BitProcess || RuntimeInformation.ProcessArchitecture!=Architecture.X64)throw new PlatformNotSupportedException("CapabilityX64LayoutRequired");
        if(buffer==IntPtr.Zero || bytes is <4 or >65536)throw new InvalidDataException("CapabilityBufferInvalid");
        var count=unchecked((uint)Marshal.ReadInt32(buffer));
        if(count>64)throw new InvalidDataException("CapabilityCountExceedsBound");
        if(count==0)
        {
            if(bytes is not (4 or 8))throw new InvalidDataException("EmptyCapabilityBufferInvalid");
            return new(Array.Empty<TokenCapability>());
        }
        var endOfEntries=checked(8+(int)count*16);
        if(bytes<endOfEntries)throw new InvalidDataException("CapabilityEntriesTruncated");
        var entries=new TokenCapability[count];var seen=new HashSet<string>(StringComparer.Ordinal);
        for(int index=0;index<count;index++)
        {
            var entry=8+index*16;var pointer=Marshal.ReadIntPtr(buffer,entry);
            var offset=pointer.ToInt64()-buffer.ToInt64();
            if(offset<endOfEntries || offset>bytes-8)throw new InvalidDataException("CapabilitySidOutsideBuffer");
            var sidOffset=checked((int)offset);
            var revision=Marshal.ReadByte(buffer,sidOffset);var authorities=Marshal.ReadByte(buffer,sidOffset+1);
            if(revision!=1 || authorities is <1 or >15)throw new InvalidDataException("CapabilitySidHeaderInvalid");
            var length=checked(8+4*authorities);
            if(sidOffset>bytes-length)throw new InvalidDataException("CapabilitySidTruncated");
            var sidBytes=new byte[length];Marshal.Copy(pointer,sidBytes,0,length);
            var sid=new SecurityIdentifier(sidBytes,0).Value;
            if(!sid.StartsWith("S-1-15-3-",StringComparison.Ordinal) || !seen.Add(sid))throw new InvalidDataException("CapabilitySidInvalidOrDuplicate");
            entries[index]=new(sid,unchecked((uint)Marshal.ReadInt32(buffer,entry+8)));
        }
        return new(entries);
    }
    [DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)]private static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr buffer,int bytes,out int used);
}
