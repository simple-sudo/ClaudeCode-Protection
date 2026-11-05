using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using System.Net.NetworkInformation;
using ProtectionLifecycle;

// Ordinary trusted reference only. No endpoint, socket, external resolution,
// token adjustment, ACL/WFP change or protected process creation.
internal static class HostReference
{
    internal sealed record Capture(string Api,uint Family,uint Flags,uint SizeStatus,uint ReadStatus,uint RequiredBytes,
        uint ReturnedBytes,string? BufferBase,string? RawBase64,string Status,string CapturedUtc,int PointerSize);
    [DllImport("iphlpapi.dll",ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetAdaptersAddresses(uint family,uint flags,IntPtr reserved,IntPtr buffer,ref uint size);
    [DllImport("iphlpapi.dll",ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetExtendedTcpTable(IntPtr buffer,ref uint size,[MarshalAs(UnmanagedType.Bool)]bool sort,uint family,int tableClass,uint reserved);

    internal static void Run(string directory)
    {
        using var identity=WindowsIdentity.GetCurrent();
        if(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))throw new InvalidOperationException("Ordinary reference only");
        if(Directory.Exists(directory) || File.Exists(directory))throw new IOException("Fresh evidence directory required");
        Directory.CreateDirectory(directory);
        Write(directory,"identity.json",new {Scope="TRUSTED_ORDINARY_REFERENCE_ONLY_NOT_LPAC",User=identity.User?.Value,AtUtc=DateTime.UtcNow,
            ExternalTrafficRequested=false,SecurityModified=false,ProtectedIdentityTested=false});
        foreach(uint family in new uint[]{0,2,23})
        {
            var capture=Read(family);var name=family==0?"adapters":family==2?"tcp4":"tcp6";
            Write(directory,name+"-raw.json",capture);
            if(capture.Status!="COMPLETE_BUFFER")continue;
            byte[] bytes=Convert.FromBase64String(capture.RawBase64!);
            try
            {
                object content=family==0?NetworkContentSnapshot.DecodeAdapters(bytes,Convert.ToUInt64(capture.BufferBase![2..],16),capture.PointerSize)
                    :NetworkContentSnapshot.DecodeTcp(bytes,family);
                Write(directory,name+"-decoded.json",new {Status="DECODED_REFERENCE_NOT_PRIVACY_PASS",Content=content});
            }
            catch(Exception error) when(error is InvalidDataException or ArgumentException or OverflowException)
            {Write(directory,name+"-decoded.json",new {Status="UNKNOWN_DECODE_FAILED",Error=error.Message});}
        }
        // Independently implemented .NET decoding; underlying Windows sources
        // can be shared. Sequential snapshots are not atomic network evidence.
        var adapters=NetworkInterface.GetAllNetworkInterfaces().Select(adapter=>
        {
            var properties=adapter.GetIPProperties();
            return new {adapter.Id,adapter.Name,adapter.Description,Mac=adapter.GetPhysicalAddress().ToString(),
                Dns=properties.DnsAddresses.Select(a=>a.ToString()).ToArray(),
                Unicast=properties.UnicastAddresses.Select(a=>a.Address.ToString()).ToArray(),
                Gateways=properties.GatewayAddresses.Select(a=>a.Address.ToString()).ToArray()};
        }).ToArray();
        Write(directory,"managed-crosscheck.json",new {Scope="DOTNET_DECODER_CROSSCHECK_SHARED_OS_SOURCES_NONATOMIC",AtUtc=DateTime.UtcNow,Adapters=adapters});
        Console.WriteLine("Ordinary local network reference retained. No LPAC/privacy qualification issued.");
    }
    private static Capture Read(uint family)
    {
        string api=family==0?"GetAdaptersAddresses":"GetExtendedTcpTable",time=DateTime.UtcNow.ToString("o");uint flags=family==0?0x80u:0u;
        uint size=0;uint first=family==0?GetAdaptersAddresses(0,flags,IntPtr.Zero,IntPtr.Zero,ref size):GetExtendedTcpTable(IntPtr.Zero,ref size,false,family,5,0);
        uint required=size;
        Capture Failure(string status,uint read=0)=>new(api,family,flags,first,read,required,size,null,null,status,time,IntPtr.Size);
        if(first!=(family==0?111u:122u))return Failure("UNKNOWN_SIZE_RETURN");
        if(size is <4 or >262144)return Failure("UNKNOWN_SIZE_BOUNDS");
        int capacity=(int)size;var pointer=Marshal.AllocHGlobal(capacity);
        try
        {
            Marshal.Copy(new byte[capacity],0,pointer,capacity);
            uint status=family==0?GetAdaptersAddresses(0,flags,IntPtr.Zero,pointer,ref size):GetExtendedTcpTable(pointer,ref size,false,family,5,0);
            if(status!=0)return Failure("READ_FAILED_NOT_PRIVACY_PASS",status);
            if(size<4 || size>capacity)return Failure("UNKNOWN_RETURN_BOUNDS",status);
            int used=(int)size;
            if(family!=0)
            {
                ulong exact=4+(ulong)unchecked((uint)Marshal.ReadInt32(pointer))*(family==2?24u:56u);
                if(exact>size)return Failure("UNKNOWN_TABLE_BOUNDS",status);
                used=(int)exact;
            }
            var bytes=new byte[used];Marshal.Copy(pointer,bytes,0,used);
            return new(api,family,flags,first,status,required,size,"0x"+unchecked((ulong)pointer.ToInt64()).ToString("X16"),Convert.ToBase64String(bytes),"COMPLETE_BUFFER",time,IntPtr.Size);
        }
        finally{Marshal.FreeHGlobal(pointer);}
    }
    internal static void Write(string directory,string name,object value)
    {
        using var file=new FileStream(Path.Combine(directory,name),FileMode.CreateNew,FileAccess.Write,FileShare.None);
        file.Write(JsonSerializer.SerializeToUtf8Bytes(value,new JsonSerializerOptions{WriteIndented=true}));file.Flush(true);
    }
}
