using System.Runtime.InteropServices;
using System.Net.Sockets;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record NetworkContentRead(string Role,uint? SizeStatus,uint RequestedBytes,uint? ReadStatus,uint ReturnedBytes,
    ulong NativeBase,byte[] Content,string? ErrorKind,int? ErrorCode);
internal sealed record GatewayCapabilityEndpoint(int Pid,string Phase,bool Created,bool? OwnedHandleClosed,GatewayChildError[] Errors)
{
    internal static GatewayCapabilityEndpoint Observe()
    {
        var phase="SOCKET_INITIALIZATION";Socket? socket=null;bool created=false;bool? closed=null;Exception? failure=null;
        try
        {
            SessionProxy.InitializeFixedClientSockets();phase="SOCKET_CREATE";socket=SessionProxy.CreateFixedClientSocket();created=true;
            if(socket.IsBound || socket.Connected || socket.AddressFamily!=AddressFamily.InterNetwork || socket.SocketType!=SocketType.Stream || socket.ProtocolType!=ProtocolType.Tcp)
                throw new InvalidDataException("FixedUnboundEndpointDiffers");
        }
        catch(Exception error)when(error is not OutOfMemoryException){failure=error;}
        finally
        {
            if(socket is not null)
                try{var handle=socket.SafeHandle;socket.Dispose();closed=handle.IsClosed;if(closed==true && failure is null)phase="SOCKET_CLOSED";}
                catch(Exception error)when(error is not OutOfMemoryException){failure??=error;closed=false;}
        }
        return new(Environment.ProcessId,phase,created,closed,GatewayChildReport.Describe(failure));
    }
}
internal sealed record GatewayNetworkContent(int Pid,long StartedFileTime,long FinishedFileTime,NetworkContentRead[] Reads)
{
    // This is only a gate for the fixed canary's subsequent HEAD, never full
    // privacy acceptance. Unsupported/empty/error output is not a denial.
    internal bool AllThreeDenied=>Reads.Length==3 && Reads.All(r=>r.ErrorKind is null &&
        (r.SizeStatus==5 && r.ReadStatus is null || r.ReadStatus==5) && r.Content.Length==0);
    // Separately selected finite research canary only. The observed adapter
    // RPC_S_INVALID_BINDING is unavailable evidence, NEVER a privacy denial.
    // No returned host bytes may accompany the fixed synthetic HEAD. The
    // ordinary comparison and every formal/daily path keep their old gate.
    internal bool FixedNoContentHttpsCanaryEligible=>AllThreeDenied ||
        Reads.Length==3 && Reads.Select(r=>r.Role).SequenceEqual(GatewayCapabilityContent.Roles) &&
        Reads.All(r=>r.ErrorKind is null && r.ErrorCode is null && r.Content.Length==0 && r.NativeBase==0 &&
            r.ReadStatus is null && r.RequestedBytes==0 && r.ReturnedBytes==0) &&
        Reads[0].SizeStatus==1702 && Reads[1].SizeStatus==5 && Reads[2].SizeStatus==5;
}

internal static class GatewayCapabilityContent
{
    internal const int MaximumBytes=65536;
    internal static readonly IReadOnlyList<string> Roles=Array.AsReadOnly(new[]{"adapters-all-families","tcp-owner-pid-v4","tcp-owner-pid-v6"});
    internal static GatewayNetworkContent Capture()
    {
        if(!OperatingSystem.IsWindows() || !Environment.Is64BitProcess || RuntimeInformation.ProcessArchitecture!=Architecture.X64)throw new PlatformNotSupportedException("FixedNetworkReadX64Required");
        var start=DateTime.UtcNow.ToFileTimeUtc();
        NetworkContentRead Read(int index)
        {
            uint? sizeStatus=null,status=null;uint size=0,requested=0;ulong origin=0;IntPtr buffer=IntPtr.Zero;
            var content=Array.Empty<byte>();string? error=null;int? code=null;
            uint Query(IntPtr p,ref uint n)=>index==0?GetAdaptersAddresses(0,0x80,IntPtr.Zero,p,ref n):GetExtendedTcpTable(p,ref n,false,index==1?2u:23u,5,0);
            try
            {
                sizeStatus=Query(IntPtr.Zero,ref size);
                // Exactly one sizing read and at most one data read. No growth
                // retry. Full native statuses/returned size remain evidence.
                if(sizeStatus==(index==0?111u:122u) && size is >=4 and <=MaximumBytes)
                {
                    requested=size;buffer=Marshal.AllocHGlobal(checked((int)size));Marshal.Copy(new byte[size],0,buffer,checked((int)size));
                    status=Query(buffer,ref size);
                    if(status==0)
                    {
                        if(size is <4 || size>requested)throw new InvalidDataException("NetworkContentReturnedBounds");
                        origin=index==0?unchecked((ulong)buffer.ToInt64()):0;content=new byte[size];Marshal.Copy(buffer,content,0,content.Length);
                    }
                }
            }
            catch(Exception ex)when(ex is not OutOfMemoryException){error=ex.GetType().Name;code=ex.HResult;content=Array.Empty<byte>();origin=0;}
            finally{if(buffer!=IntPtr.Zero)Marshal.FreeHGlobal(buffer);}
            return new(Roles[index],sizeStatus,requested,status,size,origin,content,error,code);
        }
        var reads=new[]{Read(0),Read(1),Read(2)};
        return new(Environment.ProcessId,start,DateTime.UtcNow.ToFileTimeUtc(),reads);
    }
    [DllImport("iphlpapi.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetAdaptersAddresses(uint family,uint flags,IntPtr reserved,IntPtr addresses,ref uint size);
    [DllImport("iphlpapi.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetExtendedTcpTable(IntPtr table,ref uint size,[MarshalAs(UnmanagedType.Bool)]bool order,uint family,uint kind,uint reserved);
}

// Only the two separately compiled comparison canaries use this larger envelope.
// The original zero-capability feedback schema and bound remain unchanged.
internal sealed record GatewayCapabilityChildReport(int SchemaVersion,GatewayChildReport Gateway,GatewayCapabilityEndpoint? Endpoint,GatewayNetworkContent? Network)
{
    internal const int MaximumCharacters=300000;
    internal static GatewayCapabilityChildReport Parse(string raw,string session,uint pid,uint exit,long ownerCreatedFileTime)
        =>ParseForPurpose(raw,session,pid,exit,ownerCreatedFileTime,false);
    internal static GatewayCapabilityChildReport ParseForPurpose(string raw,string session,uint pid,uint exit,long ownerCreatedFileTime,bool fixedNoContentHttpsCanary)
    {
        if(raw.Length is <2 or >MaximumCharacters)throw new InvalidDataException("CapabilityFeedbackBounds");
        using var doc=JsonDocument.Parse(raw,new JsonDocumentOptions{MaxDepth=8});var root=doc.RootElement;
        StrictJson.Fields(root,"SchemaVersion","Gateway","Endpoint","Network");
        var gateway=GatewayChildReport.Parse(root.GetProperty("Gateway").GetRawText(),session,pid,exit);
        GatewayCapabilityEndpoint? endpoint=null;var ep=root.GetProperty("Endpoint");
        if(ep.ValueKind!=JsonValueKind.Null)
        {
            StrictJson.Fields(ep,"Pid","Phase","Created","OwnedHandleClosed","Errors");
            var errors=ep.GetProperty("Errors");if(errors.ValueKind!=JsonValueKind.Array || errors.GetArrayLength()>4)throw new InvalidDataException("CapabilityEndpointErrorsInvalid");
            foreach(var error in errors.EnumerateArray())StrictJson.Fields(error,"Kind","Code");
            endpoint=JsonSerializer.Deserialize<GatewayCapabilityEndpoint>(ep.GetRawText())??throw new InvalidDataException("CapabilityEndpointMissing");
            if(endpoint.Pid!=pid || endpoint.Phase is not ("SOCKET_INITIALIZATION" or "SOCKET_CREATE" or "SOCKET_CLOSED") ||
                endpoint.Errors is null || endpoint.Errors.Any(e=>e is null || !GatewayChildReport.KnownErrorKind(e.Kind)) ||
                endpoint.Phase=="SOCKET_CLOSED" && (!endpoint.Created || endpoint.OwnedHandleClosed!=true || endpoint.Errors.Length!=0) ||
                !endpoint.Created && (endpoint.OwnedHandleClosed is not null || endpoint.Errors.Length==0) ||
                endpoint.Created && endpoint.OwnedHandleClosed is null || endpoint.Phase=="SOCKET_INITIALIZATION" && endpoint.Created)
                throw new InvalidDataException("CapabilityEndpointIdentityOrOutcomeInvalid");
        }
        GatewayNetworkContent? network=null;var n=root.GetProperty("Network");
        if(n.ValueKind!=JsonValueKind.Null)
        {
            StrictJson.Fields(n,"Pid","StartedFileTime","FinishedFileTime","Reads");
            var reads=n.GetProperty("Reads");if(reads.ValueKind!=JsonValueKind.Array || reads.GetArrayLength()!=3)throw new InvalidDataException("CapabilityReadRolesInvalid");
            foreach(var read in reads.EnumerateArray())StrictJson.Fields(read,"Role","SizeStatus","RequestedBytes","ReadStatus","ReturnedBytes","NativeBase","Content","ErrorKind","ErrorCode");
            network=JsonSerializer.Deserialize<GatewayNetworkContent>(n.GetRawText())??throw new InvalidDataException("CapabilityReadMissing");
            if(ownerCreatedFileTime<=0 || network.Pid!=pid || network.StartedFileTime<ownerCreatedFileTime || network.FinishedFileTime<network.StartedFileTime ||
                network.FinishedFileTime-network.StartedFileTime>TimeSpan.TicksPerSecond*15 || network.Reads is null || network.Reads.Length!=3)
                throw new InvalidDataException("CapabilityReadActorOrTimeInvalid");
            for(int i=0;i<3;i++)
            {
                var r=network.Reads[i];
                if(r is null || r.Role!=GatewayCapabilityContent.Roles[i] || r.Content is null || r.Content.Length>GatewayCapabilityContent.MaximumBytes ||
                    r.RequestedBytes>GatewayCapabilityContent.MaximumBytes || r.Content.Length!=0 && (r.ReadStatus!=0 || r.Content.Length!=r.ReturnedBytes || r.Content.Length>r.RequestedBytes) ||
                    r.ReadStatus is null && r.RequestedBytes!=0 ||
                    r.ReadStatus is not null && (r.RequestedBytes<4 || r.SizeStatus!=(i==0?111u:122u)) ||
                    r.ReadStatus==0 && r.ErrorKind is null && r.Content.Length<4 ||
                    r.NativeBase!=0 && (i!=0 || r.Content.Length==0) || i==0 && r.Content.Length!=0 && r.NativeBase==0 ||
                    r.ErrorKind is not (null or "DllNotFoundException" or "EntryPointNotFoundException" or "InvalidDataException" or "ArgumentException" or "TypeInitializationException" or "UnauthorizedAccessException" or "SecurityException" or "SEHException" or "BadImageFormatException" or "TypeLoadException" or "OverflowException") ||
                    (r.ErrorKind is null)!=(r.ErrorCode is null))throw new InvalidDataException("CapabilityReadDataInvalid");
            }
        }
        bool headEligible=network is not null && (fixedNoContentHttpsCanary?network.FixedNoContentHttpsCanaryEligible:network.AllThreeDenied);
        if(root.GetProperty("SchemaVersion").GetInt32()!=1 || network is null && gateway.Phase is not ("ENVIRONMENT" or "IDENTITY" or "NETWORK_CONTENT_READS") ||
            network is not null && endpoint is null ||
            gateway.Phase is "ENVIRONMENT" or "IDENTITY" && (network is not null || endpoint is not null) ||
            gateway.Phase.StartsWith("HTTPS",StringComparison.Ordinal) && !headEligible ||
            gateway.Phase=="COMPLETE" && (!headEligible || endpoint is not {Created:true,OwnedHandleClosed:true,Phase:"SOCKET_CLOSED"}) ||
            gateway.Phase=="NETWORK_CONTENT_REQUIRES_ANALYSIS" && (network is null || headEligible))
            throw new InvalidDataException("CapabilityFeedbackOutcomeInvalid");
        return new(1,gateway,endpoint,network);
    }
    internal static async Task<string> ReadBounded(StreamReader reader)
    {
        var buffer=new char[MaximumCharacters+1];int used=0;
        while(used<buffer.Length){int count=await reader.ReadAsync(buffer.AsMemory(used));if(count==0)return new string(buffer,0,used);used+=count;}
        throw new InvalidDataException("CapabilityFeedbackBounds");
    }
}
