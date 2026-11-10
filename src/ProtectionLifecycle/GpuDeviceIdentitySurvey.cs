using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProtectionLifecycle;

// Read actual identifiers in each actor. Publish match counts and native
// status only after the exact child is closed. Raw observations stay local.
internal static class GpuDeviceIdentitySurvey
{
    private const string DisplayClass="{4d36e968-e325-11ce-bfc1-08002be10318}";
    private const int MaxBytes=16384;
    private static readonly JsonSerializerOptions Strict=new(){UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,MaxDepth=8};
    private sealed record Actor<T>(int SchemaVersion,string JobId,int Pid,long CreatedFileTime,T Result);
    internal sealed record Snapshot(GpuIdentityObservation.Observation? Cuda,Pnp? Pnp,Nvml? Nvml);
    internal sealed record Pnp(int SizeCode,int? ListCode,PnpDevice[] Devices);
    internal sealed record PnpDevice(string InstanceId,int LocateCode,int? BusCode,uint? Bus,int? AddressCode,uint? Address);
    internal sealed record Nvml(int? LoadError,int? InitCode,int? CountCode,uint? Count,int? ShutdownCode,NvmlDevice[] Devices);
    internal sealed record NvmlDevice(int HandleCode,int? UuidCode,string? Uuid,int? SerialCode,string? Serial,int? PciCode,string? Pci);
    internal sealed record Comparison(int? CudaInitCode,int? NvmlLoadError,int? NvmlInitCode,int? NvmlCountCode,int? NvmlShutdownCode,
        int? PnpSizeCode,int? PnpListCode,int? ObservedCudaUuidValues,int? ObservedNvmlUuidValues,int? ObservedNvmlSerialValues,
        int? ObservedPnpInstances,int CudaUuidHostMatches,int NvmlUuidHostMatches,int PnpInstanceHostMatches,
        int CrossApiHostUuidMatches,int CudaLuidHostWddmMatches,int? ObservedCudaPnpMatches,int? ObservedCudaNvmlPciMatches);
    internal sealed record Summary(string ReceiptSHA256,bool SourcesCompleted,Comparison Matches);

    internal static Snapshot CaptureTrusted()=>new(GpuIdentityObservation.Read(),ReadPnp(),ReadNvml());

    internal static void WriteRestricted(string workspace,string job,long created)
    {
        Write("cuda",GpuIdentityObservation.Read() with {Scope="RESTRICTED_ASSURANCE_GPU_METADATA"});
        Write("pnp",ReadPnp());
        Write("nvml",ReadNvml());
        void Write<T>(string source,T result)
        {
            var bytes=JsonSerializer.SerializeToUtf8Bytes(new Actor<T>(1,job,Environment.ProcessId,created,result));
            if(bytes.Length>MaxBytes)throw WfpNative.Contract("GpuDeviceSurveyBounds");
            using var file=new FileStream(WindowsPathSeal.Child(workspace,Leaf(source)),FileMode.CreateNew,FileAccess.Write,FileShare.None);
            file.Write(bytes);file.Flush(true);
        }
    }

    internal static Summary Seal(string workspace,ProtectedState state,VerifiedVersion version,string job,uint pid,long created,
        Snapshot trusted,WddmAdapterProbe.Observation wddm)
    {
        T? Read<T>(string source) where T:class
        {
            try
            {
                using var file=new FileStream(WindowsPathSeal.Open(WindowsPathSeal.Child(workspace,Leaf(source)),false,true),FileAccess.Read);
                if(file.Length is <1 or >MaxBytes)throw WfpNative.Contract("GpuDeviceSurveyBounds");
                using var document=JsonDocument.Parse(file,new JsonDocumentOptions{MaxDepth=8});
                var root=document.RootElement;
                StrictJson.Fields(root,"SchemaVersion","JobId","Pid","CreatedFileTime","Result");
                var actor=root.Deserialize<Actor<T>>(Strict);
                if(actor is null || actor.Result is null || actor.SchemaVersion!=1 || actor.JobId!=job ||
                    pid==0 || actor.Pid!=pid || created<=0 || actor.CreatedFileTime!=created)
                    throw WfpNative.Contract("GpuDeviceSurveyActorMismatch");
                return actor.Result;
            }
            catch(Win32Exception e) when(e.NativeErrorCode==2){return null;}
        }
        var restricted=new Snapshot(Read<GpuIdentityObservation.Observation>("cuda"),Read<Pnp>("pnp"),Read<Nvml>("nvml"));
        var matches=Compare(restricted,trusted,wddm);
        var hash=state.WriteNew("gpu-device-identity-"+job+".json",JsonSerializer.SerializeToUtf8Bytes(new{
            SchemaVersion=1,state.InstallationId,JobId=job,version.Package.Release,version.Package.ManifestHash,
            RestrictedPid=pid,RestrictedCreatedFileTime=created,Restricted=restricted,Trusted=trusted,Matches=matches}));
        return new(hash,restricted is {Cuda:not null,Pnp:not null,Nvml:not null},matches);
    }

    internal static Comparison Compare(Snapshot restricted,Snapshot trusted,WddmAdapterProbe.Observation wddm)
    {
        static string[] Uuids(IEnumerable<string?> values)=>values.OfType<string>().Where(value=>value.StartsWith("GPU-",StringComparison.OrdinalIgnoreCase) &&
            Guid.TryParseExact(value[4..],"D",out var id) && id!=Guid.Empty).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        static int Common(IEnumerable<string> a,IEnumerable<string> b)=>a.Intersect(b,StringComparer.OrdinalIgnoreCase).Count();
        static string[] CudaIds(Snapshot value)=>Uuids([value.Cuda?.UuidV1,value.Cuda?.UuidV2]);
        static string[] NvmlIds(Snapshot value)=>Uuids(value.Nvml?.Devices.Select(x=>x.Uuid)??[]);
        static string[] PnpIds(Snapshot value)=>value.Pnp?.Devices.Select(x=>x.InstanceId).ToArray()??[];
        var a=CudaIds(restricted);var b=NvmlIds(restricted);var c=CudaIds(trusted);var d=NvmlIds(trusted);
        var pci=Pci(restricted.Cuda?.PciBusId);
        return new(restricted.Cuda?.Steps.FirstOrDefault()?.Result,restricted.Nvml?.LoadError,restricted.Nvml?.InitCode,restricted.Nvml?.CountCode,
            restricted.Nvml?.ShutdownCode,restricted.Pnp?.SizeCode,restricted.Pnp?.ListCode,
            restricted.Cuda is null?null:a.Length,restricted.Nvml is null?null:b.Length,
            restricted.Nvml?.Devices.Count(x=>!string.IsNullOrEmpty(x.Serial)),restricted.Pnp?.Devices.Length,
            Common(a,c),Common(b,d),Common(PnpIds(restricted),PnpIds(trusted)),
            a.Intersect(d,StringComparer.OrdinalIgnoreCase).Union(b.Intersect(c,StringComparer.OrdinalIgnoreCase),StringComparer.OrdinalIgnoreCase).Count(),
            wddm.Adapters.Count(x=>string.Equals(x.Luid,restricted.Cuda?.Luid,StringComparison.Ordinal)),
            pci is {Domain:0} && restricted.Pnp is { } pnp?pnp.Devices.Count(x=>x.Bus==pci.Value.Bus &&
                x.Address==(pci.Value.Device<<16|pci.Value.Function)):null,
            pci.HasValue?restricted.Nvml?.Devices.Count(x=>Pci(x.Pci)==pci):null);
    }

    private static (uint Domain,uint Bus,uint Device,uint Function)? Pci(string? value)
    {
        if(value is null)return null;
        var parts=value.Split(':','.');
        var numbers=new uint[4];
        if(parts.Length!=numbers.Length)return null;
        for(var i=0;i<parts.Length;i++)
            if(!uint.TryParse(parts[i],System.Globalization.NumberStyles.AllowHexSpecifier,null,out numbers[i]))return null;
        return numbers[1]<=255 && numbers[2]<=31 && numbers[3]<=7?(numbers[0],numbers[1],numbers[2],numbers[3]):null;
    }

    private static string Leaf(string source)=>"gpu-device-"+source+".json";

    private static Pnp ReadPnp()
    {
        const uint presentDisplay=0x300;
        var size=PnpNative.Size(out var chars,DisplayClass,presentDisplay);
        if(size!=0)return new(size,null,[]);
        if(chars is 0 or >4096)throw WfpNative.Contract("GpuPnpListBounds");
        var buffer=new char[chars];
        var list=PnpNative.List(DisplayClass,buffer,chars,presentDisplay);
        if(list!=0)return new(size,list,[]);
        var ids=new string(buffer).Split('\0',StringSplitOptions.RemoveEmptyEntries);
        if(ids.Length>32 || ids.Any(id=>id.Length>256 || id.Any(char.IsControl)))throw WfpNative.Contract("GpuPnpInstanceBounds");
        return new(size,list,ids.Select(id=>
        {
            var locate=PnpNative.Locate(out var node,id,0);
            if(locate!=0)return new PnpDevice(id,locate,null,null,null,null);
            (int Code,uint? Value) Read(uint property)
            {
                uint length=4;var code=PnpNative.Property(node,property,out var type,out var value,ref length,0);
                if(code==0 && (type!=4 || length!=4))throw WfpNative.Contract("GpuPnpPropertyShape");
                return(code,code==0?value:null);
            }
            var bus=Read(0x16);var address=Read(0x1d);
            return new PnpDevice(id,locate,bus.Code,bus.Value,address.Code,address.Value);
        }).ToArray());
    }

    private static Nvml ReadNvml()
    {
        if(Marshal.SizeOf<NvmlNative.PciInfo>()!=68)throw WfpNative.Contract("GpuNvmlPciAbi");
        int init;
        try{init=NvmlNative.Init();}
        catch(Exception error)when(error is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {return new(error.HResult,null,null,null,null,[]);}
        if(init!=0)return new(null,init,null,null,null,[]);
        int countCode,shutdown;uint count;var devices=new List<NvmlDevice>();
        try
        {
            countCode=NvmlNative.Count(out count);
            if(countCode==0)
            {
                if(count>16)throw WfpNative.Contract("GpuNvmlDeviceCountBounds");
                for(uint index=0;index<count;index++)
                {
                    var handle=NvmlNative.Handle(index,out var device);
                    if(handle!=0){devices.Add(new(handle,null,null,null,null,null,null));continue;}
                    var uuid=new StringBuilder(96);var uuidCode=NvmlNative.Uuid(device,uuid,(uint)uuid.Capacity);
                    var serial=new StringBuilder(64);var serialCode=NvmlNative.Serial(device,serial,(uint)serial.Capacity);
                    var pciCode=NvmlNative.Pci(device,out var pci);
                    devices.Add(new(handle,uuidCode,uuidCode==0?uuid.ToString():null,serialCode,serialCode==0?serial.ToString():null,
                        pciCode,pciCode==0?pci.BusId:null));
                }
            }
        }
        finally{shutdown=NvmlNative.Shutdown();}
        return new(null,init,countCode,countCode==0?count:null,shutdown,devices.ToArray());
    }

    private static class PnpNative
    {
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("cfgmgr32.dll",EntryPoint="CM_Get_Device_ID_List_SizeW",ExactSpelling=true,CharSet=CharSet.Unicode)]
        internal static extern int Size(out uint chars,string filter,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("cfgmgr32.dll",EntryPoint="CM_Get_Device_ID_ListW",ExactSpelling=true,CharSet=CharSet.Unicode)]
        internal static extern int List(string filter,[Out]char[] list,uint chars,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("cfgmgr32.dll",EntryPoint="CM_Locate_DevNodeW",ExactSpelling=true,CharSet=CharSet.Unicode)]
        internal static extern int Locate(out uint node,string id,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("cfgmgr32.dll",EntryPoint="CM_Get_DevNode_Registry_PropertyW",ExactSpelling=true)]
        internal static extern int Property(uint node,uint property,out uint type,out uint data,ref uint length,uint flags);
    }

    private static class NvmlNative
    {
        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Ansi)]
        internal struct PciInfo
        {
            [MarshalAs(UnmanagedType.ByValTStr,SizeConst=16)] internal string LegacyBusId;
            internal uint Domain,Bus,Device,DeviceId,SubsystemId;
            [MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)] internal string BusId;
        }
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("nvml.dll",EntryPoint="nvmlInit_v2",ExactSpelling=true)] internal static extern int Init();
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("nvml.dll",EntryPoint="nvmlShutdown",ExactSpelling=true)] internal static extern int Shutdown();
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("nvml.dll",EntryPoint="nvmlDeviceGetCount_v2",ExactSpelling=true)] internal static extern int Count(out uint count);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("nvml.dll",EntryPoint="nvmlDeviceGetHandleByIndex_v2",ExactSpelling=true)] internal static extern int Handle(uint index,out IntPtr device);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("nvml.dll",EntryPoint="nvmlDeviceGetUUID",ExactSpelling=true,CharSet=CharSet.Ansi)] internal static extern int Uuid(IntPtr device,StringBuilder value,uint length);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("nvml.dll",EntryPoint="nvmlDeviceGetSerial",ExactSpelling=true,CharSet=CharSet.Ansi)] internal static extern int Serial(IntPtr device,StringBuilder value,uint length);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("nvml.dll",EntryPoint="nvmlDeviceGetPciInfo_v3",ExactSpelling=true)] internal static extern int Pci(IntPtr device,out PciInfo info);
    }
}
