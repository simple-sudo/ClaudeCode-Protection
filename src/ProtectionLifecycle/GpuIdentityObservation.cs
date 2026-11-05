#nullable enable
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace ProtectionLifecycle;

// Trusted assurance data only. Never sent to the formal Claude tool channel.
// Queries device metadata; creates no CUDA context, allocation, kernel or model.
internal static class GpuIdentityObservation
{
    internal sealed record Step(string Api,int? Result,string? ErrorType,int? ErrorCode);
    internal sealed record Observation(string Scope,string AtUtc,int? DriverVersion,int? DeviceCount,string? Name,
        ulong? TotalMemoryBytes,string? UuidV1,string? UuidV2,string? Luid,uint? NodeMask,Step[] Steps);
    internal static Observation Read()
    {
        var steps=new List<Step>();int? driver=null,count=null;string? name=null,uuid1=null,uuid2=null,luid=null;
        ulong? memory=null;uint? nodeMask=null;
        bool Call(string api,Func<int> query)
        {
            try{int code=query();steps.Add(new(api,code,null,null));return code==0;}
            catch(Exception error) when(error is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
            {steps.Add(new(api,null,error.GetType().Name,error.HResult));return false;}
        }
        var stamp=DateTime.UtcNow.ToString("o");
        if(Call("cuInit",()=>Cuda.Init(0)))
        {
            int value=0;if(Call("cuDriverGetVersion",()=>Cuda.DriverVersion(out value)))driver=value;
            value=0;if(Call("cuDeviceGetCount",()=>Cuda.DeviceCount(out value)))count=value;
            int device=0;
            if(count is >0 and <=32 && Call("cuDeviceGet[ordinal0]",()=>Cuda.DeviceGet(out device,0)))
            {
                var text=new StringBuilder(128);if(Call("cuDeviceGetName",()=>Cuda.Name(text,text.Capacity,device)))name=text.ToString();
                nuint total=0;if(Call("cuDeviceTotalMem_v2",()=>Cuda.TotalMemory(out total,device)))memory=(ulong)total;
                var a=new byte[16];if(Call("cuDeviceGetUuid",()=>Cuda.Uuid(a,device)))uuid1=Uuid(a);
                var b=new byte[16];if(Call("cuDeviceGetUuid_v2",()=>Cuda.UuidV2(b,device)))uuid2=Uuid(b);
                var bytes=new byte[8];uint mask=0;
                if(Call("cuDeviceGetLuid",()=>Cuda.Luid(bytes,out mask,device))){luid=Convert.ToHexString(bytes);nodeMask=mask;}
            }
        }
        return new("TRUSTED_ASSURANCE_GPU_METADATA_NOT_COMPUTE_OR_ADMISSION",stamp,driver,count,name,memory,uuid1,uuid2,luid,nodeMask,steps.ToArray());
    }
    private static string Uuid(byte[] bytes)
    {
        // CUuuid is 16 octets, not Windows GUID's mixed-endian representation.
        var hex=Convert.ToHexString(bytes).ToLowerInvariant();
        return "GPU-"+hex[..8]+"-"+hex[8..12]+"-"+hex[12..16]+"-"+hex[16..20]+"-"+hex[20..];
    }
    private static class Cuda
    {
        [DllImport("nvcuda.dll",EntryPoint="cuInit",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int Init(uint flags);
        [DllImport("nvcuda.dll",EntryPoint="cuDriverGetVersion",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int DriverVersion(out int value);
        [DllImport("nvcuda.dll",EntryPoint="cuDeviceGetCount",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int DeviceCount(out int value);
        [DllImport("nvcuda.dll",EntryPoint="cuDeviceGet",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int DeviceGet(out int value,int ordinal);
        [DllImport("nvcuda.dll",EntryPoint="cuDeviceGetName",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int Name([Out]StringBuilder name,int length,int device);
        [DllImport("nvcuda.dll",EntryPoint="cuDeviceTotalMem_v2",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int TotalMemory(out nuint bytes,int device);
        [DllImport("nvcuda.dll",EntryPoint="cuDeviceGetUuid",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int Uuid([Out]byte[] uuid,int device);
        [DllImport("nvcuda.dll",EntryPoint="cuDeviceGetUuid_v2",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int UuidV2([Out]byte[] uuid,int device);
        [DllImport("nvcuda.dll",EntryPoint="cuDeviceGetLuid",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] internal static extern int Luid([Out]byte[] luid,out uint nodeMask,int device);
    }
}
