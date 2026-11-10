using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace ProtectionLifecycle;

// A narrow observation of Windows graphics-adapter enumeration. The caller
// decides where to seal the LUIDs. Adapter handles never leave this method.
internal static class WddmAdapterProbe
{
    private const string EvidenceLeaf="wddm-adapter-survey.json";
    private const int MaximumEvidenceBytes=8192;
    internal sealed record Adapter(string Luid,uint PresentSources,int CloseStatus);
    internal sealed record Observation(int SizeStatus,int? ReadStatus,uint? Count,Adapter[] Adapters);
    internal sealed record Actor(int SchemaVersion,string JobId,int Pid,long CreatedFileTime,Observation Result);
    internal sealed record Summary(string ReceiptSHA256,int RestrictedSizeStatus,int? RestrictedReadStatus,uint? RestrictedCount,
        int TrustedSizeStatus,int? TrustedReadStatus,uint? TrustedCount,int SharedLuidCount,int RestrictedCloseFailures,int TrustedCloseFailures);

    internal static Actor Capture(string job)
    {
        using var process=Process.GetCurrentProcess();
        return new(1,Identifiers.Hex32(job),process.Id,process.StartTime.ToFileTimeUtc(),Read());
    }

    internal static void Write(string workspace,Actor actor)
    {
        var bytes=JsonSerializer.SerializeToUtf8Bytes(actor);
        if(bytes.Length>MaximumEvidenceBytes)throw WfpNative.Contract("WddmEvidenceSize");
        using var output=new FileStream(WindowsPathSeal.Child(workspace,EvidenceLeaf),FileMode.CreateNew,FileAccess.Write,FileShare.None);
        output.Write(bytes);
        output.Flush(flushToDisk:true);
    }

    internal static Summary Seal(string workspace,ProtectedState state,VerifiedVersion version,string job,uint pid,long created,Actor host)
    {
        using var stream=new FileStream(WindowsPathSeal.Open(WindowsPathSeal.Child(workspace,EvidenceLeaf),false,true),FileAccess.Read);
        if(stream.Length is <1 or >MaximumEvidenceBytes)throw WfpNative.Contract("WddmEvidenceSize");
        var restricted=Parse(stream,job,pid,created);
        if(host.JobId!=job || host.Pid==restricted.Pid || host.CreatedFileTime>=created)
            throw WfpNative.Contract("WddmReferenceActorMismatch");
        var hash=state.WriteNew("independent-wddm-"+job+".json",JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,state.InstallationId,JobId=job,version.Package.Release,version.Package.ManifestHash,
            Restricted=restricted,Trusted=host
        }));
        var a=restricted.Result;
        var b=host.Result;
        var common=a.Adapters.Select(x=>x.Luid).Intersect(b.Adapters.Select(x=>x.Luid),StringComparer.Ordinal).Count();
        return new(hash,a.SizeStatus,a.ReadStatus,a.Count,b.SizeStatus,b.ReadStatus,b.Count,common,
            a.Adapters.Count(x=>x.CloseStatus!=0),b.Adapters.Count(x=>x.CloseStatus!=0));
    }

    internal static Actor Parse(Stream stream,string job,uint pid,long created)
    {
        using var doc=JsonDocument.Parse(stream,new JsonDocumentOptions{MaxDepth=6});
        var root=doc.RootElement;
        StrictJson.Fields(root,"SchemaVersion","JobId","Pid","CreatedFileTime","Result");
        var result=root.GetProperty("Result");
        StrictJson.Fields(result,"SizeStatus","ReadStatus","Count","Adapters");
        var rows=result.GetProperty("Adapters");
        if(rows.GetArrayLength()>64)throw WfpNative.Contract("WddmEvidenceAdapterBound");
        foreach(var row in rows.EnumerateArray())StrictJson.Fields(row,"Luid","PresentSources","CloseStatus");
        var actor=root.Deserialize<Actor>()??throw WfpNative.Contract("WddmEvidenceMissing");
        if(actor.SchemaVersion!=1 || actor.JobId!=job || pid==0 || actor.Pid!=pid ||
            created<=0 || actor.CreatedFileTime!=created)
            throw WfpNative.Contract("WddmEvidenceActorMismatch");
        var data=actor.Result;
        if((data.SizeStatus==0)!=data.ReadStatus.HasValue ||
            (data.Count.HasValue!=(data is {SizeStatus:0,ReadStatus:0})) ||
            (data.Count??0)!=data.Adapters.Length ||
            data.Adapters.Any(row=>row.Luid is not {Length:16} || row.Luid.Any(c=>c is not (>= 'A' and <= 'F' or >= '0' and <= '9'))) ||
            data.Adapters.Select(row=>row.Luid).Distinct(StringComparer.Ordinal).Count()!=data.Adapters.Length)
            throw WfpNative.Contract("WddmEvidenceValues");
        return actor;
    }

    internal static Observation Read()
    {
        if(RuntimeInformation.ProcessArchitecture!=Architecture.X64 ||
            Marshal.SizeOf<EnumAdapters>()!=16 || Marshal.SizeOf<AdapterInfo>()!=20)
            throw new PlatformNotSupportedException("WDDM probe requires the native x64 ABI");

        var query=new EnumAdapters();
        var sizeStatus=Enumerate(ref query);
        if(sizeStatus!=0)return new(sizeStatus,null,null,[]);
        if(query.Count is 0 or >64)throw new InvalidDataException("WddmAdapterCapacityRefused");

        var capacity=query.Count;
        var stride=Marshal.SizeOf<AdapterInfo>();
        var buffer=Marshal.AllocHGlobal(checked((int)capacity*stride));
        try
        {
            query.Adapters=buffer;
            var readStatus=Enumerate(ref query);
            if(readStatus!=0)return new(sizeStatus,readStatus,null,[]);
            if(query.Count>capacity || query.Adapters!=buffer)
                throw new InvalidDataException("WddmAdapterResultShapeDiffers");

            var rows=new List<AdapterInfo>(checked((int)query.Count));
            for(int index=0;index<query.Count;index++)
                rows.Add(Marshal.PtrToStructure<AdapterInfo>(buffer+index*stride));
            var closeStatus=new Dictionary<uint,int>();
            foreach(var row in rows)
            {
                if(row.Handle==0 || closeStatus.ContainsKey(row.Handle))continue;
                var close=new CloseAdapter {Handle=row.Handle};
                closeStatus.Add(row.Handle,Close(ref close));
            }
            if(closeStatus.Count!=rows.Count)
                throw new InvalidDataException("WddmAdapterHandlesRefused");
            return new(sizeStatus,readStatus,query.Count,rows.Select(row=>new Adapter(
                EncodeLuid(row.LuidLow,row.LuidHigh),row.PresentSources,closeStatus[row.Handle])).ToArray());
        }
        finally{Marshal.FreeHGlobal(buffer);}
    }

    private static string EncodeLuid(uint low,int high)
    {
        Span<byte> bytes=stackalloc byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes,low);
        BinaryPrimitives.WriteInt32LittleEndian(bytes[4..],high);
        return Convert.ToHexString(bytes);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EnumAdapters {internal uint Count;internal IntPtr Adapters;}
    [StructLayout(LayoutKind.Sequential)]
    private struct AdapterInfo {internal uint Handle,LuidLow;internal int LuidHigh;internal uint PresentSources,PrecisePresentRegions;}
    [StructLayout(LayoutKind.Sequential)]
    private struct CloseAdapter {internal uint Handle;}

    [DllImport("gdi32.dll",EntryPoint="D3DKMTEnumAdapters2",ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int Enumerate(ref EnumAdapters data);

    [DllImport("gdi32.dll",EntryPoint="D3DKMTCloseAdapter",ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int Close(ref CloseAdapter data);
}
