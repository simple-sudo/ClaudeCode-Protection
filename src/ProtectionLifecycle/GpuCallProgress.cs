using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

// Advisory progress on the original GPU child's inherited output pipe. The
// owner binds PID/nonce before resume. These reports never prove execution,
// privacy, cleanup or permission to start/recover a session.
internal sealed record GpuReportedCall(int Sequence,int ApiIndex,string Api,string Phase,int? Code);
internal sealed class GpuCallProgressWriter
{
    private readonly TextWriter output;
    private readonly string nonce;
    private readonly int pid;
    private int sequence;
    private int initSequence;
    internal GpuCallProgressWriter(TextWriter output,string nonce,int pid)
    {GpuCallProgressReader.ValidateIdentity(nonce,pid);this.output=output;this.nonce=nonce;this.pid=pid;}
    internal void Emit(int api,int phase,int? code)
    {
        if(sequence>=32 || api is <0 or >15 || phase is <0 or >2 || (phase==0)!=(code is null))throw new InvalidDataException("GpuProgressWriterContract");
        output.WriteLine(JsonSerializer.Serialize(new{Kind="GPU_CALL_PROGRESS_V1",Nonce=nonce,Pid=pid,Sequence=++sequence,Api=api,Phase=phase,Code=code}));
        output.Flush();
    }

    internal void EmitInit(GpuInitLoader.Checkpoint checkpoint)
    {
        output.WriteLine(JsonSerializer.Serialize(new {
            Kind="GPU_INIT_PROGRESS_V1",Nonce=nonce,Pid=pid,Sequence=++initSequence,
            Phase=(int)checkpoint.Phase,checkpoint.Returned,checkpoint.Code,checkpoint.InDriverImage
        }));
        output.Flush();
    }
}

internal sealed class GpuCallProgressReader
{
    internal static readonly string[] Stages={"cuInit","cuDriverGetVersion","cuDeviceGetCount","cuDeviceGet","cuDeviceGetName","cuCtxCreate_v2",
        "cuMemAlloc_v2","cuMemcpyHtoD_v2","cuModuleLoadData","cuModuleGetFunction","cuLaunchKernel","cuCtxSynchronize","cuMemcpyDtoH_v2",
        "cuModuleUnload","cuMemFree_v2","cuCtxDestroy_v2"};
    private readonly string nonce;
    private readonly bool progressRequired;
    private readonly bool splitInit;
    private readonly object sync=new();
    private int pid,lastApi=-1,sequence;
    private bool pending,final,reportedFailure;
    private uint returnedSuccessfully;
    private GpuReportedCall? latest,firstFailure;
    private int initSequence;
    private GpuInitLoader.Checkpoint? lastInit;
    internal GpuCallProgressReader(string nonce,bool progressRequired,bool splitInit=false)
    {ValidateIdentity(nonce,1);this.nonce=nonce;this.progressRequired=progressRequired;this.splitInit=splitInit;}
    internal void Bind(int expectedPid)
    {lock(sync){ValidateIdentity(nonce,expectedPid);if(pid!=0)throw Bad();pid=expectedPid;}}
    internal GpuReportedCall? Snapshot(){lock(sync)return latest;}
    internal GpuReportedCall? FirstFailure(){lock(sync)return firstFailure;}
    internal GpuInitLoader.Checkpoint? InitSnapshot(){lock(sync)return lastInit;}
    internal bool ReportsCompleteSuccessfulSequence
    {get{lock(sync)return final && !pending && !reportedFailure && returnedSuccessfully==0xffff && sequence==32;}}
    internal static void ValidateIdentity(string nonce,int pid)
    {if(pid<=0 || nonce.Length!=32 || nonce.Any(c=>!char.IsAsciiHexDigitLower(c)))throw Bad();}
    private static InvalidDataException Bad()=>new("GpuProgressPipeContract");

    internal async Task<string> ReadAsync(TextReader input)=>
        await ReadCoreAsync(input,requireFinal:true).ConfigureAwait(false)??throw Bad();

    // The independent creator retains the original stream after stopping the
    // Job. A missing final report may still leave complete, bound call frames.
    // A torn final line never becomes a report in this capture mode.
    internal Task<string?> ReadClosedCaptureAsync(TextReader input)=>ReadCoreAsync(input,requireFinal:false);

    private async Task<string?> ReadCoreAsync(TextReader input,bool requireFinal)
    {
        var line=new StringBuilder();var character=new char[1];var total=0;string? report=null;
        // Read a character at a time so an entered-call frame becomes visible
        // before a blocked native call, without waiting for a full buffer/EOF.
        while(await input.ReadAsync(character.AsMemory())!=0)
        {
            if(++total>32768)throw Bad();var value=character[0];
            if(value=='\n'){Consume(line.ToString().TrimEnd('\r'));line.Clear();}
            else {if(line.Length>=16384)throw Bad();line.Append(value);}
        }
        if(line.Length!=0 && requireFinal)Consume(line.ToString()); // legacy complete final JSON
        if(line.Length!=0 && !requireFinal && report is not null)throw Bad();
        if(report is null && requireFinal)throw Bad();return report;

        void Consume(string text)
        {
            lock(sync)
            {
                if(final || pid==0 || text.Length==0)throw Bad();
                using var document=JsonDocument.Parse(text,new JsonDocumentOptions{MaxDepth=8});var root=document.RootElement;
                Unique(root);
                if(root.ValueKind!=JsonValueKind.Object || Text(root,"Nonce")!=nonce || Number(root,"Pid")!=pid)throw Bad();
                if(!root.TryGetProperty("Kind",out var kind))
                {
                    if(text.Length>16384 || Number(root,"SchemaVersion")!=1 || pending || progressRequired && sequence==0)throw Bad();
                    report=text;final=true;return;
                }
                if(!progressRequired || text.Length>512 || kind.ValueKind!=JsonValueKind.String)throw Bad();
                if(kind.GetString()=="GPU_INIT_PROGRESS_V1")
                {
                    ConsumeInit(root);
                    return;
                }
                if(kind.GetString()!="GPU_CALL_PROGRESS_V1" ||
                    root.EnumerateObject().Count()!=7 || root.EnumerateObject().Any(p=>p.Name is not ("Kind" or "Nonce" or "Pid" or "Sequence" or "Api" or "Phase" or "Code")))throw Bad();
                var next=Number(root,"Sequence");var api=Number(root,"Api");var phase=Number(root,"Phase");
                var code=Field(root,"Code").ValueKind==JsonValueKind.Null?(int?)null:Number(root,"Code");
                if(next!=sequence+1 || next>32 || api is <0 or >15 || phase is <0 or >2 || (phase==0)!=(code is null))throw Bad();
                if(phase==0)
                {
                    if(pending || api<=lastApi || api<13 && api!=lastApi+1)throw Bad();
                    pending=true;lastApi=api;
                }
                else
                {
                    if(!pending || api!=lastApi)throw Bad();
                    if(splitInit && api==0 && phase==1 &&
                        (initSequence!=6 || lastInit?.Code!=code))throw Bad();
                    pending=false;
                    if(phase==1 && code==0)returnedSuccessfully|=1u<<api;else reportedFailure=true;
                }
                sequence=next;latest=new(next,api,Stages[api],phase==0?"ENTERED_NOT_RETURNED":phase==1?"RETURNED":"THREW",code);
                if(phase!=0 && (phase!=1 || code!=0))firstFailure??=latest;
            }
        }
    }

    private void ConsumeInit(JsonElement root)
    {
        if(!splitInit || !pending || lastApi!=0 || sequence!=1 || initSequence>=6 ||
            root.EnumerateObject().Count()!=8 || root.EnumerateObject().Any(p=>p.Name is not
                ("Kind" or "Nonce" or "Pid" or "Sequence" or "Phase" or "Returned" or "Code" or "InDriverImage")))
            throw Bad();
        if(initSequence>0 && lastInit is {Returned:true} prior &&
            (prior.Code!=0 || prior.InDriverImage==false))throw Bad();

        var next=Number(root,"Sequence");
        var phase=(GpuInitLoader.Phase)Number(root,"Phase");
        var returned=Boolean(root,"Returned");
        var code=Field(root,"Code").ValueKind==JsonValueKind.Null?(int?)null:Number(root,"Code");
        var owned=Field(root,"InDriverImage").ValueKind==JsonValueKind.Null?(bool?)null:Boolean(root,"InDriverImage");
        if(next!=initSequence+1 || phase!=(GpuInitLoader.Phase)(initSequence/2) || returned!=(initSequence%2==1) ||
            returned!=code.HasValue || owned.HasValue!=(phase==GpuInitLoader.Phase.Resolve && code==0))throw Bad();
        initSequence=next;
        lastInit=new(phase,returned,code,owned);
    }

    private static bool Boolean(JsonElement root,string name)=>Field(root,name).ValueKind switch {
        JsonValueKind.True=>true,JsonValueKind.False=>false,_=>throw Bad()
    };
    private static JsonElement Field(JsonElement root,string name)=>root.TryGetProperty(name,out var item)?item:throw Bad();
    private static int Number(JsonElement root,string name)=>Field(root,name).ValueKind==JsonValueKind.Number && Field(root,name).TryGetInt32(out var value)?value:throw Bad();
    private static string Text(JsonElement root,string name)=>Field(root,name).ValueKind==JsonValueKind.String?Field(root,name).GetString()!:throw Bad();
    private static void Unique(JsonElement value)
    {
        if(value.ValueKind==JsonValueKind.Object)
        {var names=new HashSet<string>(StringComparer.Ordinal);foreach(var property in value.EnumerateObject()){if(!names.Add(property.Name))throw Bad();Unique(property.Value);}}
        else if(value.ValueKind==JsonValueKind.Array)foreach(var item in value.EnumerateArray())Unique(item);
    }
}
