using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

// Runs only after the fixed offline worker has checked its identity, private
// desktop, isolated environment and inherited standard streams.
internal static class IndependentGpuWorkload
{
    internal const string ChildCommand="private-window-cuda-child";
    internal const string Scope="FIXED_INDEPENDENT_CUDA_FULL_QUARANTINE";

    internal sealed record Capture(string Status,GpuReportedCall? LastCall,GpuReportedCall? FirstFailedCall,
        bool ReportComplete,bool SuccessfulCallSequence,bool ComputationQualified)
    {
        public GpuInitLoader.Checkpoint? LastInit {get;init;}
    }

    internal static int RunChild(string job)
    {
        SessionZeroStartupBranchTrace.CudaAccessTrace.WaitForObserver();
        var plan=new GpuProbePlan(job,1);
        using var output=new StreamWriter(Console.OpenStandardOutput(),new UTF8Encoding(false,true)){NewLine="\n"};
        var progress=new GpuCallProgressWriter(output,job,Environment.ProcessId);
        var report=GpuQualification.ComputeWithSplitInit(plan,GpuQualification.LpacScope,progress);
        output.WriteLine(JsonSerializer.Serialize(report));
        output.Flush();
        return GpuQualification.Qualified(report)?0:3;
    }

    internal static Capture Observe(string job,uint pid,uint? exit,OfflineConsoleOutput? output,OfflineConsoleOutput? error)
    {
        if(pid is 0 or >int.MaxValue || output is null || error is null)
            return new("CAPTURE_UNAVAILABLE",null,null,false,false,false);
        if(output.Overflow || error.Overflow || output.Bytes.Length>OfflineConsoleStreams.GpuOutputMaximumBytes)
            return new("CAPTURE_OVERFLOW",null,null,false,false,false);
        var reader=new GpuCallProgressReader(job,true,splitInit:true);
        reader.Bind((int)pid);
        try
        {
            using var text=new StringReader(new UTF8Encoding(false,true).GetString(output.Bytes));
            var final=reader.ReadClosedCaptureAsync(text).GetAwaiter().GetResult();
            if(final is null)return new(reader.Snapshot() is null?"NO_BOUND_CALLS":"BOUND_PROGRESS_ONLY",
                reader.Snapshot(),reader.FirstFailure(),false,false,false){LastInit=reader.InitSnapshot()};
            var report=JsonSerializer.Deserialize<GpuChildReport>(final);
            if(report is null || report.SchemaVersion!=1 || report.Scope!=GpuQualification.LpacScope || report.Pid!=(int)pid || report.Nonce!=job)
                return new("REPORT_BINDING_REFUSED",null,null,false,false,false);
            var sequence=reader.ReportsCompleteSuccessfulSequence;
            var qualified=sequence && exit==0 && error.Bytes.Length==0 && GpuQualification.Qualified(report);
            return new(qualified?"CUDA_RESULT_OBSERVED":"CUDA_RESULT_NOT_QUALIFIED",reader.Snapshot(),reader.FirstFailure(),true,sequence,qualified)
                {LastInit=reader.InitSnapshot()};
        }
        catch(Exception e) when(e is JsonException or InvalidDataException or DecoderFallbackException)
        {
            return new("CAPTURE_PROTOCOL_REFUSED",null,null,false,false,false);
        }
    }
}
