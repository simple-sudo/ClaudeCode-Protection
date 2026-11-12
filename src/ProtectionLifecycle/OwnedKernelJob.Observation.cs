using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using Microsoft.Win32.SafeHandles;
using System.Text.Json;
using System.Runtime.InteropServices;

namespace ProtectionLifecycle;

internal sealed partial class OwnedKernelJob
{
    internal JobSnapshot Observe()
    {
        AssertHeld();
        if(!QueryLimits(handle,9,out var limits,(uint)Marshal.SizeOf<ExtendedLimits>(),out _))throw Error("QueryOwnedJobLimits");
        var before=Active();var ids=ProcessIds();var after=Active();
        return new(intent.JobId,limits.Basic.LimitFlags,before,after,ids,DateTime.UtcNow.ToString("o"));
    }
    internal bool ContainsProcess(SafeProcessHandle process)
    {
        AssertHeld();if(!IsProcessInJob(process,handle,out var belongs))throw Error("InspectExactJobMembership");return belongs;
    }
    internal void AssertSingleProcessEverAdmitted()
    {
        AssertHeld();
        if(Accounting().TotalProcesses!=1)throw WfpNative.Contract("OfflineConsoleJobProcessCountDiffers");
    }
    private uint Active()=>Accounting().ActiveProcesses;
    private BasicAccounting Accounting()
    {
        if(!QueryAccounting(handle,1,out var accounting,(uint)Marshal.SizeOf<BasicAccounting>(),out _))throw Error("QueryOwnedJobAccounting");
        return accounting;
    }
    private uint[] ProcessIds()
    {
        for(var capacity=32;capacity<=4096;capacity*=2)
        {
            var length=checked(8+IntPtr.Size*capacity);var buffer=Marshal.AllocHGlobal(length);
            try
            {
                if(!QueryBuffer(handle,3,buffer,(uint)length,out _))
                {var error=Marshal.GetLastWin32Error();if(error==234 && capacity<4096)continue;throw new Win32Exception(error,"QueryOwnedJobMembers");}
                var assigned=Marshal.ReadInt32(buffer,0);var count=Marshal.ReadInt32(buffer,4);
                if(assigned<0 || count<0 || count>capacity || count>assigned)throw new InvalidDataException("Invalid job member buffer");
                if(count<assigned){if(capacity<4096)continue;throw new InvalidDataException("Job member capacity exceeded; no truncated zero observation");}
                var result=new uint[count];
                for(var i=0;i<count;i++)result[i]=checked((uint)Marshal.ReadIntPtr(buffer,8+i*IntPtr.Size).ToInt64());
                if(result.Any(id=>id==0) || result.Distinct().Count()!=result.Length)throw new InvalidDataException("Invalid/duplicate job member identifier");
                return result;
            }
            finally{Marshal.FreeHGlobal(buffer);}
        }
        throw new InvalidDataException("Job member capacity exceeded");
    }
    internal JobSnapshot StopAndVerifyZero()
    {
        AssertHeld();var attempt=Guid.NewGuid().ToString("N");
        try
        {
            var before=Observe();Record("BEFORE_TERMINATE",before,attempt);
            AssertHeld();if(!TerminateJobObject(handle,125))throw Error("TerminateExactOwnedJob");
            var clock=Stopwatch.StartNew();JobSnapshot latest;
            do
            {
                latest=Observe();
                if(latest.ObservedZero){Record("JOB_MEMBERS_ZERO_OBSERVED",latest,attempt);return latest;}
                Thread.Sleep(20);
            }while(clock.ElapsedMilliseconds<5000);
            Record("JOB_MEMBERS_ZERO_TIMEOUT",latest,attempt);throw new TimeoutException("Owned job members were not observed zero within the bounded wait");
        }
        catch(Exception ex)
        {
            try{state.WriteNew("job-failure-"+intent.JobId+"-"+attempt+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,InstallationId=state.InstallationId,intent.JobId,
                Status="STOP_NOT_CONFIRMED",FailureType=ex.GetType().Name,FailureCode=ex is Win32Exception native?native.NativeErrorCode:ex.HResult,AtUtc=DateTime.UtcNow.ToString("o")}));}
            catch(Exception log){throw new AggregateException("Job stop and failure recording both failed",ex,log);}throw;
        }
    }
    private void Record(string status,JobSnapshot snapshot,string? attempt=null)
    {state.WriteNew("job-observed-"+intent.JobId+"-"+(attempt??Guid.NewGuid().ToString("N"))+"-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {
        SchemaVersion=1,InstallationId=state.InstallationId,intent.JobId,Status=status,Snapshot=snapshot,Scope="JOB_MEMBERS_ONLY",AdmissionOrNetworkQualified=false
    }));}
}
