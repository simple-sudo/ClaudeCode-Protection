using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

public static partial class InstalledBroker
{
    // Only the peer PID/nonce of the currently connected installed daily UI.
    // No payload, target, command, token, output path or child PID is accepted.
    public static int QualifyHostGpuReferencePipe(int callerPid,string nonce)
    {
        MaintenanceIdentity.RequireCurrentAdministrator();_=Identifiers.Hex32(nonce);
        using var channel=new NamedPipeClientStream(".",WorkspacePipe.HostGpuName(callerPid,nonce),PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification);
        channel.Connect(15000);WorkspacePipe.AssertPeer(channel,callerPid,false);
        GpuHostReferenceResult? result=null;var failures=new List<WfpErrorEvidence>();var code=125;
        var closed=false;
        try
        {
            var run=WithCurrentInstallation((layout,state,version)=>
            {
                using var caller=GpuReferenceCaller.Open(channel,callerPid,layout.Version(version.Package.Release));
                var fences=new List<PersistentFence>();
                try
                {
                    foreach(var plan in FencePlan.ReadAll(state))fences.Add(PersistentFence.OpenExisting(state,plan.Data.FenceId));
                    result=GpuHostReferenceQualification.RunBound(state,version,layout,fences,caller);
                    if(result.JobId is not null)
                    {
                        var intent=OwnedJobIntent.Read(state,result.JobId);
                        closed=AtomicJobCompletion.ReadClosed(state,intent) is not null;
                    }
                    return(result.Complete?0:3,"");
                }
                finally{foreach(var fence in fences)fence.Dispose();}
            });
            code=run.ExitCode;
        }
        catch(Exception error){failures.AddRange(WfpNative.Describe(error));}
        if(result is not null)failures.AddRange(result.Failures);
        // Closure is independently reread from this invocation's original
        // completion, including the empty-Job startup-failure case. It grants
        // neither computation success nor a reusable admission.
        if(result?.Complete==true && (!closed || failures.Count!=0))code=3;
        var complete=result?.Complete==true && closed && failures.Count==0;
        var reply=new HostGpuReferenceReply(1,nonce,complete?HostGpuReferenceReply.Passed:HostGpuReferenceReply.Failed,code,result?.RequestId,
            result?.ChildPid,complete,closed,failures.Take(32).Select(f=>f.Code).ToArray(),false,false,false);
        var bytes=JsonSerializer.SerializeToUtf8Bytes(reply);_=HostGpuReferenceReply.Parse(bytes,nonce);
        WorkspacePipe.AssertPeer(channel,callerPid,false);
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));WorkspacePipe.Write(channel,bytes,4096,timeout.Token).GetAwaiter().GetResult();
        return code;
    }
}
