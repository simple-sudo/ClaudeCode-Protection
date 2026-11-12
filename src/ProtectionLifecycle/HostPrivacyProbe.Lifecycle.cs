using System.ComponentModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal sealed partial class HostPrivacyProbe
{
    internal void Publish(string workspace)
    {
        var path=PlanPath(workspace);
        if(published is not null || withdrawn)throw WfpNative.Contract("HostPrivacyPlanAlreadyPublished");
        published=new FileStream(WindowsPathSeal.CreateWithdrawableProbeFile(path),FileAccess.ReadWrite);
        published.Write(bytes);published.Flush(true);
        if(WorkspaceBundle.Hash(publishedBytes())!=SHA256)throw WfpNative.Contract("HostPrivacyPublishedPlanDiffers");
    }
    private byte[] publishedBytes(){published!.Position=0;var bytes=new byte[checked((int)published.Length)];published.ReadExactly(bytes);published.Position=0;return bytes;}
    internal void AssertHeld()
    {
        if(!withdrawn && published?.SafeFileHandle.IsClosed!=false)throw WfpNative.Contract("HostPrivacyPlanLeaseLost");
        foreach(var handle in processes)
            if(handle.IsClosed || !ProcessAlive(handle))throw WfpNative.Contract("HostPrivacyTargetProcessExited");
        foreach(var handle in controlFiles)if(handle.IsClosed || handle.IsInvalid)throw WfpNative.Contract("ProtectionControlFileLeaseLost");
    }
    private void AssertTargetsCurrent()
    {
        foreach(var target in plan.Targets)
            switch(target.Check.TargetKind)
            {
                case HostPrivacyTargetKind.HostFile: AssertFileStateCurrent(target);break;
                case HostPrivacyTargetKind.ControlFile:
                    if(FileIdentity(target.Path)!=target.Identity)throw WfpNative.Contract("ProtectionControlFileIdentityChanged");
                    break;
                case HostPrivacyTargetKind.MachineRegistry:
                case HostPrivacyTargetKind.UserRegistry: PositiveRegistry(target.Check,target.Path);break;
            }
        foreach(var handle in processes)if(!ProcessAlive(handle))throw WfpNative.Contract("HostPrivacyTargetProcessExited");
    }
    private HostPrivacyObservation ReadObservation(string workspace,string actor,int expectedPid)
    {
        AssertHeld();
        using var file=new FileStream(WindowsPathSeal.Open(ReportPath(workspace,actor),false,true),FileAccess.Read);
        if(file.Length is <1 or >16384)throw WfpNative.Contract("HostPrivacyReportBounds");
        var bytes=new byte[(int)file.Length];file.ReadExactly(bytes);using var json=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=4});
        var r=json.RootElement;
        if(actor=="project")
            HostPrivacyContract.Fields(r,"SchemaVersion","SessionId","PlanSHA256","Pid","Cases","HostReads");
        else
            HostPrivacyContract.Fields(r,"SchemaVersion","SessionId","PlanSHA256","Pid","Cases");
        foreach(var c in r.GetProperty("Cases").EnumerateArray())HostPrivacyContract.Fields(c,"Role","Kind","Status","Error");
        var result=JsonSerializer.Deserialize<HostPrivacyObservation>(bytes)??throw WfpNative.Contract("HostPrivacyReportMissing");
        if(result.SchemaVersion!=1 || result.SessionId!=plan.SessionId || result.PlanSHA256!=SHA256 || result.Pid!=expectedPid)
            throw WfpNative.Contract("HostPrivacyActorBindingDiffers");
        if(actor=="project")
        {
            HostPrivacyContract.ValidateCompilerCases(result.Cases);
            var host=r.GetProperty("HostReads");
            HostPrivacyContract.Fields(host,"Adapters","Tcp4Size","Tcp6Size","Udp4Size","Udp6Size","SmbiosSize");
            var reads=new CompilerHostReads(host.GetProperty("Adapters").GetInt32(),
                host.GetProperty("Tcp4Size").GetUInt32(),host.GetProperty("Tcp6Size").GetUInt32(),
                host.GetProperty("Udp4Size").GetUInt32(),host.GetProperty("Udp6Size").GetUInt32(),
                host.GetProperty("SmbiosSize").GetInt32());
            if(!reads.Denied)throw WfpNative.Contract("CompilerHostReadsNotDenied");
        }
        else HostPrivacyContract.ValidateCases(result.Cases);
        return result;
    }
    internal bool ExecutionReleased=>execution.ExecutionReleased;
    internal void SealRootBeforeGit(string workspace,int rootPid)
    {AssertResetTargetCurrent();execution.SealRoot(ReadObservation(workspace,"root",rootPid),rootPid);}
    internal bool ProbeSealed=>execution.ProbeSealed;
    internal void AuthorizeProbeCreation()=>execution.AuthorizeProbeCreation();
    internal void SealProbeBeforeExit(string workspace,int pid)
    {
        AssertTargetsCurrent();
        if(probeProcess is not null)throw WfpNative.Contract("HostPrivacyProbeAlreadyHeld");
        var handle=OpenProcess(0x101000,false,checked((uint)pid));
        if(handle.IsInvalid || !ProcessAlive(handle)){handle.Dispose();throw WfpNative.Contract("HostPrivacyProbeNotLive");}
        try
        {
            // Capture the complete observation while this exact actor is held.
            // A negative observation is diagnostic only. The gate still refuses it.
            probeObservation=ReadObservation(workspace,"probe",pid);
            execution.SealProbe(probeObservation,pid);probeProcess=handle;
        }
        catch{handle.Dispose();throw;}
    }
    internal void AuthorizeToolCreation(string workspace)
    {
        AssertHeld();
        if(!execution.ProbeSealed)throw WfpNative.Contract("HostPrivacyProbeExitZeroRequired");
        RequireExitedProbe(probeProcess);
        WithdrawPlan(workspace);
        AssertTargetsCurrent();execution.AuthorizeToolCreation();
    }
    internal void SealToolBeforeExecution(string workspace,int toolPid)
    {
        AssertResetTargetCurrent();
        compilerObservation=ReadObservation(workspace,"project",toolPid);
        execution.SealTool(compilerObservation,toolPid);
    }
    internal void ReleaseExecution(string workspace,Action assertCurrentOwner)
    {
        AssertHeld();
        if(!withdrawn)throw WfpNative.Contract("HostPrivacyPlanMustBeWithdrawnBeforeCompiler");
        AssertPlanAbsent(workspace);AssertTargetsCurrent();assertCurrentOwner();execution.ReleaseExecution();
    }
    private void WithdrawPlan(string workspace)
    {
        var file=published??throw WfpNative.Contract("HostPrivacyPlanLeaseLost");
        WithdrawPlanFile(file,workspace);published=null;withdrawn=true;
    }
    internal static void RequireExitedProbe(SafeProcessHandle? process)
    {
        if(process is null || process.IsInvalid || process.IsClosed || WaitForSingleObject(process,0)!=0 ||
            !GetExitCodeProcess(process,out var exit) || exit!=0)throw WfpNative.Contract("HostPrivacyProbeExitZeroRequired");
    }
    internal static void WithdrawPlanFile(FileStream file,string workspace)
    {
        if(file.SafeFileHandle.IsClosed || file.SafeFileHandle.IsInvalid)throw WfpNative.Contract("HostPrivacyPlanLeaseLost");
        var path=PlanPath(workspace);
        WindowsPathSeal.VerifyObject(file.SafeFileHandle,path,false);
        WindowsPathSeal.MarkDelete(file.SafeFileHandle);
        file.Dispose();AssertPlanAbsent(workspace);
    }
    internal static void AssertPlanAbsent(string workspace)
    {
        var path=PlanPath(workspace);
        try
        {
            using var remaining=WindowsPathSeal.Open(path,false,false);
            throw WfpNative.Contract("HostPrivacyPlanStillPresent");
        }
        catch(ExactPathAbsentException ex)when(ex.NativeErrorCode==2 && string.Equals(ex.FailedPath,path,StringComparison.OrdinalIgnoreCase))
        {}
    }
    private void AssertResetTargetCurrent()=>AssertFileStateCurrent(plan.Targets.Single(target=>target.Check.AllowsOwnerObservedAbsence));
    internal void AssertGitCreationAllowed()
    {if(execution.ToolCreationAuthorized)throw WfpNative.Contract("ProjectGitCreationPhaseAlreadyClosed");}
    internal HostPrivacySummary ReadClosed(string workspace,int rootPid,int? toolPid)
    {
        AssertHeld();AssertTargetsCurrent();
        // Once code could have run, never reopen a child-writable observation.
        // A failed pre-code task may still expose its honest bounded diagnosis.
        if(execution.ExecutionReleased)
            return execution.Snapshot(rootPid,toolPid??throw WfpNative.Contract("SealedProjectToolPidMissing"));
        var root=ReadObservation(workspace,"root",rootPid);var tool=compilerObservation;
        if(tool is not null && tool.Pid!=toolPid)throw WfpNative.Contract("HostPrivacyActorBindingDiffers");
        var probe=probeObservation;
        var summary=new HostPrivacySummary(HostPrivacyContract.PolicySHA256,SHA256,plan.SessionId,rootPid,tool?.Pid,root.Cases,tool?.Cases??Array.Empty<HostPrivacyCase>())
            {ProbePid=probe?.Pid,ProbeCases=probe?.Cases??Array.Empty<HostPrivacyCase>()};
        HostPrivacyContract.Validate(summary,plan.SessionId,false);return summary;
    }
}
