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
    internal static bool RunRestricted(ResourceProbePlan resource,string workspace,string actor)
    {
        if(actor is not ("root" or "probe") || !resource.DevelopProject || resource.HostPrivacySHA256 is null)throw WfpNative.Contract("ExplicitHostPrivacyTaskRequired");
        var actual=AtomicChild.AssertRestrictedToolSelf();using var package=InstallationPackageSid.FromInstallationId(resource.InstallationId);
        if(actual!=package.Value || !string.Equals(Environment.ProcessPath,resource.ExpectedChildImage,StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFullPath(Environment.CurrentDirectory),workspace,StringComparison.OrdinalIgnoreCase))throw WfpNative.Contract("HostPrivacyRestrictedActorRequired");
        // Share the original owner's existing read/write/delete handle; the
        // probe itself opens for read only and closes before signalling ready.
        using var file=new FileStream(PlanPath(workspace),FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);
        if(file.Length is <1 or >16384)throw WfpNative.Contract("HostPrivacyPlanBounds");
        var bytes=new byte[(int)file.Length];file.ReadExactly(bytes);
        if(WorkspaceBundle.Hash(bytes)!=resource.HostPrivacySHA256)throw WfpNative.Contract("HostPrivacyPlanDigestDiffers");
        using var doc=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=4});var root=doc.RootElement;
        HostPrivacyContract.Fields(root,"SchemaVersion","SessionId","InstallationId","Release","Targets");
        foreach(var t in root.GetProperty("Targets").EnumerateArray())HostPrivacyContract.Fields(t,"Role","Kind","Path","Pid","OwnerObservedAbsent");
        var plan=JsonSerializer.Deserialize<RestrictedPlan>(bytes)??throw WfpNative.Contract("HostPrivacyPlanMissing");
        if(plan.SchemaVersion!=4 || plan.SessionId!=resource.Nonce || plan.InstallationId!=resource.InstallationId || plan.Release!=resource.Release || plan.Targets?.Length!=HostPrivacyContract.Checks.Count)
            throw WfpNative.Contract("HostPrivacyPlanContextDiffers");
        var observations=plan.Targets.Select((target,i)=>
        {
            var check=HostPrivacyContract.Checks[i];
            if(target is null || target.Role!=check.Role || target.Kind!=check.Kind ||
                target.OwnerObservedAbsent && !check.AllowsOwnerObservedAbsence)
                throw WfpNative.Contract("HostPrivacyTargetContractDiffers");
            int error;
            switch(check.TargetKind)
            {
                case HostPrivacyTargetKind.HostFile:
                case HostPrivacyTargetKind.MachineRegistry:
                case HostPrivacyTargetKind.UserRegistry:
                    if(target.Path is not {Length:>=1 and <=1024} || target.Path.Contains('\0') || target.Pid!=0)
                        throw WfpNative.Contract("HostPrivacyTargetContractDiffers");
                    error=check.TargetKind==HostPrivacyTargetKind.HostFile?FileAccessOpen(target.Path,check.Access):RegistryReadOpen(check,target.Path);
                    break;
                case HostPrivacyTargetKind.HostProcess:
                    if(target.Path!="" || target.Pid<=0)throw WfpNative.Contract("HostPrivacyTargetContractDiffers");
                    error=ProcessAccessOpen(target.Pid,check);
                    break;
                case HostPrivacyTargetKind.OwnerProcess:
                    RequireOwnerTarget(target.Path,target.Pid,resource.BrokerPid);
                    error=ProcessAccessOpen(target.Pid,check);
                    break;
                case HostPrivacyTargetKind.ControlFile:
                    RequireControlFileTarget(target.Path,target.Pid,resource.ProgramFilesRoot,resource.Release,check);
                    error=FileAccessOpen(target.Path,check.Access);
                    break;
                default: throw WfpNative.Contract("HostPrivacyTargetContractDiffers");
            }
            return check.Observe(error,target.OwnerObservedAbsent);
        }).ToArray();
        var report=new HostPrivacyObservation(1,resource.Nonce,resource.HostPrivacySHA256,Environment.ProcessId,observations);
        var data=JsonSerializer.SerializeToUtf8Bytes(report);
        using(var output=new FileStream(ReportPath(workspace,actor),FileMode.CreateNew,FileAccess.Write,FileShare.None)){output.Write(data);output.Flush(true);}
        return HostPrivacyContract.CasesSatisfied(observations,plan.Targets.Any(target=>target.OwnerObservedAbsent));
    }
    private static string PlanPath(string workspace)=>WindowsPathSeal.Child(workspace,"host-privacy-plan.json");
    // The compiler never opens/deserializes the private target plan. These
    // are fixed public installation paths and held owner/root process IDs.


    private static string ReportPath(string workspace,string actor)=>WindowsPathSeal.Child(workspace,"host-privacy-"+actor+".json");
    // OPEN_EXISTING and one minimal access right. Close even an
    // unexpectedly granted handle without using the requested right.
    private static int FileAccessOpen(string path,uint access)
    {
        using var handle=CreateFile(path,access,7,IntPtr.Zero,3,0x40200000,IntPtr.Zero);
        return handle.IsInvalid?Marshal.GetLastWin32Error():0;
    }
    private static int RegistryReadOpen(HostPrivacyCheck check,string path)
    {
        var hive=check.TargetKind switch {
            HostPrivacyTargetKind.MachineRegistry=>unchecked((int)0x80000002),
            HostPrivacyTargetKind.UserRegistry=>unchecked((int)0x80000003),
            _=>throw WfpNative.Contract("HostPrivacyRegistryTargetDiffers")
        };
        var error=RegOpenKeyEx(new IntPtr(hive),path,0,check.Access,out var key);key?.Dispose();return error;
    }
    private static void PositiveRegistry(HostPrivacyCheck check,string path)
    {var error=RegistryReadOpen(check,path);if(error!=0)throw new Win32Exception(error,"Host privacy key positive control");}
    private static int ProcessAccessOpen(int pid,HostPrivacyCheck check)
    {
        if(pid<=0 || check.TargetKind is not (HostPrivacyTargetKind.HostProcess or HostPrivacyTargetKind.OwnerProcess or HostPrivacyTargetKind.RootProcess))
            throw WfpNative.Contract("HostPrivacyProcessRequired");
        using var handle=OpenProcess(check.Access,false,checked((uint)pid));
        return handle.IsInvalid?Marshal.GetLastWin32Error():0;
    }
    private static void RequireOwnerTarget(string path,int pid,int ownerPid)
    {
        if(path!="" || ownerPid<=0 || pid!=ownerPid)throw WfpNative.Contract("ProtectionOwnerTargetBindingDiffers");
    }
    private static bool ProcessAlive(SafeProcessHandle process)=>WaitForSingleObject(process,0)==258;
}
