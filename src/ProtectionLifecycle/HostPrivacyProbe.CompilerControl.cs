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
    internal static bool RunCompilerControl(ResourceProbePlan resource,string workspace,int rootPid)
    {
        resource.Validate();
        if(!resource.DevelopProject || resource.HostPrivacySHA256 is null || rootPid<=0 || rootPid==Environment.ProcessId || rootPid==resource.BrokerPid)
            throw WfpNative.Contract("CompilerRootBindingRequired");
        AssertPlanAbsent(workspace);
        var observations=HostPrivacyContract.CompilerChecks.Select(check=>check.Observe(check.TargetKind switch {
            HostPrivacyTargetKind.ControlFile=>FileAccessOpen(ControlFilePath(resource.ProgramFilesRoot,resource.Release,check),check.Access),
            HostPrivacyTargetKind.OwnerProcess=>ProcessAccessOpen(resource.BrokerPid,check),
            HostPrivacyTargetKind.RootProcess=>ProcessAccessOpen(rootPid,check),
            _=>throw WfpNative.Contract("CompilerPrivacyTargetDiffers")
        })).ToArray();
        HostPrivacyContract.ValidateCompilerCases(observations);
        var report=new HostPrivacyObservation(1,resource.Nonce,resource.HostPrivacySHA256,Environment.ProcessId,observations);
        // Any result other than explicit access denied refuses execution. A
        // Sizing response alone does not establish content exposure.
        var host=new CompilerHostReads(ObserveAdapterRead(),
            ProxyChannelLease.QueryTcpOwnerTableSize(false,out _),ProxyChannelLease.QueryTcpOwnerTableSize(true,out _),
            QueryUdpOwnerTableSize(false,out _),QueryUdpOwnerTableSize(true,out _),QuerySmbiosSize(out _));
        using(var output=new FileStream(ReportPath(workspace,"project"),FileMode.CreateNew,FileAccess.Write,FileShare.None))
        {
            JsonSerializer.Serialize(output,new {report.SchemaVersion,report.SessionId,report.PlanSHA256,report.Pid,report.Cases,HostReads=host});
            output.Flush(true);
        }
        return host.Denied && observations.All(c=>c.Status=="ACCESS_DENIED" && c.Error==5);
    }
    private static int ObserveAdapterRead()
    {
        try{_=NetworkInterface.GetAllNetworkInterfaces();return 0;}
        catch(NetworkInformationException error){return error.NativeErrorCode;}
    }
    private static uint QueryUdpOwnerTableSize(bool ipv6,out uint size)
    {
        size=0;
        return GetExtendedUdpTable(IntPtr.Zero,ref size,false,ipv6?23u:2u,1,0);
    }
    private static int QuerySmbiosSize(out uint size)
    {
        const uint rawSmbios=0x52534D42; // RSMB
        size=GetSystemFirmwareTable(rawSmbios,0,IntPtr.Zero,0);
        return size!=0?0:Marshal.GetLastWin32Error();
    }
}
