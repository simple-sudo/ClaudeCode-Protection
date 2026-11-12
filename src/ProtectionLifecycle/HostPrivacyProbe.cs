using System.ComponentModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

internal sealed partial class HostPrivacyProbe : IDisposable
{
    private sealed record Target(HostPrivacyCheck Check,string Path,int Pid,string? Identity,int MissingParentDepth=0);
    private sealed record Plan(string SessionId,string InstallationId,string Release,Target[] Targets);
    private sealed record RestrictedTarget(string Role,string Kind,string Path,int Pid,bool OwnerObservedAbsent);
    private sealed record RestrictedPlan(int SchemaVersion,string SessionId,string InstallationId,string Release,RestrictedTarget[] Targets);
    private sealed record CompilerHostReads(int Adapters,uint Tcp4Size,uint Tcp6Size,uint Udp4Size,uint Udp6Size,int SmbiosSize)
    {
        internal bool Denied=>Adapters==5 && Tcp4Size==5 && Tcp6Size==5 && Udp4Size==5 && Udp6Size==5 && SmbiosSize==5;
    }
    private readonly Plan plan;
    private readonly List<SafeProcessHandle> processes;
    private readonly HostPrivacyExecutionGate execution;
    private FileStream? published;
    private SafeProcessHandle? probeProcess;
    private HostPrivacyObservation? probeObservation,compilerObservation;
    private bool withdrawn;
    private readonly List<SafeFileHandle> controlFiles=new();
    private readonly byte[] bytes;
    internal string SHA256=>WorkspaceBundle.Hash(bytes);
    private HostPrivacyProbe(Plan plan,List<SafeProcessHandle> processes)
    {
        this.plan=plan;this.processes=processes;
        // Object IDs and absence anchors are positive-control data. Only the
        // trusted owner needs them; the fixed probe requests one minimal open.
        var targets=plan.Targets.Select(target=>new RestrictedTarget(target.Check.Role,target.Check.Kind,
            target.Check.TargetKind==HostPrivacyTargetKind.HostProcess?"":target.Path,target.Pid,target.MissingParentDepth!=0)).ToArray();
        bytes=JsonSerializer.SerializeToUtf8Bytes(new RestrictedPlan(3,plan.SessionId,plan.InstallationId,plan.Release,targets));
        if(bytes.Length>16384)throw WfpNative.Contract("HostPrivacyPlanBounds");
        execution=new(plan.SessionId,SHA256,plan.Targets.Single(target=>target.Check.AllowsOwnerObservedAbsence).MissingParentDepth!=0);
    }
    internal static HostPrivacyProbe Capture(string session,string installation,string release)
    {
        // Confirm the same APIs are available to the owner. Except for
        // adapter enumeration, the gate queries only required buffer sizes.
        if(NetworkInterface.GetAllNetworkInterfaces().Length==0 ||
            ProxyChannelLease.QueryTcpOwnerTableSize(false,out var size4)!=122 || size4<4 ||
            ProxyChannelLease.QueryTcpOwnerTableSize(true,out var size6)!=122 || size6<4 ||
            QueryUdpOwnerTableSize(false,out var udp4)!=122 || udp4<4 ||
            QueryUdpOwnerTableSize(true,out var udp6)!=122 || udp6<4)
            throw WfpNative.Contract("HostNetworkReadPositiveControlMissing");
        if(QuerySmbiosSize(out var firmwareSize)!=0 || firmwareSize<8)
            throw WfpNative.Contract("HostSmbiosReadPositiveControlMissing");
        using var human=WindowsIdentity.GetCurrent();var sid=human.User?.Value??throw WfpNative.Contract("HostPrivacyHumanMissing");
        var profile=Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var roaming=Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var local=Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var common=Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        string HostPath(HostPrivacyTarget target)=>target switch {
            HostPrivacyTarget.FlClashJson=>Path.Combine(roaming,"com.follow","clash","config.json"),
            HostPrivacyTarget.FlClashYaml=>Path.Combine(roaming,"com.follow","clash","config.yaml"),
            HostPrivacyTarget.FlClashPreferences=>Path.Combine(roaming,"com.follow","clash","shared_preferences.json"),
            HostPrivacyTarget.UuUserSettings=>Path.Combine(local,"GameViewer","setting.ini"),
            HostPrivacyTarget.UuUserConfigures=>Path.Combine(local,"GameViewer","configures_info.ini"),
            HostPrivacyTarget.UuSystemUser=>Path.Combine(common,"Netease","GameViewer","user_info.ini"),
            HostPrivacyTarget.UuSystemAssist=>Path.Combine(common,"Netease","GameViewer","remote_assist_code.ini"),
            HostPrivacyTarget.ClaudeSettings=>Path.Combine(profile,".claude","settings.json"),
            HostPrivacyTarget.GitConfig=>Path.Combine(profile,".gitconfig"),
            HostPrivacyTarget.MachineRegistry=>@"SOFTWARE\Microsoft\Cryptography",
            HostPrivacyTarget.UserRegistry=>sid+@"\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            HostPrivacyTarget.FlClashUi=>@"E:\program\FlClash\FlClash.exe",
            HostPrivacyTarget.FlClashCore=>@"E:\program\FlClash\FlClashCore.exe",
            HostPrivacyTarget.UuService=>@"E:\program\uu\GameViewer\GameViewerService.exe",
            _=>throw WfpNative.Contract("HostPrivacyFixedPathRequired")
        };
        var held=new List<SafeProcessHandle>();
        try
        {
            var targets=HostPrivacyContract.Checks.Where(check=>check.TargetKind is HostPrivacyTargetKind.HostFile or
                HostPrivacyTargetKind.MachineRegistry or HostPrivacyTargetKind.UserRegistry or HostPrivacyTargetKind.HostProcess).Select(check=>
            {
                var path=HostPath(check.Target);
                var pid=0;string? identity=null;var missingParentDepth=0;
                if(check.TargetKind==HostPrivacyTargetKind.HostFile)
                {
                    path=WindowsPathSeal.Canonical(path);
                    var observed=ObserveFileState(path,check.AllowsOwnerObservedAbsence);
                    identity=observed.Identity;missingParentDepth=observed.MissingParentDepth;
                }
                else if(check.TargetKind is HostPrivacyTargetKind.MachineRegistry or HostPrivacyTargetKind.UserRegistry)
                    PositiveRegistry(check,path);
                else
                {
                    var candidates=Process.GetProcessesByName(Path.GetFileNameWithoutExtension(path));
                    try
                    {
                        if(candidates.Length!=1)throw WfpNative.Contract("HostPrivacyExactProcessRequired");
                        // Query plus read-only wait. Exit code259 alone is not
                        // liveness: it can also be an application's exit code.
                        pid=candidates[0].Id;var handle=OpenProcess(0x101000,false,checked((uint)pid));
                        if(handle.IsInvalid){handle.Dispose();throw new Win32Exception(Marshal.GetLastWin32Error(),"Host privacy process metadata");}
                        held.Add(handle);var image=new StringBuilder(32768);var length=image.Capacity;
                        if(!QueryFullProcessImageName(handle,0,image,ref length) || !string.Equals(image.ToString(),path,StringComparison.OrdinalIgnoreCase))
                            throw WfpNative.Contract("HostPrivacyProcessImageDiffers");
                    }
                    finally{foreach(var process in candidates)process.Dispose();}
                }
                return new Target(check,path,pid,identity,missingParentDepth);
            }).ToList();
            // The original installed owner selects ONLY itself, never a
            // caller PID or a process-name discovery. Keep an independent
            // query/wait handle alive through both actors and result release.
            var owner=OpenProcess(0x101000,false,checked((uint)Environment.ProcessId));
            if(owner.IsInvalid){owner.Dispose();throw new Win32Exception(Marshal.GetLastWin32Error(),"Protection owner metadata");}
            held.Add(owner);
            foreach(var check in HostPrivacyContract.Checks.Where(check=>check.TargetKind==HostPrivacyTargetKind.OwnerProcess))
            {
                var error=ProcessAccessOpen(Environment.ProcessId,check);
                if(error!=0)throw new Win32Exception(error,"Protection owner maintenance positive control");
                targets.Add(new(check,"",Environment.ProcessId,null));
            }
            var controls=CaptureControlFiles(release);
            try
            {
                targets.AddRange(controls.Targets);
                var byCheck=targets.ToDictionary(target=>target.Check);
                var ordered=HostPrivacyContract.Checks.Select(check=>byCheck[check]).ToArray();
                var result=new HostPrivacyProbe(new(Identifiers.Hex32(session),Identifiers.Hex32(installation),Identifiers.Hex32(release),ordered),held);
                result.controlFiles.AddRange(controls.Handles);result.AssertTargetsCurrent();return result;
            }
            catch{foreach(var file in controls.Handles)file.Dispose();throw;}
        }
        catch{foreach(var handle in held)handle.Dispose();throw;}
    }

    public void Dispose(){published?.Dispose();probeProcess?.Dispose();foreach(var handle in controlFiles)handle.Dispose();foreach(var handle in processes)handle.Dispose();}
}
