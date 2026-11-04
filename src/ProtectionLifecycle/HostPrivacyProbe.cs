using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

// Original owner's fixed resource catalogue. No caller-selected host path,
// secret bytes/value reads, permission changes, process-memory reads or stop.
internal sealed partial class HostPrivacyProbe : IDisposable
{
    private sealed record Target(string Role,string Kind,string Path,int Pid,string? Identity,int MissingParentDepth=0);
    private sealed record Plan(string SessionId,string InstallationId,string Release,Target[] Targets);
    private sealed record RestrictedTarget(string Role,string Kind,string Path,int Pid,bool OwnerObservedAbsent);
    private sealed record RestrictedPlan(int SchemaVersion,string SessionId,string InstallationId,string Release,RestrictedTarget[] Targets);
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
        var targets=plan.Targets.Select((target,index)=>new RestrictedTarget(target.Role,target.Kind,
            index is >=11 and <HostPrivacyContract.HostResourceCount?"":target.Path,target.Pid,target.MissingParentDepth!=0)).ToArray();
        bytes=JsonSerializer.SerializeToUtf8Bytes(new RestrictedPlan(3,plan.SessionId,plan.InstallationId,plan.Release,targets));
        if(bytes.Length>16384)throw WfpNative.Contract("HostPrivacyPlanBounds");
        execution=new(plan.SessionId,SHA256,plan.Targets[HostPrivacyContract.ResetSettingsIndex].MissingParentDepth!=0);
    }
    internal static HostPrivacyProbe Capture(string session,string installation,string release)
    {
        using var human=WindowsIdentity.GetCurrent();var sid=human.User?.Value??throw WfpNative.Contract("HostPrivacyHumanMissing");
        var profile=Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var roaming=Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var local=Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var common=Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var paths=new[]{Path.Combine(roaming,"com.follow","clash","config.json"),Path.Combine(roaming,"com.follow","clash","config.yaml"),
            Path.Combine(roaming,"com.follow","clash","shared_preferences.json"),Path.Combine(local,"GameViewer","setting.ini"),
            Path.Combine(local,"GameViewer","configures_info.ini"),Path.Combine(common,"Netease","GameViewer","user_info.ini"),
            Path.Combine(common,"Netease","GameViewer","remote_assist_code.ini"),Path.Combine(profile,".claude","settings.json"),Path.Combine(profile,".gitconfig"),
            @"SOFTWARE\Microsoft\Cryptography",sid+@"\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            @"E:\program\FlClash\FlClash.exe",@"E:\program\FlClash\FlClashCore.exe",@"E:\program\uu\GameViewer\GameViewerService.exe"};
        var held=new List<SafeProcessHandle>();
        try
        {
            var targets=paths.Select((path,i)=>
            {
                var pid=0;string? identity=null;var missingParentDepth=0;
                if(i<9){path=WindowsPathSeal.Canonical(path);var observed=ObserveFileState(path,i==HostPrivacyContract.ResetSettingsIndex);identity=observed.Identity;missingParentDepth=observed.MissingParentDepth;}
                else if(i<11)PositiveRegistry(i==9,path);
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
                return new Target(HostPrivacyContract.Roles[i],HostPrivacyContract.Kind(i),path,pid,identity,missingParentDepth);
            }).ToList();
            // The original installed owner selects ONLY itself, never a
            // caller PID or a process-name discovery. Keep an independent
            // query/wait handle alive through both actors and result release.
            var owner=OpenProcess(0x101000,false,checked((uint)Environment.ProcessId));
            if(owner.IsInvalid){owner.Dispose();throw new Win32Exception(Marshal.GetLastWin32Error(),"Protection owner metadata");}
            held.Add(owner);
            for(var i=HostPrivacyContract.HostResourceCount;i<HostPrivacyContract.OwnerProcessEnd;i++)
            {
                var error=OwnerAccessOpen(Environment.ProcessId,i);
                if(error!=0)throw new Win32Exception(error,"Protection owner maintenance positive control");
                targets.Add(new(HostPrivacyContract.Roles[i],HostPrivacyContract.Kind(i),"",Environment.ProcessId,null));
            }
            var controls=CaptureControlFiles(release);
            try
            {
                targets.AddRange(controls.Targets);
                var result=new HostPrivacyProbe(new(Identifiers.Hex32(session),Identifiers.Hex32(installation),Identifiers.Hex32(release),targets.ToArray()),held);
                result.controlFiles.AddRange(controls.Handles);result.AssertTargetsCurrent();return result;
            }
            catch{foreach(var file in controls.Handles)file.Dispose();throw;}
        }
        catch{foreach(var handle in held)handle.Dispose();throw;}
    }
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
        for(var i=0;i<9;i++)AssertFileStateCurrent(plan.Targets[i],i);
        for(var i=HostPrivacyContract.ControlFileStart;i<plan.Targets.Length;i++)
            if(FileIdentity(plan.Targets[i].Path)!=plan.Targets[i].Identity)throw WfpNative.Contract("ProtectionControlFileIdentityChanged");
        PositiveRegistry(true,plan.Targets[9].Path);PositiveRegistry(false,plan.Targets[10].Path);
        foreach(var handle in processes)if(!ProcessAlive(handle))throw WfpNative.Contract("HostPrivacyTargetProcessExited");
    }
    private HostPrivacyObservation ReadObservation(string workspace,string actor,int expectedPid)
    {
        AssertHeld();
        using var file=new FileStream(WindowsPathSeal.Open(ReportPath(workspace,actor),false,true),FileAccess.Read);
        if(file.Length is <1 or >16384)throw WfpNative.Contract("HostPrivacyReportBounds");
        var bytes=new byte[(int)file.Length];file.ReadExactly(bytes);using var json=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=4});
        var r=json.RootElement;HostPrivacyContract.Fields(r,"SchemaVersion","SessionId","PlanSHA256","Pid","Cases");
        foreach(var c in r.GetProperty("Cases").EnumerateArray())HostPrivacyContract.Fields(c,"Role","Kind","Status","Error");
        var result=JsonSerializer.Deserialize<HostPrivacyObservation>(bytes)??throw WfpNative.Contract("HostPrivacyReportMissing");
        if(result.SchemaVersion!=1 || result.SessionId!=plan.SessionId || result.PlanSHA256!=SHA256 || result.Pid!=expectedPid)
            throw WfpNative.Contract("HostPrivacyActorBindingDiffers");
        if(actor=="project")HostPrivacyContract.ValidateCompilerCases(result.Cases);else HostPrivacyContract.ValidateCases(result.Cases);
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
    private void AssertResetTargetCurrent()=>AssertFileStateCurrent(plan.Targets[HostPrivacyContract.ResetSettingsIndex],HostPrivacyContract.ResetSettingsIndex);
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
        if(plan.SchemaVersion!=3 || plan.SessionId!=resource.Nonce || plan.InstallationId!=resource.InstallationId || plan.Release!=resource.Release || plan.Targets?.Length!=HostPrivacyContract.Roles.Length)
            throw WfpNative.Contract("HostPrivacyPlanContextDiffers");
        var observations=plan.Targets.Select((target,i)=>
        {
            if(target.Role!=HostPrivacyContract.Roles[i] || target.Kind!=HostPrivacyContract.Kind(i) ||
                target.OwnerObservedAbsent && i!=HostPrivacyContract.ResetSettingsIndex ||
                i<11 && (target.Path is not {Length:>=1 and <=1024} || target.Path.Contains('\0') || target.Pid!=0) ||
                i is >=11 and <HostPrivacyContract.HostResourceCount && (target.Path!="" || target.Pid<=0))
                throw WfpNative.Contract("HostPrivacyTargetContractDiffers");
            if(i>=HostPrivacyContract.ControlFileStart)RequireControlFileTarget(target.Path,target.Pid,resource.ProgramFilesRoot,resource.Release,i);
            else if(i>=HostPrivacyContract.HostResourceCount)RequireOwnerTarget(target.Path,target.Pid,resource.BrokerPid,i);
            var error=i>=HostPrivacyContract.ControlFileStart?ControlFileOpen(target.Path,i):i>=HostPrivacyContract.HostResourceCount?OwnerAccessOpen(target.Pid,i):
                i<9?FileReadOpen(target.Path):i<11?RegistryReadOpen(i==9,target.Path):ProcessReadOpen(target.Pid);
            return i<9?HostPrivacyContract.FileObservation(i,target.OwnerObservedAbsent,error):
                new HostPrivacyCase(target.Role,target.Kind,error==5?"ACCESS_DENIED":error==0?"OPENED":"UNKNOWN",error);
        }).ToArray();
        var report=new HostPrivacyObservation(1,resource.Nonce,resource.HostPrivacySHA256,Environment.ProcessId,observations);
        var data=JsonSerializer.SerializeToUtf8Bytes(report);
        using(var output=new FileStream(ReportPath(workspace,actor),FileMode.CreateNew,FileAccess.Write,FileShare.None)){output.Write(data);output.Flush(true);}
        return HostPrivacyContract.CasesSatisfied(observations,plan.Targets[HostPrivacyContract.ResetSettingsIndex].OwnerObservedAbsent);
    }
    private static string PlanPath(string workspace)=>WindowsPathSeal.Child(workspace,"host-privacy-plan.json");
    // The compiler never opens/deserializes the private target plan. These
    // are fixed public installation paths and held owner/root process IDs.
    internal static bool RunCompilerControl(ResourceProbePlan resource,string workspace,int rootPid)
    {
        resource.Validate();
        if(!resource.DevelopProject || resource.HostPrivacySHA256 is null || rootPid<=0 || rootPid==Environment.ProcessId || rootPid==resource.BrokerPid)
            throw WfpNative.Contract("CompilerRootBindingRequired");
        AssertPlanAbsent(workspace);
        var observations=Enumerable.Range(0,HostPrivacyContract.CompilerCaseCount).Select(i=>
        {
            var c=HostPrivacyContract.CompilerCase(i);var source=i<19?i+HostPrivacyContract.HostResourceCount:i-19+HostPrivacyContract.HostResourceCount;
            var error=i is >=9 and <19?ControlFileOpen(ControlFilePath(resource.ProgramFilesRoot,resource.Release,source),source):
                OwnerAccessOpen(i<9?resource.BrokerPid:rootPid,source);
            return new HostPrivacyCase(c.Role,c.Kind,error==5?"ACCESS_DENIED":error==0?"OPENED":"UNKNOWN",error);
        }).ToArray();
        HostPrivacyContract.ValidateCompilerCases(observations);
        var report=new HostPrivacyObservation(1,resource.Nonce,resource.HostPrivacySHA256,Environment.ProcessId,observations);
        using(var output=new FileStream(ReportPath(workspace,"project"),FileMode.CreateNew,FileAccess.Write,FileShare.None))
        {JsonSerializer.Serialize(output,report);output.Flush(true);}
        return observations.All(c=>c.Status=="ACCESS_DENIED" && c.Error==5);
    }
    private static string ReportPath(string workspace,string actor)=>WindowsPathSeal.Child(workspace,"host-privacy-"+actor+".json");
    // Request only FILE_READ_DATA, asynchronously: no denial caused solely by
    // extra GENERIC_READ/READ_CONTROL/SYNCHRONIZE rights can become a PASS.
    private static int FileReadOpen(string path)
    {using var handle=CreateFile(path,1,7,IntPtr.Zero,3,0x40200000,IntPtr.Zero);return handle.IsInvalid?Marshal.GetLastWin32Error():0;}
    private static int RegistryReadOpen(bool machine,string path)
    {var error=RegOpenKeyEx(new IntPtr(machine?unchecked((int)0x80000002):unchecked((int)0x80000003)),path,0,0x101,out var key);key?.Dispose();return error;}
    private static void PositiveRegistry(bool machine,string path)
    {var error=RegistryReadOpen(machine,path);if(error!=0)throw new Win32Exception(error,"Host privacy key positive control");}
    private static int ProcessReadOpen(int pid)
    {using var handle=OpenProcess(0x10,false,checked((uint)pid));return handle.IsInvalid?Marshal.GetLastWin32Error():0;}
    private static int OwnerAccessOpen(int pid,int index)
    {
        var access=HostPrivacyContract.OwnerAccess(index);
        if(pid<=0)throw WfpNative.Contract("ProtectionOwnerProcessRequired");
        // Close immediately. Never use the acquired right, even on exposure.
        using var handle=OpenProcess(access,false,checked((uint)pid));
        return handle.IsInvalid?Marshal.GetLastWin32Error():0;
    }
    private static void RequireOwnerTarget(string path,int pid,int ownerPid,int index)
    {
        _=HostPrivacyContract.OwnerAccess(index);
        if(path!="" || ownerPid<=0 || pid!=ownerPid)
            throw WfpNative.Contract("ProtectionOwnerTargetBindingDiffers");
    }
    private static bool ProcessAlive(SafeProcessHandle process)=>WaitForSingleObject(process,0)==258;
    private static string FileIdentity(string path)
    {
        for(var p=path;p is not null;p=Path.GetDirectoryName(p))
            if((File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw WfpNative.Contract("HostPrivacyRedirectedTargetRefused");
        using var handle=CreateFile(path,0x80,7,IntPtr.Zero,3,0x40200000,IntPtr.Zero);
        if(handle.IsInvalid || !GetFileInformationByHandle(handle,out var info))throw new Win32Exception(Marshal.GetLastWin32Error(),"Host privacy file metadata positive control");
        if((info.Attributes&0x410)!=0)throw WfpNative.Contract("HostPrivacyOrdinaryFileRequired");
        return info.Volume.ToString("X8")+info.IndexHigh.ToString("X8")+info.IndexLow.ToString("X8");
    }
    public void Dispose(){published?.Dispose();probeProcess?.Dispose();foreach(var handle in controlFiles)handle.Dispose();foreach(var handle in processes)handle.Dispose();}
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle process,out uint exitCode);
    [StructLayout(LayoutKind.Sequential)] private struct FileInfo
    {internal uint Attributes;internal System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;internal uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle file,out FileInfo info);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint pid);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",EntryPoint="QueryFullProcessImageNameW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder path,ref int length);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll",EntryPoint="RegOpenKeyExW",CharSet=CharSet.Unicode)] private static extern int RegOpenKeyEx(IntPtr root,string path,uint options,uint access,out SafeRegistryHandle key);
}
