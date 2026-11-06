using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

// A held current-installed daily peer, never a supplied token or a lookup of
// Explorer/another process. CREATE_PROCESS is solely for the fixed parent
// attribute; no VM, thread, DUP_HANDLE, terminate or token-adjust access.
internal sealed class GpuReferenceCaller : IDisposable
{
    internal const uint ProcessAccess=0x00100000|0x1000|0x0080;
    private readonly SafeProcessHandle process;
    private readonly PipeStream channel;
    private readonly string image;
    private readonly long created;
    private bool disposed;
    internal uint Pid {get;}
    internal GpuHostTokenFacts Expected {get;}
    private GpuReferenceCaller(SafeProcessHandle process,PipeStream channel,string image,uint pid,long created,GpuHostTokenFacts expected)
    {this.process=process;this.channel=channel;this.image=image;Pid=pid;this.created=created;Expected=expected;}
    internal static GpuReferenceCaller Open(PipeStream channel,int pid,string versionRoot)
    {
        MaintenanceIdentity.RequireCurrentAdministrator();WorkspacePipe.AssertPeer(channel,pid,false);
        if(pid<=0 || pid==Environment.ProcessId)throw WfpNative.Contract("HostGpuOrdinaryDailyPeerRequired");
        var handle=OpenProcess(ProcessAccess,false,(uint)pid);
        if(handle.IsInvalid){var error=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(error,"Open bound GPU daily peer");}
        try
        {
            var expected=ReadToken(handle);GpuHostToken.RequireNormal(expected);
            using var identity=WindowsIdentity.GetCurrent(TokenAccessLevels.Query|TokenAccessLevels.Duplicate);
            var owner=GpuHostToken.Capture(identity.AccessToken);GpuHostToken.RequireSource(owner);
            RequireSameHuman(owner,expected);
            if(!GetProcessTimes(handle,out var at,out _,out _,out _))throw Error();
            var result=new GpuReferenceCaller(handle,channel,WindowsPathSeal.Child(versionRoot,"bin/current/ClaudeProtection.exe"),(uint)pid,at,expected);
            result.AssertCurrent();return result;
        }
        catch{handle.Dispose();throw;}
    }
    internal static void RequireSameHuman(GpuHostTokenFacts owner,GpuHostTokenFacts ordinary)
    {
        GpuHostToken.RequireSource(owner);GpuHostToken.RequireNormal(ordinary);
        if(owner.UserSid!=ordinary.UserSid || owner.SessionId!=ordinary.SessionId)throw WfpNative.Contract("HostGpuCallerHumanOrSessionMismatch");
    }
    internal void AssertCurrent()
    {
        if(disposed || process.IsInvalid || process.IsClosed || GetProcessId(process)!=Pid || WaitForSingleObject(process,0)!=258 ||
            !GetProcessTimes(process,out var at,out _,out _,out _) || at!=created)throw WfpNative.Contract("HostGpuOriginalDailyPeerUnavailable");
        WorkspacePipe.AssertPeer(channel,checked((int)Pid),false);
        var path=new StringBuilder(32768);uint length=(uint)path.Capacity;
        if(!QueryFullProcessImageName(process,0,path,ref length))throw Error();
        if(!string.Equals(WindowsPathSeal.Canonical(path.ToString()),image,StringComparison.OrdinalIgnoreCase))throw WfpNative.Contract("HostGpuCurrentInstalledDailyRequired");
        GpuHostToken.RequireCreated(Expected,ReadToken(process));
    }
    internal IntPtr AllocateParentValue()
    {AssertCurrent();var value=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(value,process.DangerousGetHandle());return value;}
    private static GpuHostTokenFacts ReadToken(SafeProcessHandle process)
    {
        if(!OpenProcessToken(process,0x0a,out var token))throw Error();
        using(token)return GpuHostToken.Capture(token);
    }
    public void Dispose(){if(disposed)return;disposed=true;process.Dispose();}
    private static Win32Exception Error(){var e=new Win32Exception(Marshal.GetLastWin32Error(),"Read bound ordinary GPU peer");e.Data["Stage"]="HostGpuBoundPeerRead";return e;}
    [DllImport("kernel32.dll",SetLastError=true)]private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint pid);
    [DllImport("kernel32.dll")]private static extern uint GetProcessId(SafeProcessHandle process);
    [DllImport("kernel32.dll",SetLastError=true)]private static extern uint WaitForSingleObject(SafeProcessHandle process,uint ms);
    [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool GetProcessTimes(SafeProcessHandle process,out long created,out long exit,out long kernel,out long user);
    [DllImport("kernel32.dll",EntryPoint="QueryFullProcessImageNameW",CharSet=CharSet.Unicode,SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder path,ref uint size);
    [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool OpenProcessToken(SafeProcessHandle process,uint access,out SafeAccessTokenHandle token);
}
