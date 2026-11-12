using System.ComponentModel;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Security;

namespace ProtectionLifecycle;

internal sealed record LoopbackEntry(string Sid,uint Attributes);

// The Windows CLI receives one derived owned SID, never a global-list restore.
// Snapshot comparisons detect unrelated drift; cleanup removes only our SID.
// An external concurrent writer cannot be atomically locked by this API.
internal sealed class InstallationLoopbackLease : IDisposable
{
    private readonly ProtectedState state;
    private readonly string sid,id;
    private readonly LoopbackEntry[] prior;
    private bool disposed,toolStopped=true;
    internal static void AssertClosedHistory(ProtectedState state)
    {
        state.AssertHeld();using var target=new InstallationPackageSid(state);using var control=InstallationPackageSid.ForNetworkControl(state);
        foreach(var leaf in state.ListLeaves("loopback-intent-"))
        {
            if(leaf.Length!=53)throw WfpNative.Contract("LoopbackIntentLeafShape");
            var id=Identifiers.Hex32(leaf.Substring(16,32));
            using var before=JsonDocument.Parse(state.Read(leaf).Bytes);var b=before.RootElement;
            if(b.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(b,"InstallationId")!=state.InstallationId ||
                StrictJson.Text(b,"Sid") is not string sid || (sid!=target.Value && sid!=control.Value))throw WfpNative.Contract("LoopbackIntentScopeMismatch");
            var closed=state.ReadOptional("loopback-cleanup-"+id+".json");if(closed is null)throw WfpNative.Contract("PendingOwnedLoopbackOperationRequiresRecovery");
            using var doc=JsonDocument.Parse(closed.Bytes);var c=doc.RootElement;
            if(c.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(c,"InstallationId")!=state.InstallationId || StrictJson.Text(c,"Sid")!=sid ||
                !c.GetProperty("ExactSidAbsent").GetBoolean() || !c.GetProperty("UnrelatedEntriesPreserved").GetBoolean())throw WfpNative.Contract("OwnedLoopbackCleanupNotConfirmed");
        }
    }
    private InstallationLoopbackLease(ProtectedState state,string sid,string id,LoopbackEntry[] prior)
    {this.state=state;this.sid=sid;this.id=id;this.prior=prior;}
    internal static InstallationLoopbackLease Enable(ProtectedState state,bool control)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();
        using var package=control?InstallationPackageSid.ForNetworkControl(state):new InstallationPackageSid(state);
        var before=Read();if(before.Any(e=>e.Sid==package.Value))throw WfpNative.Contract("ExistingLoopbackExemptionNotAdopted");
        var id=Guid.NewGuid().ToString("N");
        state.WriteNew("loopback-intent-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,Sid=package.Value,
            Before=before,Operation="ADD_EXACT_OWNED_SID",ExternalConcurrentWritersSerialized=false,AtUtc=DateTime.UtcNow.ToString("o")}));
        var lease=new InstallationLoopbackLease(state,package.Value,id,before);
        try
        {
            Invoke("-a",package.Value,ref lease.toolStopped);var after=Read();
            if(after.Count(e=>e.Sid==package.Value)!=1 || !Others(after,package.Value).SequenceEqual(before))throw WfpNative.Contract("LoopbackAddOrOtherEntriesChanged");
            state.WriteNew("loopback-added-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,Sid=package.Value,Status="EXACT_SID_PRESENT_OTHERS_UNCHANGED"}));
            return lease;
        }
        catch(Exception failure){try{lease.Dispose();}catch(Exception cleanup){throw new AggregateException(failure,cleanup);}throw;}
    }
    public void Dispose()
    {
        if(disposed)return;disposed=true;state.AssertHeld();
        if(!toolStopped)throw WfpNative.Contract("LoopbackUtilityLifetimeUnknownNoCleanupProof");
        var before=Read();if(before.Any(e=>e.Sid==sid))Invoke("-d",sid,ref toolStopped);
        var after=Read();var absent=after.All(e=>e.Sid!=sid);var othersSame=Others(before,sid).SequenceEqual(after);
        state.WriteNew("loopback-cleanup-"+id+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,Sid=sid,
            ExactSidAbsent=absent,UnrelatedEntriesPreserved=othersSame,OriginalOthersUnchanged=after.SequenceEqual(prior),AtUtc=DateTime.UtcNow.ToString("o")}));
        if(!absent || !othersSame)throw WfpNative.Contract("LoopbackCleanupOrUnrelatedEntriesNotConfirmed");
    }
    private static LoopbackEntry[] Others(IEnumerable<LoopbackEntry> rows,string sid)=>rows.Where(e=>e.Sid!=sid).OrderBy(e=>e.Sid,StringComparer.Ordinal).ToArray();
    private static LoopbackEntry[] Read()
    {
        WfpNative.Check(NetworkIsolationGetAppContainerConfig(out var count,out var pointer),"ReadLoopbackExemptions");
        try
        {
            if(count>4096 || (count>0 && pointer==IntPtr.Zero))throw WfpNative.Contract("LoopbackSnapshotBounds");
            var result=new List<LoopbackEntry>();var size=Marshal.SizeOf<SidAttributes>();
            for(var i=0;i<count;i++)
            {
                var row=Marshal.PtrToStructure<SidAttributes>(pointer+checked((int)i)*size);
                if(row.Sid==IntPtr.Zero || !WfpNative.IsValidSid(row.Sid))throw WfpNative.Contract("InvalidLoopbackSid");
                result.Add(new(new SecurityIdentifier(row.Sid).Value,row.Attributes));
            }
            if(result.Select(e=>e.Sid).Distinct().Count()!=result.Count)throw WfpNative.Contract("DuplicateLoopbackSid");
            return result.OrderBy(e=>e.Sid,StringComparer.Ordinal).ToArray();
        }
        finally
        {
            if(pointer!=IntPtr.Zero)
            {
                if(count<=4096)for(var i=0;i<count;i++){var p=Marshal.ReadIntPtr(pointer+checked((int)i)*Marshal.SizeOf<SidAttributes>());if(p!=IntPtr.Zero)HeapFree(GetProcessHeap(),0,p);}
                HeapFree(GetProcessHeap(),0,pointer);
            }
        }
    }
    private static void Invoke(string operation,string sid,ref bool stopped)
    {
        if(operation is not ("-a" or "-d") || !sid.StartsWith("S-1-15-2-",StringComparison.Ordinal))throw WfpNative.Contract("ExactLoopbackCommandRequired");
        var system=Environment.GetFolderPath(Environment.SpecialFolder.System);using var path=WindowsPathSeal.LockDirectory(system,PathPolicy.TrustedAncestor);
        using var executable=WindowsPathSeal.OpenCheckNetIsolation();
        var start=new ProcessStartInfo(Path.Combine(system,"CheckNetIsolation.exe")){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=system,
            RedirectStandardOutput=true,RedirectStandardError=true};
        start.Environment.Clear();foreach(var name in new[]{"SystemRoot","windir","SystemDrive","USERPROFILE","LOCALAPPDATA"})
        {var value=Environment.GetEnvironmentVariable(name);if(value is not null)start.Environment[name]=value;}
        start.ArgumentList.Add("LoopbackExempt");start.ArgumentList.Add(operation);start.ArgumentList.Add("-p="+sid);
        using var process=Process.Start(start)??throw WfpNative.Contract("LoopbackCommandNotStarted");
        stopped=false;
        var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
        if(!process.WaitForExit(10000))
        {process.Kill();stopped=process.WaitForExit(5000);throw new TimeoutException("Exact loopback command timeout; termination status retained");}
        stopped=true;
        _=output.GetAwaiter().GetResult();_=error.GetAwaiter().GetResult();
        if(process.ExitCode!=0)throw WfpNative.Contract("ExactLoopbackCommandFailed");
    }
    [StructLayout(LayoutKind.Sequential)] private struct SidAttributes {internal IntPtr Sid;internal uint Attributes;}
    [DllImport("FirewallAPI.dll",ExactSpelling=true)] private static extern uint NetworkIsolationGetAppContainerConfig(out uint count,out IntPtr entries);
    [DllImport("kernel32.dll")] private static extern IntPtr GetProcessHeap();
    [DllImport("kernel32.dll")] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool HeapFree(IntPtr heap,uint flags,IntPtr memory);
}
