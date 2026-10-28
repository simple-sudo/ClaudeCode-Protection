using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Fixed, offline qualification data, never an executable/path/script grant.
internal sealed record ResourceProbePlan(int SchemaVersion,string Nonce,string InstallationId,string Release,int BrokerPid,string ToolSHA256)
{
    internal void Validate()
    {
        if(SchemaVersion!=1 || BrokerPid<=0)throw WfpNative.Contract("ResourceQualificationPlanRefused");
        _=Identifiers.Hex32(Nonce);_=Identifiers.Hex32(InstallationId);_=Identifiers.Hex32(Release);_=Identifiers.Hash(ToolSHA256);
    }
    internal string Fixture=>WindowsPathSeal.Child(FixedLayout.FromWindows().StateRoot,"resource-fixture-"+Nonce+".json");
    internal string Workspace(string sid)=>WindowsPathSeal.Child(SessionResources.ProfileFolder(sid),"workspace-"+Nonce);
    internal byte[] Input=>Encoding.UTF8.GetBytes("CPC-RESOURCE:"+Nonce);
}
internal sealed record ResourceAccessCase(string Role,string Status,int? Error);
internal sealed record ResourceChildReport(int SchemaVersion,int Pid,string Nonce,bool WorkspaceWriteReadMatched,int? ToolExit,
    ResourceAccessCase[] Cases,string? FailureType,int? FailureCode,string? FailureStage);

// The workspace belongs to the freshly created installation profile. No host
// directory ACL is widened, adopted, recursively copied or deleted. It is task
// data, not a trust anchor. All executable inputs remain outside the workspace.
internal sealed class SessionResources : IDisposable
{
    private readonly ProtectedState state;
    private readonly PathLease folder;
    private readonly FileStream input,tool;
    internal ResourceProbePlan Plan {get;}
    internal string Workspace=>folder.Path;
    private SessionResources(ProtectedState state,PathLease folder,FileStream input,FileStream tool,ResourceProbePlan plan)
    {this.state=state;this.folder=folder;this.input=input;this.tool=tool;Plan=plan;}
    internal static SessionResources Create(ProtectedState state,VerifiedVersion version,InstallationProfileLease profile,string nonce)
    {
        state.AssertHeld();version.AssertHeld(state);
        using var sid=new InstallationPackageSid(state);profile.AssertPackage(sid);
        var tool=new FileStream(WindowsPathSeal.OpenPowerShell(),FileAccess.Read,65536,false);
        PathLease? directory=null;FileStream? input=null;
        try
        {
            var hash=Convert.ToHexString(SHA256.HashData(tool));tool.Position=0;
            var plan=new ResourceProbePlan(1,Identifiers.Hex32(nonce),state.InstallationId,version.Package.Release,Environment.ProcessId,hash);plan.Validate();
            var root=profile.WorkspaceRoot();
            using var parent=WindowsPathSeal.LockDirectory(root,PathPolicy.Source);
            var path=plan.Workspace(sid.Value);
            if(!CreateDirectory(path,IntPtr.Zero))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),"CreateFreshSessionWorkspace");
            directory=WindowsPathSeal.LockDirectory(path,PathPolicy.Source);
            var inputPath=WindowsPathSeal.Child(path,"input.txt");
            using(var seeded=new FileStream(inputPath,FileMode.CreateNew,FileAccess.Write,FileShare.None)){seeded.Write(plan.Input);seeded.Flush(true);}
            input=new FileStream(WindowsPathSeal.Open(inputPath,false,true),FileAccess.Read,4096,false);
            if(input.Length!=plan.Input.Length || Convert.ToHexString(SHA256.HashData(input))!=Convert.ToHexString(SHA256.HashData(plan.Input)))
                throw WfpNative.Contract("FreshWorkspaceInputChanged");
            input.Position=0;
            state.WriteNew("resource-fixture-"+nonce+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,Nonce=nonce,
                Value="CONTROLLED_NON_SECRET_FIXTURE",Scope="PRIVATE_STATE_ACCESS_DENIAL_CONTROL"}));
            // An existing, readable positive host control prevents absence from
            // being mistaken for a restricted child's access-denied result.
            _=state.Read("resource-fixture-"+nonce+".json",4096);
            return new(state,directory,input,tool,plan);
        }
        catch{input?.Dispose();directory?.Dispose();tool.Dispose();throw;}
    }
    internal void AssertHeld()
    {
        state.AssertHeld();folder.AssertHeld();
        if(input.SafeFileHandle.IsClosed || tool.SafeFileHandle.IsClosed)throw WfpNative.Contract("SessionResourceLeaseLost");
        WindowsPathSeal.VerifyObject(input.SafeFileHandle,WindowsPathSeal.Child(Workspace,"input.txt"),false);
        WindowsPathSeal.AssertAcl(tool.SafeFileHandle,false,true);
    }
    internal void AssertOutput()
    {
        AssertHeld();
        foreach(var name in new[]{"root-output.txt","tool-output.txt"})
        {
            using var handle=WindowsPathSeal.Open(WindowsPathSeal.Child(Workspace,name),false,true);
            using var output=new FileStream(handle,FileAccess.Read,4096,false);
            if(output.Length!=Plan.Input.Length || Convert.ToHexString(SHA256.HashData(output))!=Convert.ToHexString(SHA256.HashData(Plan.Input)))
                throw WfpNative.Contract("SessionWorkspaceOutputMismatch");
        }
    }
    internal static string ToolPath=>WindowsPathSeal.Child(Environment.GetFolderPath(Environment.SpecialFolder.System),"WindowsPowerShell/v1.0/powershell.exe");
    internal static string ProfileFolder(string sid)
    {
        var status=GetAppContainerFolderPath(sid,out var pointer);
        try
        {
            if(status!=0)throw new WfpFailure("GetOwnedProfileFolder",unchecked((uint)status));
            return WindowsPathSeal.Canonical(Marshal.PtrToStringUni(pointer)??throw WfpNative.Contract("ProfileFolderMissing"));
        }
        finally{if(pointer!=IntPtr.Zero)Marshal.FreeCoTaskMem(pointer);}
    }
    internal static int RunChild(string packageSid)
    {
        var raw=Environment.GetEnvironmentVariable("CPC_RESOURCE_PLAN");if(raw is null || raw.Length>1024)return 125;
        using var json=JsonDocument.Parse(raw);StrictJson.Fields(json.RootElement,"SchemaVersion","Nonce","InstallationId","Release","BrokerPid","ToolSHA256");
        var plan=JsonSerializer.Deserialize<ResourceProbePlan>(raw)??throw WfpNative.Contract("ResourcePlanMissing");plan.Validate();
        using var sid=InstallationPackageSid.FromInstallationId(plan.InstallationId);
        if(sid.Value!=packageSid || Environment.GetEnvironmentVariable("CPC_NETWORK_PLAN") is not null ||
            Environment.GetEnvironmentVariable("CPC_GPU_PLAN") is not null || Environment.GetEnvironmentVariable("CPC_SESSION_ID") is not null ||
            !string.Equals(Environment.ProcessPath,WindowsPathSeal.Child(FixedLayout.FromWindows().Version(plan.Release),"bin/admin/ProtectionBroker.exe"),StringComparison.OrdinalIgnoreCase))return 125;
        var workspace=plan.Workspace(packageSid);var cases=new List<ResourceAccessCase>();bool matched=false;int? toolExit=null;string? failure=null;
        string stage="OPEN_AUTHORIZED_WORKSPACE_LEAF";int? failureCode=null;string? failureStage=null;
        try
        {
            // The trusted owner holds the complete ancestry. The restricted
            // child must not need READ_CONTROL on unrelated host ancestors.
            using var folder=WindowsPathSeal.Open(workspace,true,false);
            stage="READ_WORKSPACE_INPUT";
            var input=ReadSmall(WindowsPathSeal.Child(workspace,"input.txt"));
            if(!input.AsSpan().SequenceEqual(plan.Input))throw WfpNative.Contract("ResourceInputMismatch");
            var result=WindowsPathSeal.Child(workspace,"root-output.txt");
            stage="WRITE_AND_READ_WORKSPACE_OUTPUT";
            using(var output=new FileStream(result,FileMode.CreateNew,FileAccess.Write,FileShare.None)){output.Write(input);output.Flush(true);}
            matched=ReadSmall(result).AsSpan().SequenceEqual(input);
            stage="DENY_PRIVATE_STATE_AND_BROKER_HANDLE";
            foreach(var access in new[]{FileAccess.Read,FileAccess.Write})
            {
                try{using var opened=new FileStream(plan.Fixture,FileMode.Open,access,FileShare.ReadWrite);cases.Add(new("private-state-"+access,"OPENED",null));}
                catch(UnauthorizedAccessException){cases.Add(new("private-state-"+access,"ACCESS_DENIED",5));}
                catch(Exception ex){cases.Add(new("private-state-"+access,"UNKNOWN",ex.HResult));}
            }
            using(var broker=OpenProcess(0x10,false,checked((uint)plan.BrokerPid)))
            {
                var error=Marshal.GetLastWin32Error();cases.Add(new("broker-vm-read-open",!broker.IsInvalid?"OPENED":error==5?"ACCESS_DENIED":"UNKNOWN",broker.IsInvalid?error:null));
            }
            // The fixed OS tool executes no user profile, module, supplied
            // script or network request. It uses the same workspace and must
            // independently fail to read the protected non-secret fixture.
            const string script="$ErrorActionPreference='Stop';$v=[IO.File]::ReadAllText('input.txt');[IO.File]::WriteAllText('tool-output.txt',$v);$denied=$false;try{$f=[IO.File]::OpenRead($env:CPC_DENIAL_FIXTURE);$f.Dispose()}catch{if($_.Exception -is [UnauthorizedAccessException] -or $_.Exception.InnerException -is [UnauthorizedAccessException]){$denied=$true}else{exit 22}};if(!$denied){exit 23};[Threading.Thread]::Sleep(2200);exit 0";
            stage="VERIFY_FIXED_TOOL_BYTES";
            using(var tool=File.OpenRead(ToolPath))
                if(Convert.ToHexString(SHA256.HashData(tool))!=plan.ToolSHA256)throw WfpNative.Contract("FixedToolBytesChanged");
            var start=new ProcessStartInfo(ToolPath){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=workspace,RedirectStandardOutput=true,RedirectStandardError=true};
            start.Environment.Clear();
            foreach(var name in new[]{"SystemRoot","windir","SystemDrive","PROCESSOR_ARCHITECTURE"})
            {var value=Environment.GetEnvironmentVariable(name);if(value is not null)start.Environment[name]=value;}
            foreach(var name in new[]{"TEMP","TMP","LOCALAPPDATA","USERPROFILE"})start.Environment[name]=workspace;
            start.Environment["PATH"]=Environment.GetFolderPath(Environment.SpecialFolder.System);
            start.Environment["PSModulePath"]=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"WindowsPowerShell\\v1.0\\Modules");
            start.Environment["CPC_DENIAL_FIXTURE"]=plan.Fixture;
            foreach(var arg in new[]{"-NoLogo","-NoProfile","-NonInteractive","-Command",script})start.ArgumentList.Add(arg);
            stage="START_FIXED_POWERSHELL";
            using var process=Process.Start(start)??throw WfpNative.Contract("FixedToolStartFailed");
            var stdout=ReadBounded(process.StandardOutput);var stderr=ReadBounded(process.StandardError);
            stage="WAIT_FIXED_POWERSHELL";
            if(!process.WaitForExit(10000))throw new TimeoutException("Fixed offline tool deadline");
            toolExit=process.ExitCode;
            if(stdout.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult().Length!=0 ||
                stderr.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult().Length!=0)throw WfpNative.Contract("FixedToolUnexpectedOutput");
        }
        catch(Exception ex){failure=ex.GetType().Name;failureCode=ex is System.ComponentModel.Win32Exception native?native.NativeErrorCode:ex.HResult;failureStage=stage;}
        var report=new ResourceChildReport(1,Environment.ProcessId,plan.Nonce,matched,toolExit,cases.ToArray(),failure,failureCode,failureStage);
        Console.WriteLine(JsonSerializer.Serialize(report));return Qualified(report)?0:3;
    }
    internal static bool Qualified(ResourceChildReport report)=>report.SchemaVersion==1 && report.WorkspaceWriteReadMatched && report.ToolExit==0 && report.FailureType is null && report.FailureCode is null && report.FailureStage is null &&
        report.Cases.Length==3 && report.Cases.Select(c=>c.Role).SequenceEqual(new[]{"private-state-Read","private-state-Write","broker-vm-read-open"}) &&
        report.Cases.All(c=>c.Status=="ACCESS_DENIED" && c.Error==5);
    internal static async Task<string> ReadBounded(StreamReader reader)
    {
        var data=new char[4097];var total=0;
        while(total<data.Length){var count=await reader.ReadAsync(data.AsMemory(total));if(count==0)return new string(data,0,total);total+=count;}
        throw WfpNative.Contract("ResourceReportTooLarge");
    }
    private static byte[] ReadSmall(string path)
    {
        using var file=File.OpenRead(path);if(file.Length is <1 or >1024)throw WfpNative.Contract("ResourceFixtureBounds");
        var data=new byte[checked((int)file.Length)];file.ReadExactly(data);return data;
    }
    public void Dispose(){input.Dispose();folder.Dispose();tool.Dispose();}
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] private static extern int GetAppContainerFolderPath(string sid,out IntPtr path);
    [DllImport("kernel32.dll",EntryPoint="CreateDirectoryW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateDirectory(string path,IntPtr attributes);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)] bool inherit,uint pid);
}
