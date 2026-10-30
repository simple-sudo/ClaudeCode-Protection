using System.Diagnostics;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

if(args.Length!=1 || args[0] is not ("policy" or "messages" or "handle-transfer"))return 125;
using var identity=WindowsIdentity.GetCurrent();
if(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))throw new InvalidOperationException("Ordinary qualification only");
var library=Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory,"ProtectionLifecycle.dll"));
const BindingFlags flags=BindingFlags.Static|BindingFlags.NonPublic;
object? Call(Type type,string method,params object?[] values)
{
    try{return type.GetMethod(method,flags)!.Invoke(null,values);}
    catch(TargetInvocationException ex)when(ex.InnerException is not null){ExceptionDispatchInfo.Capture(ex.InnerException).Throw();throw;}
}
void Require(bool value,string reason){if(!value)throw new InvalidOperationException(reason);}
void Refuse(Action action,string reason)
{
    try{action();}catch(InvalidDataException ex)when(ex.Message==reason){return;}
    throw new InvalidOperationException("Expected refusal: "+reason);
}
var launch=library.GetType("ProtectionLifecycle.OwnedToolLaunch",true)!;
if(args[0]=="handle-transfer")
{
    var atomic=library.GetType("ProtectionLifecycle.AtomicChild",true)!;
    var toolType=atomic.GetNestedType("InheritedTool",BindingFlags.NonPublic)!;
    var evidenceType=library.GetType("ClaudeCodeProtection.Workspaces.ToolCreationEvidence",true)!;
    var evidence=JsonSerializer.Deserialize("{\"ChildProcessPolicy\":0,\"ChildPolicyQueryError\":null,\"ImageLoadPolicy\":0,\"ImagePolicyQueryError\":null,\"ImageExecuteOpenError\":0}",evidenceType)!;
    using var self=OpenProcess(0x1fffff,false,checked((uint)Environment.ProcessId));Require(!self.IsInvalid,"owned process handle opened");
    Require(CreatePipe(out var inputRead,out var inputWrite,IntPtr.Zero,0),"owned stdin pipe created");
    Require(CreatePipe(out var outputRead,out var outputWrite,IntPtr.Zero,0),"owned stdout pipe created");
    Require(CreatePipe(out var errorRead,out var errorWrite,IntPtr.Zero,0),"owned stderr pipe created");
    using var inputSource=new FileStream(inputRead,FileAccess.Read);using var outputSource=new FileStream(outputWrite,FileAccess.Write);using var errorSource=new FileStream(errorWrite,FileAccess.Write);
    var constructor=toolType.GetConstructors(BindingFlags.Instance|BindingFlags.NonPublic).Single(c=>c.GetParameters().Length==5);
    using var tool=(IDisposable)constructor.Invoke(new object[]{self,inputWrite,outputRead,errorRead,evidence});
    object reply;
    try{reply=toolType.GetMethod("TransferTo",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(tool,new object[]{self,Environment.ProcessId,1,new string('a',32)})!;}
    catch(TargetInvocationException ex)when(ex.InnerException is not null){ExceptionDispatchInfo.Capture(ex.InnerException).Throw();throw;}
    long Value(string name)=>(long)reply.GetType().GetProperty(name)!.GetValue(reply)!;
    using var limited=new SafeProcessHandle((IntPtr)Value("Process"),true);
    // The published PUBLIC_OBJECT_BASIC_INFORMATION has fourteen ULONGs.
    // Preserve the failed 64-byte and zero-buffer probes; this host did not
    // report a required size for those STATUS_INFO_LENGTH_MISMATCH results.
    const int basicBytes=14*sizeof(uint);
    var buffer=Marshal.AllocHGlobal(basicBytes);
    try{var status=NtQueryObject(limited,0,buffer,basicBytes,out var returned);Require(status==0,"own transferred process handle basic query: "+status.ToString("X8")+"/"+returned);Require(unchecked((uint)Marshal.ReadInt32(buffer,4))==0x101000u,"native granted process access is exactly synchronize plus limited query");}
    finally{Marshal.FreeHGlobal(buffer);}
    using var input=new FileStream(new SafeFileHandle((IntPtr)Value("Input"),true),FileAccess.Write);
    using var output=new FileStream(new SafeFileHandle((IntPtr)Value("Output"),true),FileAccess.Read);
    using var error=new FileStream(new SafeFileHandle((IntPtr)Value("Error"),true),FileAccess.Read);
    foreach(var handle in new[]{limited.DangerousGetHandle(),input.SafeFileHandle.DangerousGetHandle(),output.SafeFileHandle.DangerousGetHandle(),error.SafeFileHandle.DangerousGetHandle()})
        Require(GetHandleInformation(handle,out var information) && (information&1)==0,"all transferred handles are non-inheritable");
    input.WriteByte(73);input.Flush();Require(inputSource.ReadByte()==73,"stdin endpoint direction");
    outputSource.WriteByte(79);outputSource.Flush();Require(output.ReadByte()==79,"stdout endpoint direction");
    errorSource.WriteByte(69);errorSource.Flush();Require(error.ReadByte()==69,"stderr endpoint direction");
    Console.WriteLine("PASS production handle transfer on own ordinary process/local anonymous pipes: native process granted mask exactly101000, four non-inheritable handles and all stdio directions; no other process, Job/profile or elevated execution");return 0;
}
var planType=library.GetType("ProtectionLifecycle.ResourceProbePlan",true)!;
var resources=library.GetType("ProtectionLifecycle.SessionResources",true)!;
var git=library.GetType("ProtectionLifecycle.SessionGitToolchain",true)!;
var nonce=new string('a',32);var programFiles=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
var plan=Activator.CreateInstance(planType,3,nonce,new string('b',32),new string('c',32),Environment.ProcessId,new string('A',64),
    "9DE2A6DB90D8383F3738249D52F30DEFBEDB994513A8F2697E9D90693CD1D285",null,programFiles)!;
var workspace=Path.Combine(programFiles,"ClaudeCodeProtection-Task-"+nonce);
var directory=Path.Combine(programFiles,"Git","mingw64","bin");
string Digest(ProcessStartInfo start)=>(string)Call(launch,"StartHash",start)!;
void Validate(string kind,ProcessStartInfo start)=>_=Call(launch,"ValidateStart",plan,workspace,kind,start.ArgumentList.ToArray(),Digest(start));
var powerShell=(ProcessStartInfo)Call(resources,"PowerShellStart",plan,workspace)!;
if(args[0]=="policy")
{
    Validate("powershell",powerShell);
    var script=powerShell.ArgumentList[^1];powerShell.ArgumentList[^1]="Write-Output unapproved";
    Refuse(()=>Validate("powershell",powerShell),"OwnedPowerShellCompiledProgramRequired");powerShell.ArgumentList[^1]=script;
    powerShell.Environment["PATH"]="C:\\unapproved";
    Refuse(()=>Validate("powershell",powerShell),"OwnedToolEnvironmentOrStartMismatch");
    powerShell=(ProcessStartInfo)Call(resources,"PowerShellStart",plan,workspace)!;
    Refuse(()=>Validate("shell",powerShell),"OwnedToolKindRefused");
    var repo=Path.Combine(workspace,"git-project");
    var tails=new[]{new[]{"hash-object","--stdin"},new[]{"init","--quiet","--initial-branch=qualification","--template="+Path.Combine(workspace,"empty-git-template"),repo},
        new[]{"--literal-pathspecs","-C",repo,"add","--force","--pathspec-from-file="+Path.Combine(workspace,"git-selected-paths.bin"),"--pathspec-file-nul"},
        new[]{"-C",repo,"commit","--quiet","--no-gpg-sign","-m","Controlled offline qualification"},
        new[]{"-C",repo,"rev-parse","--verify","HEAD"},new[]{"hash-object","--",Path.Combine(programFiles,"ClaudeCodeProtection-State","resource-fixture-"+nonce+".json")},
        new[]{"hash-object","--",Path.Combine(workspace,"all-packages-only.json")}};
    foreach(var tail in tails)Validate("git",(ProcessStartInfo)Call(git,"Start",workspace,directory,tail)!);
    foreach(var tail in new[]{new[]{"config","--global","test.value","x"},new[]{"clone","https://example.invalid/repo"},new[]{"-C","C:\\outside","status"},new[]{"-c","core.hooksPath=C:\\outside","commit"}})
        Refuse(()=>Validate("git",(ProcessStartInfo)Call(git,"Start",workspace,directory,tail)!),"OwnedGitCompiledOperationRequired");
    var changed=(ProcessStartInfo)Call(git,"Start",workspace,directory,new[]{"hash-object","--stdin"})!;changed.ArgumentList[2]="credential.helper=unapproved";
    Refuse(()=>Validate("git",changed),"OwnedGitConfigurationRequired");
    Console.WriteLine("PASS production owner-start policy accepts only compiled PowerShell/Git operations and exact environments; rejects arbitrary code/config/remote/host paths; no process or private-state access");return 0;
}
var request=JsonSerializer.Serialize(new{SchemaVersion=1,Scope="OWNED_TOOL_START_REQUEST",Nonce=nonce,RootPid=Environment.ProcessId,Sequence=1,Kind="powershell",Arguments=powerShell.ArgumentList.ToArray(),StartSHA256=Digest(powerShell)});
string Read(string data)
{
    var instance=Activator.CreateInstance(launch,true)!;
    using var bytes=new MemoryStream(Encoding.UTF8.GetBytes(data));using var reader=new StreamReader(bytes);
    var task=(Task<string>)launch.GetMethod("ReadMessages",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(instance,new object[]{reader})!;
    return task.GetAwaiter().GetResult();
}
Require(Read(request+"\n{\"SchemaVersion\":1,\"Pid\":123}\n")=="{\"SchemaVersion\":1,\"Pid\":123}","request plus distinct terminal report parsed");
Refuse(()=>Read(request+"\n"+request+"\n"),"OnlyOneOwnedToolRequestAtATime");
Refuse(()=>Read(request+"\n"),"OwnedToolPipeClosedWithoutTerminalReport");
Refuse(()=>Read(new string('x',16385)+"\n"),"OwnedToolMessageBounds");
var unknown=request[..^1]+",\"ArbitraryCommand\":true}";
var rejected=false;try{Read(unknown+"\n");}catch(InvalidDataException){rejected=true;}Require(rejected,"unknown request field rejected");
Console.WriteLine("PASS production bounded report-pipe parser separates tool requests from terminal evidence and rejects oversized, duplicate pending, truncated and unknown-field messages; no IPC or native process execution");return 0;

[DllImport("kernel32.dll",SetLastError=true)] static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint pid);
[DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool CreatePipe(out SafeFileHandle read,out SafeFileHandle write,IntPtr attributes,uint size);
[DllImport("ntdll.dll")] static extern int NtQueryObject(SafeProcessHandle handle,int information,IntPtr buffer,int length,out int needed);
[DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool GetHandleInformation(IntPtr handle,out uint flags);
