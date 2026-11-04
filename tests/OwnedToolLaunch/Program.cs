using System.Diagnostics;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Text;
using System.Text.Json;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

if(args.Length!=1 || args[0] is not ("gpu-report-policy" or "privacy-probe-closure" or "privacy-probe-exit-child" or "timezone-snapshot" or "timezone-policy" or "timezone-metadata" or "gateway-feedback" or "gateway-qualification-boundary" or "policy" or "messages" or "handle-transfer" or "fault-mode" or "fault-mode-read" or "partial-output" or "hosted-policy" or "etw-policy" or "tls-transport-policy" or "etw-token-access" or "inactive-transition" or "project-policy" or "project-build" or "privacy-native" or "caller-project-build" or "caller-project-policy" or "self-control-open" or "caller-data-build" or "caller-compile-failure" or "caller-run-failure" or "caller-test-failure" or "caller-output-failure" or "caller-failure-owner" or "control-file-gate" or "caller-multi-edit-build" or "workspace-caller-lifetime" or "workspace-caller-lifetime-child" or "maintenance-identity" or "reset-settings-file"))return 125;
try
{
using var identity=WindowsIdentity.GetCurrent();
if(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))throw new InvalidOperationException("Ordinary qualification only");
if(args[0]=="workspace-caller-lifetime-child"){Console.WriteLine("READY");Console.ReadLine();return 259;}
if(args[0]=="privacy-probe-exit-child"){Console.WriteLine("READY");Console.ReadLine();return 0;}
var library=Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory,"ProtectionLifecycle.dll"));
if(args[0]=="privacy-probe-closure"){PrivacyProbeClosureCases.Run(library,(access,pid)=>OpenProcess(access,false,pid));return 0;}
if(args[0] is "timezone-policy" or "timezone-metadata"){TimeZoneReadCases.Run(library,args[0]=="timezone-metadata");return 0;}
if(args[0]=="timezone-snapshot"){TimeZoneReadCases.RunSnapshot(library);return 0;}
if(args[0]=="gateway-feedback"){GatewayFeedbackCases.Run(library);return 0;}
if(args[0]=="gateway-qualification-boundary"){GatewayQualificationBoundaryCases.Run(library);return 0;}
if(args[0]=="reset-settings-file"){ResetSettingsFileCases.Run(library);return 0;}
if(args[0]=="maintenance-identity"){MaintenanceIdentityCases.Run(library);return 0;}
if(args[0]=="workspace-caller-lifetime"){WorkspaceCallerLifetimeCases.Run(library,(access,pid)=>OpenProcess(access,false,pid));return 0;}
if(args[0]=="control-file-gate"){ControlFileGateCases.Run(library);return 0;}
if(args[0] is "caller-compile-failure" or "caller-run-failure" or "caller-test-failure" or "caller-output-failure" or "caller-failure-owner")
{ProjectFailureExecutionCases.Run(library,args[0]);return 0;}
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
if(args[0]=="gpu-report-policy")
{
    var qualification=library.GetType("ProtectionLifecycle.GpuQualification",true)!;
    var reportType=library.GetType("ProtectionLifecycle.GpuChildReport",true)!;
    var hash=(string)qualification.GetProperty("ExpectedHash",flags)!.GetValue(null)!;var gpuNonce=new string('a',32);
    var steps=new[]{"cuInit","cuDriverGetVersion","cuDeviceGetCount","cuDeviceGet","cuDeviceGetName","cuCtxCreate_v2",
        "cuMemAlloc_v2","cuMemcpyHtoD_v2","cuModuleLoadData","cuModuleGetFunction","cuLaunchKernel","cuCtxSynchronize","cuMemcpyDtoH_v2",
        "cuModuleUnload","cuMemFree_v2","cuCtxDestroy_v2"}.Select(stage=>new{Stage=stage,Result=0}).ToArray();
    object Receipt(string scope,int pid,int? driver=12080,string? model="Synthetic GPU model")=>JsonSerializer.Deserialize(JsonSerializer.Serialize(new
    {
        SchemaVersion=1,Pid=pid,Nonce=gpuNonce,Scope=scope,DriverVersion=driver,Device=model,AllocatedBytes=1024,Elements=256,
        ResultSHA256=hash,ComputeMatched=true,ResourceCleanupSucceeded=true,Steps=steps,FailureType=(string?)null
    }),reportType)!;
    const string lpac="LPAC_LOW_ZERO_CAPABILITIES";
    var host=Receipt("HOST_CONTROL",111);
    bool Qualifies(object receipt,uint pid=222,uint exit=0,string? expectedNonce=null)=>
        Call(qualification,"QualifiedChild",receipt,expectedNonce??gpuNonce,pid,exit,host) is true;
    Require(Qualifies(Receipt(lpac,222)),"bound LPAC report accepted");
    Require(!Qualifies(Receipt("APPCONTAINER_LOW_ZERO_CAPABILITIES",222)),"old ordinary AppContainer evidence cannot qualify LPAC");
    Require(!Qualifies(Receipt(lpac,333)) && !Qualifies(Receipt(lpac,222),exit:3) &&
        !Qualifies(Receipt(lpac,222),expectedNonce:new string('b',32)),"wrong process, exit and nonce refused");
    Require(!Qualifies(Receipt(lpac,222,12090)) && !Qualifies(Receipt(lpac,222,null)) && !Qualifies(Receipt(lpac,222,12080,"")) &&
        !Qualifies(Receipt(lpac,222,12080,"invalid\nmodel")),"mismatched driver and missing or invalid metadata refused");
    Console.WriteLine("PASS fixed GPU report binding: LPAC scope, child PID/nonce/exit, matching driver and bounded model; synthetic only, no CUDA or LPAC execution");return 0;
}
if(args[0]=="self-control-open")
{
    var probe=library.GetType("ProtectionLifecycle.HostPrivacyProbe",true)!;
    for(var index=14;index<23;index++)
    {
        Call(probe,"RequireOwnerTarget","",Environment.ProcessId,Environment.ProcessId,index);
        Require((int)Call(probe,"OwnerAccessOpen",Environment.ProcessId,index)! ==0,"ordinary self maintenance minimal-right positive control "+index);
    }
    Refuse(()=>Call(probe,"RequireOwnerTarget","",Environment.ProcessId+1,Environment.ProcessId,15),"ProtectionOwnerTargetBindingDiffers");
    Refuse(()=>Call(probe,"RequireOwnerTarget","supplied-host-path",Environment.ProcessId,Environment.ProcessId,15),"ProtectionOwnerTargetBindingDiffers");
    Refuse(()=>Call(probe,"RequireOwnerTarget","",0,0,15),"ProtectionOwnerTargetBindingDiffers");
    Refuse(()=>Call(probe,"OwnerAccessOpen",0,15),"ProtectionOwnerProcessRequired");
    var unknownOwnerRight=false;try{Call(probe,"OwnerAccessOpen",Environment.ProcessId,23);}catch(InvalidDataException){unknownOwnerRight=true;}
    Require(unknownOwnerRight,"undefined right rejected before native open");
    Console.WriteLine("PASS nine minimal process-right opens on this own ordinary test process; owner binding, foreign PID/path/identity, zero PID and undefined right checked. Handles closed unused; no process memory read/write, termination, suspension, injection, duplication, ACL change, host target, UAC, Broker/Job or LPAC test");return 0;
}
if(args[0] is "caller-project-build" or "caller-project-policy" or "caller-data-build" or "caller-multi-edit-build")
{
    var dataProjectFixture=args[0]=="caller-data-build";
    var multiEditFixture=args[0]=="caller-multi-edit-build";
    var bundleType=library.GetType("ClaudeCodeProtection.Workspaces.WorkspaceBundle",true)!;
    var taskType=library.GetType("ClaudeCodeProtection.Workspaces.CSharpProjectTask",true)!;
    var executor=library.GetType("ProtectionLifecycle.CallerCSharpProject",true)!;
    var files=library.GetType("ClaudeCodeProtection.Workspaces.WorkspaceFiles",true)!;
    var fixtureNames=dataProjectFixture?new[]{"cpc-project.json","src/Entry.cs","tests/Checks.cs","data/values.json","README.md"}:
        new[]{"cpc-project.json","src/Counter.cs","src/Entry.cs","tests/Checks.cs","README.md"};
    var fixtureData=fixtureNames.Select(name=>
    {
        using var resource=Assembly.GetExecutingAssembly().GetManifestResourceStream((dataProjectFixture?"DataFixture.":"CallerFixture.")+name)??throw new InvalidDataException("Missing caller fixture");
        using var bytes=new MemoryStream();resource.CopyTo(bytes);return (name,bytes.ToArray());
    }).ToArray();
    if(multiEditFixture)
    {
        var manifestIndex=Array.FindIndex(fixtureData,f=>f.name=="cpc-project.json");
        var manifest=System.Text.Json.Nodes.JsonNode.Parse(fixtureData[manifestIndex].Item2)!.AsObject();
        manifest["Edits"]!.AsArray().Add(new System.Text.Json.Nodes.JsonObject{
            ["Path"]="tests/Checks.cs",["Before"]="return 3;",["After"]="if(Counter.CountWords(\"  one   two  \")!=2)throw new Exception(\"repeated spaces\"); return 4;"});
        manifest["ExpectedTests"]=4;
        fixtureData[manifestIndex]=("cpc-project.json",Encoding.UTF8.GetBytes(manifest.ToJsonString()));
    }
    var bundle=Call(bundleType,"Create",fixtureData,null)!;
    var baseline=(byte[])bundleType.GetMethod("Serialize",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(bundle,null)!;
    var task=Call(taskType,"Parse",baseline)!;
    var callerPlanType=library.GetType("ProtectionLifecycle.ResourceProbePlan",true)!;
    var hash=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(baseline));
    var callerNonce=new string('d',32);var callerProgramFiles=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    var callerPlan=Activator.CreateInstance(callerPlanType,6,callerNonce,new string('b',32),new string('c',32),Environment.ProcessId,new string('A',64),
        "9DE2A6DB90D8383F3738249D52F30DEFBEDB994513A8F2697E9D90693CD1D285",hash,callerProgramFiles)!;
    callerPlanType.GetProperty("DevelopProject")!.SetValue(callerPlan,true);callerPlanType.GetProperty("HostPrivacySHA256")!.SetValue(callerPlan,new string('F',64));
    var selectedCallerKind=dataProjectFixture?"CSHARP_LITERAL_EDIT_DATA_BUILD_RUN_TEST_V2":"CSHARP_LITERAL_EDIT_BUILD_RUN_TEST_V1";
    callerPlanType.GetProperty("CallerProjectKind")!.SetValue(callerPlan,selectedCallerKind);
    var project=library.GetType("ProtectionLifecycle.BundledProjectDevelopment",true)!;
    var callerWorkspace=Path.Combine(callerProgramFiles,"ClaudeCodeProtection-Task-"+callerNonce);
    var start=(ProcessStartInfo)Call(project,"StartFixed",callerPlan,callerWorkspace,111,false)!;
    _=Call(launch,"ValidateStart",callerPlan,callerWorkspace,"project",start.ArgumentList.ToArray(),Call(launch,"StartHash",start)!);
    _=Call(callerPlanType,"Parse",JsonSerializer.Serialize(callerPlan,callerPlanType));
    callerPlanType.GetProperty("CallerProjectKind")!.SetValue(callerPlan,"OTHER_EXECUTOR");
    Refuse(()=>Call(project,"StartFixed",callerPlan,callerWorkspace,111,false),"ResourceQualificationPlanRefused");
    callerPlanType.GetProperty("CallerProjectKind")!.SetValue(callerPlan,selectedCallerKind);
    callerPlanType.GetProperty("SchemaVersion")!.SetValue(callerPlan,5);
    Refuse(()=>Call(project,"StartFixed",callerPlan,callerWorkspace,111,false),"ResourceQualificationPlanRefused");
    if(args[0]=="caller-project-policy"){Console.WriteLine("PASS explicit caller v6 kind, input/privacy digest and original fixed tool start; wrong kind and v5 mixing refused; no product/Job/code execution");return 0;}
    var fixture=Path.Combine(AppContext.BaseDirectory,"ordinary-caller-project-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(fixture);
    Call(files,"MaterializeNew",fixture,"project",baseline);
    var callerBeforeDirectory=Environment.CurrentDirectory;
    Call(executor,"BuildAndRun",Path.Combine(callerProgramFiles,"ClaudeCodeProtection-PowerShell-7.4.22"),Path.Combine(fixture,"project"),baseline);
    Require(Environment.CurrentDirectory==callerBeforeDirectory,"ordinary caller execution restores prior working directory");
    var result=(byte[])Call(files,"SnapshotResult",fixture,"project",baseline)!;
    try{taskType.GetMethod("VerifyResult",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(task,new object[]{result});}
    catch(TargetInvocationException error)when(error.InnerException is not null){ExceptionDispatchInfo.Capture(error.InnerException).Throw();throw;}
    Call(files,"ExtractResultNew",Path.Combine(fixture,"exported"),baseline,result);
    if(dataProjectFixture)
    {
        Require(File.ReadAllText(Path.Combine(fixture,"exported","cpc-results","summary.json"))=="{\"Count\":3,\"Total\":12}" &&
            File.ReadAllBytes(Path.Combine(fixture,"exported","data","values.json")).AsSpan().SequenceEqual(fixtureData.Single(f=>f.name=="data/values.json").Item2) &&
            File.ReadAllText(Path.Combine(fixture,"exported","cpc-output","test-result.txt"))=="3","selected data, generated JSON, unchanged input and three tests");
        Console.WriteLine("PASS ordinary CallerDataReport: explicit data/result V2 intent and original fixed tool binding, actual Roslyn compile/run/three tests, eleven-file snapshot/verify/extract, Count=3 Total=12, unchanged data and restored CWD. No protected product/LPAC/Job/UAC/network/host probes; fixture="+fixture);return 0;
    }
    Require(File.ReadAllText(Path.Combine(fixture,"exported","cpc-output","stdout.txt"))=="words=3" &&
        File.ReadAllText(Path.Combine(fixture,"exported","cpc-output","test-result.txt"))==(multiEditFixture?"4":"3") &&
        File.ReadAllText(Path.Combine(fixture,"exported","src","Counter.cs")).Contains("StringSplitOptions.RemoveEmptyEntries"),"caller literal edit, run, three tests and extraction");
    Require(!AppDomain.CurrentDomain.GetAssemblies().Any(a=>a.GetName().Name=="System.Management.Automation"),"caller project never loaded PowerShell");
    if(multiEditFixture)
    {
        Require(File.ReadAllText(Path.Combine(fixture,"exported","tests","Checks.cs")).Contains("repeated spaces"),"test source edit survives exact result verification and extraction");
        Console.WriteLine("PASS ordinary multi-file task: implementation and test edited together, pinned Roslyn compile/run, four tests, ten-file verification/extraction. No LPAC/Job/UAC/product/host probes/network; fixture="+fixture);return 0;
    }
    Console.WriteLine("PASS ordinary reviewed CallerWordCount: explicit manifest, three source files, exact edit, pinned Roslyn compile, entry words=3, three tests, ten-file snapshot/verification/extraction; no PowerShell/MSBuild/project imports/network/LPAC/Job/UAC/real host probes; fixture="+fixture);return 0;
}
if(args[0]=="privacy-native")
{
    var probe=library.GetType("ProtectionLifecycle.HostPrivacyProbe",true)!;
    var folder=Path.Combine(AppContext.BaseDirectory,"privacy-own-file-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);
    var path=Path.Combine(folder,"non-secret.txt");File.WriteAllText(path,"OWN_NON_SECRET_NATIVE_READ_OPEN_FIXTURE");
    var before=File.ReadAllBytes(path);var identityBefore=(string)Call(probe,"FileIdentity",path)!;
    Require((int)Call(probe,"FileReadOpen",path)! ==0,"own allowed FILE_READ_DATA open");
    var acl=new FileInfo(path).GetAccessControl();var original=acl.GetSecurityDescriptorBinaryForm();
    File.WriteAllBytes(Path.Combine(folder,"original-security.bin"),original);
    try
    {
        acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(identity.User!,System.Security.AccessControl.FileSystemRights.ReadData,System.Security.AccessControl.AccessControlType.Deny));
        new FileInfo(path).SetAccessControl(acl);
        Require((int)Call(probe,"FileReadOpen",path)! ==5,"exact own ReadData deny observed");
        Require((string)Call(probe,"FileIdentity",path)! ==identityBefore,"metadata positive control still succeeds while ReadData denied");
    }
    finally
    {
        var restore=new System.Security.AccessControl.FileSecurity();restore.SetSecurityDescriptorBinaryForm(original,AccessControlSections.Access);new FileInfo(path).SetAccessControl(restore);
    }
    Require(new FileInfo(path).GetAccessControl().GetSecurityDescriptorBinaryForm().AsSpan().SequenceEqual(original),"own fixture DACL restored exactly");
    Require(File.ReadAllBytes(path).AsSpan().SequenceEqual(before),"no fixture content changed by native opens");
    Require((int)Call(probe,"FileReadOpen",Path.Combine(folder,"absent.txt"))! ==2,"absence stays actual native error, never denial");
    Require((int)Call(probe,"ProcessReadOpen",Environment.ProcessId)! ==0,"own process VM_READ handle only, no memory read");
    using(var self=Process.GetCurrentProcess())Require((bool)Call(probe,"ProcessAlive",self.SafeHandle)!,"actual own wait object alive, not exit-code259 inference");
    Console.WriteLine("PASS actual native own-file read-data allow/deny, metadata-only positive control, absence2, exact own DACL restoration and unchanged bytes; own VM_READ handle only. No real host target/key/process, content/memory read, UAC, product or LPAC qualification");return 0;
}
if(args[0] is "project-policy" or "project-build")
{
    var project=library.GetType("ProtectionLifecycle.BundledProjectDevelopment",true)!;
    var baseline=(byte[])Call(project,"Baseline")!;
    var hash=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(baseline));
    var projectPlanType=library.GetType("ProtectionLifecycle.ResourceProbePlan",true)!;
    var roots=library.GetType("ProtectionLifecycle.SessionResources",true)!;
    var projectNonce=new string('e',32);var projectProgramFiles=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    object Plan(int schema,bool development,string input)
    {
        var valuePlan=Activator.CreateInstance(projectPlanType,schema,projectNonce,new string('b',32),new string('c',32),Environment.ProcessId,new string('A',64),
            "9DE2A6DB90D8383F3738249D52F30DEFBEDB994513A8F2697E9D90693CD1D285",input,projectProgramFiles)!;
        projectPlanType.GetProperty("DevelopProject")!.SetValue(valuePlan,development);
        if(development)projectPlanType.GetProperty("HostPrivacySHA256")!.SetValue(valuePlan,new string('F',64));return valuePlan;
    }
    var development=Plan(5,true,hash);var data=Plan(3,false,hash);
    var projectWorkspace=Path.Combine(projectProgramFiles,"ClaudeCodeProtection-Task-"+projectNonce);
    var start=(ProcessStartInfo)Call(project,"StartFixed",development,projectWorkspace,111,false)!;
    var digest=(string)Call(launch,"StartHash",start)!;
    _=Call(launch,"ValidateStart",development,projectWorkspace,"project",start.ArgumentList.ToArray(),digest);
    var probeStart=(ProcessStartInfo)Call(project,"StartFixed",development,projectWorkspace,111,true)!;
    _=Call(launch,"ValidateStart",development,projectWorkspace,"project-probe",probeStart.ArgumentList.ToArray(),Call(launch,"StartHash",probeStart)!);
    Refuse(()=>Call(launch,"ValidateStart",development,projectWorkspace,"project",probeStart.ArgumentList.ToArray(),Call(launch,"StartHash",probeStart)!),"OwnedProjectCompiledProgramRequired");
    Refuse(()=>Call(launch,"ValidateStart",development,projectWorkspace,"project-probe",start.ArgumentList.ToArray(),digest),"OwnedProjectCompiledProgramRequired");
    Refuse(()=>Call(project,"StartFixed",development,projectWorkspace,0,true),"ProjectFixedRootRequired");
    Refuse(()=>Call(project,"StartFixed",development,projectWorkspace,Environment.ProcessId,true),"ProjectFixedRootRequired");
    Refuse(()=>Call(project,"StartFixed",data,projectWorkspace,111,false),"ExplicitProjectDevelopmentRequired");
    Refuse(()=>Call(launch,"ValidateStart",data,projectWorkspace,"project",start.ArgumentList.ToArray(),digest),"ExplicitProjectDevelopmentRequired");
    Refuse(()=>Call(project,"StartFixed",Plan(3,true,hash),projectWorkspace,111,false),"ResourceQualificationPlanRefused");
    Refuse(()=>Call(project,"StartFixed",Plan(4,true,hash),projectWorkspace,111,false),"ResourceQualificationPlanRefused");
    Refuse(()=>Call(project,"StartFixed",Plan(5,true,new string('D',64)),projectWorkspace,111,false),"FixedDevelopmentProjectPlanRequired");
    var missingPrivacy=Plan(5,true,hash);projectPlanType.GetProperty("HostPrivacySHA256")!.SetValue(missingPrivacy,null);
    Refuse(()=>Call(project,"StartFixed",missingPrivacy,projectWorkspace,111,false),"ResourceQualificationPlanRefused");
    Refuse(()=>Call(roots,"PowerShellStart",development,projectWorkspace),"WorkspaceDataCannotRequestPowerShell");
    var changed=start.ArgumentList.ToArray();changed[1]=new string('f',32);
    Refuse(()=>Call(launch,"ValidateStart",development,projectWorkspace,"project",changed,digest),"OwnedProjectCompiledProgramRequired");
    Require(!start.Environment.ContainsKey("PSModulePath") && !start.Environment.ContainsKey("CPC_POWERSHELL_POLICY_NONCE"),"project compile does not impersonate a PowerShell host");
    _=Call(projectPlanType,"Parse",JsonSerializer.Serialize(development,projectPlanType));
    var unknownProjectField=JsonSerializer.Serialize(data,projectPlanType).TrimEnd('}')+",\"DevelopProject\":false}";
    var projectFieldRejected=false;try{Call(projectPlanType,"Parse",unknownProjectField);}catch(InvalidDataException){projectFieldRejected=true;}Require(projectFieldRejected,"v3 DATA rejects the added development field even when false");
    if(args[0]=="project-policy"){Console.WriteLine("PASS explicit v5 fixed project intent plus mandatory privacy digest/start binding; old v4/missing privacy refused; v3 DATA cannot execute project code, no PowerShell fallback or host-path grant; pure policy only");return 0;}
    var fixture=Path.Combine(AppContext.BaseDirectory,"ordinary-text-summary-project");
    Require(!Directory.Exists(fixture),"new own project fixture only");Directory.CreateDirectory(fixture);
    var files=library.GetType("ClaudeCodeProtection.Workspaces.WorkspaceFiles",true)!;
    Call(files,"MaterializeNew",fixture,"project",baseline);
    Call(project,"BuildAndRun",Path.Combine(projectProgramFiles,"ClaudeCodeProtection-PowerShell-7.4.22"),Path.Combine(fixture,"project"));
    var result=(byte[])Call(files,"SnapshotResult",fixture,"project",baseline)!;Call(project,"VerifyResult",result);
    Call(files,"ExtractResultNew",Path.Combine(fixture,"exported"),baseline,result);
    Require(File.ReadAllText(Path.Combine(fixture,"exported","test-result.txt"))=="6" &&
        File.ReadAllText(Path.Combine(fixture,"exported","run-result.json"))=="{\"Lines\":2,\"Words\":5}","modified source compiled/executed/tested and result extracted");
    Require(!library.GetReferencedAssemblies().Any(a=>a.Name=="System.Management.Automation") && !AppDomain.CurrentDomain.GetAssemblies().Any(a=>a.GetName().Name=="System.Management.Automation"),"compile/run task never loaded PowerShell engine");
    Console.WriteLine("PASS ordinary real TextSummary project: read source, add CountWords and three cases, compile pinned Roslyn, execute six tests and counters, snapshot/verify/extract result; NOT LPAC/Job/host-privacy qualification");return 0;
}
if(args[0]=="inactive-transition")
{
    var lease=library.GetType("ProtectionLifecycle.BootstrapInstaller",true)!
        .GetNestedType("PinnedInactiveUpdateLease",BindingFlags.NonPublic)!;
    const string actualRelease="8aee9af022fe4808a6c0261df1eb9580";
    const string actualManifest="BC53B2C0BA82C668A9D3C2CC4B234EA90FF8E1A51E2DD9BEE6EC6373D0FB5093";
    // The replacement is a fixture selection, not an approved package or
    // installed transition. This executes only the real pure selection guard.
    var replacementRelease=new string('a',32);var replacementManifest=new string('A',64);
    void Check(string currentRelease,string currentManifest,string priorRelease,string priorManifest,string nextRelease,string nextManifest)
        =>Call(lease,"RequirePinnedTransition",currentRelease,currentManifest,priorRelease,priorManifest,nextRelease,nextManifest);
    void Deny(Action check)
    {
        var refused=false;try{check();}catch(InvalidOperationException error)when(error.Message=="Only pinned reviewed inactive packages can migrate"){refused=true;}
        Require(refused,"inactive selection must refuse changed, unknown or same-package transitions");
    }
    Check(actualRelease,actualManifest,actualRelease,actualManifest,replacementRelease,replacementManifest);
    Deny(()=>Check(replacementRelease,actualManifest,actualRelease,actualManifest,replacementRelease,replacementManifest));
    Deny(()=>Check(actualRelease,replacementManifest,actualRelease,actualManifest,replacementRelease,replacementManifest));
    Deny(()=>Check(actualRelease,actualManifest,actualRelease,actualManifest,actualRelease,replacementManifest));
    Deny(()=>Check(actualRelease,actualManifest,actualRelease,actualManifest,replacementRelease,actualManifest));
    Deny(()=>Check(actualRelease,replacementManifest,actualRelease,replacementManifest,replacementRelease,new string('B',64)));
    Deny(()=>Check(actualRelease,actualManifest.ToLowerInvariant(),actualRelease,actualManifest.ToLowerInvariant(),replacementRelease,replacementManifest));
    Console.WriteLine($"PASS actual installed{actualRelease[..8]} exact pinned inactive selection and six current/prior/next/unknown/case drift refusals; pure production guard only, not live Job closure, maintenance, installation or UAC");return 0;
}
if(args[0]=="etw-token-access")
{
    var atomic=library.GetType("ProtectionLifecycle.AtomicChild",true)!;
    using var self=new SafeProcessHandle((IntPtr)(-1),false);
    object Check(string descriptor)=>Call(atomic,"ObserveTokenRegisterAccess",self,descriptor)!;
    object? Value(object value,string name)=>value.GetType().GetProperty(name)!.GetValue(value);
    var allowed=Check("O:SYG:SYD:P(A;;0x800;;;WD)");var denied=Check("O:SYG:SYD:P");
    Require((bool)Value(allowed,"ApiSucceeded")! && (bool)Value(allowed,"AccessAllowed")! && (uint)Value(allowed,"GrantedMask")! == 0x800 && Value(allowed,"ApiError") is null,
        "documented AccessCheck succeeds for register-only World grant on own ordinary token");
    Require((bool)Value(denied,"ApiSucceeded")! && !(bool)Value(denied,"AccessAllowed")! && (uint)Value(denied,"GrantedMask")! == 0 && Value(denied,"ApiError") is null,
        "access-denied result is distinct from an AccessCheck API failure");
    Require((string)Value(allowed,"DescriptorSHA256")! != (string)Value(denied,"DescriptorSHA256")!,"observations bind to the exact input SD bytes");
    Console.WriteLine("PASS own ordinary-token register-only AccessCheck allow/deny and descriptor binding; no ETW query, grant, other-process open, Job or product entry; not LPAC qualification");return 0;
}
if(args[0]=="tls-transport-policy")
{
    var channel=library.GetType("ProtectionLifecycle.ProxyChannelLease",true)!;
    System.Net.Http.SocketsHttpHandler Handler(object? observe=null)=>(System.Net.Http.SocketsHttpHandler)Call(channel,"CreateTransportHandler",observe,null,null)!;
    using var first=Handler();
    Require(first.UseProxy && first.Proxy is System.Net.WebProxy proxy && proxy.Address?.AbsoluteUri=="http://127.0.0.1:7890/" &&
        !first.AllowAutoRedirect && !first.UseCookies && first.Credentials is null && first.DefaultProxyCredentials is null,"fixed explicit proxy without ambient credentials or redirect");
    var options=first.SslOptions;
    Require(options.CertificateRevocationCheckMode==System.Security.Cryptography.X509Certificates.X509RevocationMode.Offline &&
        options.CertificateChainPolicy is {DisableCertificateDownloads:true,RevocationMode:System.Security.Cryptography.X509Certificates.X509RevocationMode.Offline,
            VerificationFlags:System.Security.Cryptography.X509Certificates.X509VerificationFlags.NoFlag},"chain policy must prevent online revocation and AIA BEFORE validation callback");
    Require(options.RemoteCertificateValidationCallback is null && !options.AllowTlsResume && !options.AllowRenegotiation,
        "platform certificate/name validation on a fresh handshake without renegotiation");
    options.CertificateChainPolicy!.RevocationMode=System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
    using var second=Handler();
    Require(!ReferenceEquals(first.SslOptions,second.SslOptions) && !ReferenceEquals(first.SslOptions.CertificateChainPolicy,second.SslOptions.CertificateChainPolicy) &&
        second.SslOptions.CertificateChainPolicy!.RevocationMode==System.Security.Cryptography.X509Certificates.X509RevocationMode.Offline,"each transport gets an independent strict policy");
    var observations=0;Action<object> observed=_=>observations++;
    var callback=Delegate.CreateDelegate(typeof(Action<>).MakeGenericType(library.GetType("ProtectionLifecycle.TlsValidationObservation",true)!),observed.Target,observed.Method);
    using var diagnostic=Handler(callback);
    Require(diagnostic.SslOptions.RemoteCertificateValidationCallback is not null &&
        !diagnostic.SslOptions.RemoteCertificateValidationCallback(new object(),null,null,System.Net.Security.SslPolicyErrors.None) && observations==0,
        "diagnostic callback refuses a sender outside the fixed TLS transport without a CRL or network attempt");
    Console.WriteLine("PASS actual transport factory: explicit proxy, strict offline revocation/no AIA before callback, independent policies, platform default validation and wrong-context callback refusal; no requests, sockets or certificate-store changes");return 0;
}
if(args[0]=="etw-policy")
{
    var type=library.GetType("ProtectionLifecycle.SessionEtwProviderAccess",true)!;
    var prefix=(string)type.GetField("Prefix",flags)!.GetRawConstantValue()!;
    var state=library.GetType("ProtectionLifecycle.ProtectedState",true)!;
    Call(state,"RequireFixedInventoryPrefix",prefix);
    var unknownRefused=false;
    try{Call(state,"RequireFixedInventoryPrefix",prefix+"arbitrary-");}
    catch(InvalidOperationException ex)when(ex.Message=="Fixed inventory prefix required"){unknownRefused=true;}
    Require(unknownRefused,"ETW caller inventory accepted without allowing arbitrary prefixes");
    var original=(string)type.GetField("ObservedDefault",BindingFlags.NonPublic|BindingFlags.Static)!.GetRawConstantValue()!;
    var sid="S-1-15-2-101-102-103-104-105-106-107";
    var granted=(string)Call(type,"AddRegisterAce",original,sid)!;
    var originalSd=new System.Security.AccessControl.RawSecurityDescriptor(original);
    var grantedSd=new System.Security.AccessControl.RawSecurityDescriptor(granted);
    Require(grantedSd.DiscretionaryAcl!.Count==originalSd.DiscretionaryAcl!.Count+1,"only one exact provider ACE added");
    var added=(System.Security.AccessControl.CommonAce)grantedSd.DiscretionaryAcl[^1];
    Require(added.SecurityIdentifier.Value==sid && added.AccessMask==0x800 && added.AceFlags==0 && added.AceQualifier==System.Security.AccessControl.AceQualifier.AccessAllowed,"register only: no query, consume, controller or blanket package rights");
    Require((bool)Call(type,"IsExactGrant",granted,original,sid)!,"exact one ACE accepted");
    var moved=new System.Security.AccessControl.RawSecurityDescriptor(granted);var last=moved.DiscretionaryAcl![^1];moved.DiscretionaryAcl.RemoveAce(moved.DiscretionaryAcl.Count-1);moved.DiscretionaryAcl.InsertAce(0,last);
    Require((bool)Call(type,"IsExactGrant",moved.GetSddlForm(System.Security.AccessControl.AccessControlSections.All),original,sid)!,"native insertion position can vary without accepting other changes");
    Require((string)Call(type,"RestoreDecision",original,null,original,sid,null)! == "ALREADY_ORIGINAL_DEFAULT","no-write intent remains original only with persisted value absent");
    Require((string)Call(type,"RestoreDecision",granted,new string('A',64),original,sid,null)! == "REMOVE_ONLY_OWN_NEW_OVERRIDE","interrupted-before-grant-receipt exact own addition recoverable");
    Refuse(()=>Call(type,"RestoreDecision",original,new string('A',64),original,sid,null),"EtwSecurityDriftRequiresHumanResolution");
    Refuse(()=>Call(type,"AddRegisterAce",original,"S-1-15-2-1"),"EtwExactPackageSidRequired");
    Refuse(()=>Call(type,"AddRegisterAce",original,"S-1-15-2-2"),"EtwExactPackageSidRequired");
    Refuse(()=>Call(type,"AddRegisterAce",original+"(A;;0x800;;;BU)",sid),"EtwUnreviewedDefaultSecurity");
    foreach(var mask in new[]{0x1800,0x400,0x200,0x120fff})
    {
        var drift=new System.Security.AccessControl.RawSecurityDescriptor(granted);((System.Security.AccessControl.CommonAce)drift.DiscretionaryAcl![^1]).AccessMask=mask;
        Require(!(bool)Call(type,"IsExactGrant",drift.GetSddlForm(System.Security.AccessControl.AccessControlSections.All),original,sid)!,"expanded or replaced right rejected");
    }
    var grantType=library.GetType("ProtectionLifecycle.EtwAccessGrant",true)!;
    var receipt=Activator.CreateInstance(grantType,1,new string('b',32),new string('c',32),new string('D',64),granted,new string('A',64));
    Refuse(()=>Call(type,"RestoreDecision",granted,new string('E',64),original,sid,receipt),"EtwSecurityDriftRequiresHumanResolution");
    Console.WriteLine("PASS exact provider register-only ACE, unchanged original rights, default absence, interrupted grant, recorded hash drift and no broad SID/controller/read grants; no native ETW mutation");return 0;
}
if(args[0]=="fault-mode-read")
{
    var mode=(uint)Call(library.GetType("ProtectionLifecycle.ToolFaultMode",true)!,"CurrentMode")!;
    Console.WriteLine(mode);return (mode&0x8003)==0x8003?0:3;
}
if(args[0]=="fault-mode")
{
    var mode=library.GetType("ProtectionLifecycle.ToolFaultMode",true)!;
    var before=(uint)Call(mode,"CurrentMode")!;
    using((IDisposable)Call(mode,"Enter")!)
    {
        Require((uint)Call(mode,"CurrentMode")! == (before|0x8003),"own process error mode only");
        var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=AppContext.BaseDirectory};
        foreach(var argument in new[]{"exec","--fx-version","8.0.28",typeof(Program).Assembly.Location,"fault-mode-read"})start.ArgumentList.Add(argument);
        start.Environment.Clear();foreach(var name in new[]{"SystemRoot","windir","TEMP","TMP"}){var value=Environment.GetEnvironmentVariable(name);if(value is not null)start.Environment[name]=value;}
        using var child=Process.Start(start)!;var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();
        if(!child.WaitForExit(4000)){child.Kill();throw new InvalidDataException("Ordinary own mode-reader deadline");}
        Require(stdout.Wait(1000) && stderr.Wait(1000) && child.ExitCode==0 && stderr.Result.Length==0 && uint.Parse(stdout.Result.Trim())==(before|0x8003),"actual own child inherits noninteractive failure mode");
    }
    Require((uint)Call(mode,"CurrentMode")! == before,"exact prior mode restored after normal creation");
    try{using var scope=(IDisposable)Call(mode,"Enter")!;throw new InvalidOperationException("owned fixture exception");}catch(InvalidOperationException){}
    Require((uint)Call(mode,"CurrentMode")! == before,"exact prior mode restored after exception");
    Console.WriteLine("PASS own error-mode scope, exact restoration on success/failure and one ordinary own child inheritance; no induced crash or host setting change");return 0;
}
if(args[0]=="partial-output")
{
    var captureType=library.GetType("ProtectionLifecycle.ToolOutputCapture",true)!;
    object Capture(StreamReader input)=>Activator.CreateInstance(captureType,BindingFlags.Instance|BindingFlags.NonPublic,null,new object[]{input},null)!;
    string Snapshot(object capture)=>(string)captureType.GetMethod("Snapshot",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(capture,null)!;
    Task<string> Completion(object capture)=>(Task<string>)captureType.GetProperty("Completion",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(capture)!;
    using(var input=new System.IO.Pipes.AnonymousPipeServerStream(System.IO.Pipes.PipeDirection.In))
    using(var output=new System.IO.Pipes.AnonymousPipeClientStream(System.IO.Pipes.PipeDirection.Out,input.ClientSafePipeHandle))
    using(var reader=new StreamReader(input))
    {
        var capture=Capture(reader);var bytes=Encoding.UTF8.GetBytes("Unhandled exception. System.UnauthorizedAccessException: PRIVATE-PATH-CONTROL");output.Write(bytes);output.Flush();
        Require(SpinWait.SpinUntil(()=>Snapshot(capture).Length==bytes.Length,1000),"partial bytes retained before pipe closure");
        Require(!Completion(capture).IsCompleted,"snapshot does not wait for EOF");
        Require((string)Call(captureType,"Classify","",Snapshot(capture))! == "MANAGED_UNHANDLED_TYPE=System.UnauthorizedAccessException","only bounded exception type leaves private error record");
        output.Dispose();Require(Completion(capture).Wait(1000),"pipe closes normally after snapshot");
    }
    using(var reader=new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes(new string('x',4097)))))
    {
        var capture=Capture(reader);try{_=Completion(capture).GetAwaiter().GetResult();throw new InvalidOperationException("Expected output bound refusal");}
        catch(InvalidDataException ex)when(ex.Message=="ResourceReportTooLarge"){}
        Require(Snapshot(capture).Length<=4096,"bounded retained output on overflow");
    }
    Console.WriteLine("PASS partial anonymous-pipe output before EOF, bounded overflow refusal and exception-type-only public metadata; no protected resource access");return 0;
}
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
if(args[0]=="hosted-policy")
{
    Refuse(()=>Call(library.GetType("ProtectionLifecycle.AtomicChild",true)!,"AssertRestrictedToolSelf"),"PowerShellRequiresConfinedTool");
    var snapshot=library.GetType("ProtectionLifecycle.PowerShellPolicySnapshot",true)!;
    Call(snapshot,"AssertActuallyAbsent"); // Real fixed GPO absence, never fake a present policy.
    using var assets=(IDisposable)Call(library.GetType("ProtectionLifecycle.SessionPowerShellToolchain",true)!,"Open")!;
    var fixture=Path.Combine(AppContext.BaseDirectory,"owned-hosted-shell-fixture");
    Require(!Directory.Exists(fixture),"new own fixture only");Directory.CreateDirectory(fixture);
    var start=(ProcessStartInfo)Call(resources,"PowerShellStart",plan,fixture)!;
    foreach(var pair in Environment.GetEnvironmentVariables().Keys.Cast<string>().ToArray())Environment.SetEnvironmentVariable(pair,null);
    foreach(var pair in start.Environment)Environment.SetEnvironmentVariable(pair.Key,pair.Value);
    Environment.CurrentDirectory=fixture;
    File.WriteAllText(Path.Combine(fixture,"input.txt"),"OWNED-HOSTED-POWERSHELL-COMPILE");
    foreach(var pair in new[]{("private-control.txt","CPC_DENIAL_FIXTURE"),("aap-control.txt","CPC_LPAC_FIXTURE")})
    {
        var path=Path.Combine(fixture,pair.Item1);File.WriteAllText(path,"NONSECRET-OWN-ACL-CONTROL");
        var acl=new System.Security.AccessControl.FileSecurity();acl.SetOwner(identity.User!);acl.SetAccessRuleProtection(true,false);
        acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(identity.User!,System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));
        acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(identity.User!,System.Security.AccessControl.FileSystemRights.ReadData,System.Security.AccessControl.AccessControlType.Deny));
        System.IO.FileSystemAclExtensions.SetAccessControl(new FileInfo(path),acl);Environment.SetEnvironmentVariable(pair.Item2,path);
    }
    File.WriteAllText(Path.Combine(fixture,"tool-go.txt"),nonce);File.WriteAllBytes(Path.Combine(fixture,"tool-go.signal"),Array.Empty<byte>());
    var host=library.GetType("ProtectionLifecycle.RestrictedPowerShellHost",true)!;
    var code=(int)Call(host,"InvokeConfirmedAbsentPolicies",Path.Combine(programFiles,"ClaudeCodeProtection-PowerShell-7.4.22"),start.ArgumentList.Skip(1).ToArray())!;
    Require(code==0 && File.ReadAllText(Path.Combine(fixture,"tool-output.txt"))=="OWNED-HOSTED-POWERSHELL-COMPILE" &&
        File.ReadAllText(Path.Combine(fixture,"owned-build-result.txt"))=="12" && new FileInfo(Path.Combine(fixture,"owned-build.dll")).Length>=512,"same fixed PowerShell script compiled and executed owned CSharp with actual policy absence");
    Console.WriteLine("PASS ordinary same .NET host invokes pinned PowerShell engine with actual absent-policy snapshot, fixed I/O, two own deny controls, CSharp compilation/execution; ordinary restricted entry refused; NOT LPAC proof");return 0;
}
if(args[0]=="policy")
{
    var dataPlan=Activator.CreateInstance(planType,3,nonce,new string('b',32),new string('c',32),Environment.ProcessId,new string('A',64),
        "9DE2A6DB90D8383F3738249D52F30DEFBEDB994513A8F2697E9D90693CD1D285",new string('D',64),programFiles)!;
    Require((bool)planType.GetProperty("RequiresPowerShell",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(plan)! &&
        !(bool)planType.GetProperty("RequiresPowerShell",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(dataPlan)!,"only explicit pinned workspace data removes the PowerShell dependency");
    Refuse(()=>Call(resources,"PowerShellStart",dataPlan,workspace),"WorkspaceDataCannotRequestPowerShell");
    Refuse(()=>Call(launch,"ValidateStart",dataPlan,workspace,"powershell",powerShell.ArgumentList.ToArray(),Digest(powerShell)),"WorkspaceDataCannotRequestPowerShell");
    var dataGit=(ProcessStartInfo)Call(git,"Start",workspace,directory,new[]{"hash-object","--stdin"})!;
    _=Call(launch,"ValidateStart",dataPlan,workspace,"git",dataGit.ArgumentList.ToArray(),Digest(dataGit));
    var policy=Call(library.GetType("ProtectionLifecycle.SessionPowerShellToolchain",true)!,"ReadAssets")!;
    Require((int)((Array)policy.GetType().GetProperty("Files")!.GetValue(policy)!).Length==552,"complete embedded official PowerShell asset set");
    Require(powerShell.FileName==Path.Combine(programFiles,"ClaudeCodeProtection","versions",new string('c',32),"bin","admin","ProtectionBroker.exe") && powerShell.ArgumentList[0]=="resource-powershell","same original fixed confined host image");
    Require(powerShell.Environment["POWERSHELL_TELEMETRY_OPTOUT"]=="1" && powerShell.Environment["POWERSHELL_UPDATECHECK"]=="Off","fixed offline startup environment");
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
}
catch(Exception error)
{
    Console.Error.WriteLine(error);return 3;
}
