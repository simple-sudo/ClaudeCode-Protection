using System.Reflection;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using ProtectionLifecycle;

using var identity=WindowsIdentity.GetCurrent();
if(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))throw new Exception("Ordinary tests required");
var library=typeof(InstalledBroker).Assembly;const BindingFlags hidden=BindingFlags.NonPublic|BindingFlags.Static;
var token=library.GetType("ProtectionLifecycle.GpuHostToken",true)!;var factsType=library.GetType("ProtectionLifecycle.GpuHostTokenFacts",true)!;
var nonce=new string('a',32);var job=new string('b',32);var checks=0;
object Call(Type type,string name,params object?[] values)=>type.GetMethod(name,hidden)!.Invoke(null,values)!;
object Decode(JsonObject data,Type type)=>JsonSerializer.Deserialize(data.ToJsonString(),type)!;
JsonObject Facts(bool source)=>new(){["Type"]=1,["AppContainer"]=0,["Elevated"]=source?1:0,["ElevationType"]=source?2:3,["RestrictedSidCount"]=0,["UiAccess"]=0,
    ["SessionId"]=1,["UserSid"]="S-1-5-21-1-2-3-1001",["IntegritySid"]=source?"S-1-16-12288":"S-1-16-8192",["AuthenticationId"]="0011223344556677",["Administrator"]=source,["PrivilegesSHA256"]=new string('A',64)};
void Check(bool value,string name){checks++;if(!value)throw new Exception("FAILED: "+name);}
void Refuse(Action action,string name)
{
    try{action();}catch(TargetInvocationException error)when(error.InnerException is InvalidDataException or UnauthorizedAccessException){checks++;return;}
    throw new Exception("ACCEPTED: "+name);
}
var source=Decode(Facts(true),factsType);var normal=Decode(Facts(false),factsType);
Call(token,"RequireLinked",source,normal);checks++;
var aadSource=Facts(true);var aadNormal=Facts(false);aadSource["UserSid"]="S-1-12-1-1-2-3-4";aadNormal["UserSid"]="S-1-12-1-1-2-3-4";
Call(token,"RequireLinked",Decode(aadSource,factsType),Decode(aadNormal,factsType));checks++;
var privilegeDrift=Facts(false);privilegeDrift["PrivilegesSHA256"]=new string('B',64);
Refuse(()=>Call(token,"RequireCreated",normal,Decode(privilegeDrift,factsType)),"created token privileges changed");
var distinctLogon=Facts(false);distinctLogon["AuthenticationId"]="0011223344556688";
Call(token,"RequireLinked",source,Decode(distinctLogon,factsType));checks++;
Refuse(()=>Call(token,"RequireCreated",normal,Decode(distinctLogon,factsType)),"created token must preserve linked token logon, not switch to another");
foreach(var (key,value) in new (string,JsonNode?)[]{("Type",JsonValue.Create(2)),("AppContainer",JsonValue.Create(1)),("Elevated",JsonValue.Create(1)),
    ("ElevationType",JsonValue.Create(2)),("RestrictedSidCount",JsonValue.Create(1)),("UiAccess",JsonValue.Create(1)),("Administrator",JsonValue.Create(true)),
    ("IntegritySid",JsonValue.Create("S-1-16-4096")),("SessionId",JsonValue.Create(2)),("UserSid",JsonValue.Create("S-1-5-21-1-2-3-1002")),
    ("AuthenticationId",JsonValue.Create("malformed"))})
{
    var changed=Facts(false);changed[key]=value;var candidate=Decode(changed,factsType);
    Refuse(()=>Call(token,"RequireLinked",source,candidate),"lower token "+key);
    Refuse(()=>Call(token,"RequireCreated",normal,candidate),"created token "+key);
}
foreach(var (key,value) in new (string,JsonNode?)[]{("Type",JsonValue.Create(2)),("AppContainer",JsonValue.Create(1)),("Elevated",JsonValue.Create(0)),
    ("ElevationType",JsonValue.Create(1)),("RestrictedSidCount",JsonValue.Create(1)),("UiAccess",JsonValue.Create(1)),("Administrator",JsonValue.Create(false)),("IntegritySid",JsonValue.Create("S-1-16-8192"))})
{var changed=Facts(true);changed[key]=value;Refuse(()=>Call(token,"RequireLinked",Decode(changed,factsType),normal),"source token "+key);}
Refuse(()=>Call(token,"OpenOwnLinkedNormalToken"),"ordinary caller cannot enter elevated creation-token path");
try{_=InstalledBroker.QualifyHostGpuReference();throw new Exception("Ordinary caller entered installed host qualifier");}
catch(UnauthorizedAccessException){checks++;}

var gpu=library.GetType("ProtectionLifecycle.GpuQualification",true)!;
var host=library.GetType("ProtectionLifecycle.GpuHostReferenceQualification",true)!;
var reportType=library.GetType("ProtectionLifecycle.GpuChildReport",true)!;var stopType=library.GetType("ProtectionLifecycle.RuntimeStop",true)!;
var hash=(string)gpu.GetProperty("ExpectedHash",hidden)!.GetValue(null)!;
var stages=new[]{"cuInit","cuDriverGetVersion","cuDeviceGetCount","cuDeviceGet","cuDeviceGetName","cuCtxCreate_v2","cuMemAlloc_v2","cuMemcpyHtoD_v2",
    "cuModuleLoadData","cuModuleGetFunction","cuLaunchKernel","cuCtxSynchronize","cuMemcpyDtoH_v2","cuModuleUnload","cuMemFree_v2","cuCtxDestroy_v2"};
JsonObject Report(string scope)=>new(){["SchemaVersion"]=1,["Pid"]=42,["Nonce"]=nonce,["Scope"]=scope,["DriverVersion"]=13030,["Device"]="Synthetic model",
    ["AllocatedBytes"]=1024,["Elements"]=256,["ResultSHA256"]=hash,["ComputeMatched"]=true,["ResourceCleanupSucceeded"]=true,["FailureType"]=null,
    ["Steps"]=new JsonArray(stages.Select(s=>(JsonNode?)new JsonObject{["Stage"]=s,["Result"]=0}).ToArray())};
JsonObject Stop()=>new(){["SessionId"]=nonce,["Reason"]="FIXED_HOST_GPU_REFERENCE_TERMINAL",["AdmissionClosed"]=true,["QuarantineObservedBeforeStop"]=true,
    ["QuarantineAtMs"]=1,["JobStopAtMs"]=2,["Failures"]=new JsonArray(),["FinalJob"]=new JsonObject{["JobId"]=job,["LimitFlags"]=8192,["ActiveBefore"]=0,["ActiveAfter"]=0,["ProcessIds"]=new JsonArray(),["AtUtc"]="SYNTHETIC"}};
const string hostScope="TRUSTED_LINKED_ORDINARY_HOST_GPU_REFERENCE_NOT_LPAC";const string lpacScope="LPAC_LOW_ZERO_CAPABILITIES";
bool Qualifies(JsonObject report,JsonObject? stop=null,string? expectedNonce=null,uint pid=42,uint exit=0,bool progress=true,string? expectedJob=null)
    =>(bool)Call(host,"Qualified",Decode(report,reportType),expectedNonce??nonce,pid,exit,progress,stop is null?null:Decode(stop,stopType),expectedJob??job);
Check(Qualifies(Report(hostScope),Stop()),"bound host report and original host-stop closure");
Check(!Qualifies(Report(lpacScope),Stop()),"LPAC report cannot become host control");
Check(!(bool)Call(gpu,"QualifiedChild",Decode(Report(hostScope),reportType),nonce,42u,0u,Decode(Report(hostScope),reportType)),"ordinary host cannot qualify protected LPAC computation");
Check(!Qualifies(Report(hostScope)),"missing stop");Check(!Qualifies(Report(hostScope),Stop(),pid:43),"wrong PID");
Check(!Qualifies(Report(hostScope),Stop(),exit:3),"failed child");Check(!Qualifies(Report(hostScope),Stop(),progress:false),"incomplete progress");
Check(!Qualifies(Report(hostScope),Stop(),expectedNonce:new string('c',32)),"wrong nonce");Check(!Qualifies(Report(hostScope),Stop(),expectedJob:new string('d',32)),"wrong Job");
var wrongReason=Stop();wrongReason["Reason"]="FIXED_GPU_QUALIFICATION_TERMINAL";Check(!Qualifies(Report(hostScope),wrongReason),"LPAC closure cannot replace host closure");
foreach(var field in new[]{"AdmissionClosed","QuarantineObservedBeforeStop"}){var bad=Stop();bad[field]=false;Check(!Qualifies(Report(hostScope),bad),field);}
var busy=Stop();busy["FinalJob"]!["ActiveAfter"]=1;Check(!Qualifies(Report(hostScope),busy),"Job not zero");
var limits=Stop();limits["FinalJob"]!["LimitFlags"]=8200;Check(!Qualifies(Report(hostScope),limits),"Job limits changed");
var order=Stop();order["JobStopAtMs"]=0;Check(!Qualifies(Report(hostScope),order),"quarantine ordering changed");
var failure=Stop();failure["Failures"]=new JsonArray(new JsonObject{["Type"]="Synthetic",["Code"]=5,["Stage"]="Synthetic"});Check(!Qualifies(Report(hostScope),failure),"stop failure retained");
Console.WriteLine(JsonSerializer.Serialize(new{Scope="ORDINARY_SYNTHETIC_HOST_GPU_TOKEN_ROLE_AND_STOP_BINDING",Checks=checks,Passed=true,
    RealLinkedTokenOpened=false,ProcessAsUserCalled=false,JobCreated=false,NativeCudaExecuted=false,Installed=false}));
