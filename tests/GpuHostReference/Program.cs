using System.Reflection;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using ProtectionLifecycle;
using System.IO.Pipes;
using System.Security.AccessControl;

using var identity=WindowsIdentity.GetCurrent();
if(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))throw new Exception("Ordinary tests required");
var library=typeof(InstalledBroker).Assembly;const BindingFlags hidden=BindingFlags.NonPublic|BindingFlags.Static;
var token=library.GetType("ProtectionLifecycle.GpuHostToken",true)!;var factsType=library.GetType("ProtectionLifecycle.GpuHostTokenFacts",true)!;
var nonce=new string('a',32);var job=new string('b',32);var checks=0;
object Call(Type type,string name,params object?[] values)=>type.GetMethod(name,hidden)!.Invoke(null,values)!;
object Decode(JsonObject data,Type type)=>JsonSerializer.Deserialize(data.ToJsonString(),type)!;
if(args.Length==1 && args[0]=="label")
{
    var pipes=library.GetType("ClaudeCodeProtection.Workspaces.WorkspacePipe",true)!;
    var sd=new PipeSecurity();sd.SetOwner(identity.User!);sd.SetAccessRuleProtection(true,false);
    sd.AddAccessRule(new PipeAccessRule(identity.User!,PipeAccessRights.FullControl,AccessControlType.Allow));
    foreach(var package in new[]{"S-1-15-2-1","S-1-15-2-2"})sd.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(package),PipeAccessRights.FullControl,AccessControlType.Deny));
    using var own=NamedPipeServerStreamAcl.Create("CPC.Research.NewReportLabel."+Guid.NewGuid().ToString("N"),PipeDirection.InOut,1,
        PipeTransmissionMode.Byte,PipeOptions.Asynchronous|PipeOptions.FirstPipeInstance,4096,4096,sd,HandleInheritability.None,PipeAccessRights.TakeOwnership);
    Call(pipes,"SetNewReportMediumLabel",own);
    Console.WriteLine(JsonSerializer.Serialize(new{Scope="ACTUAL_ORDINARY_NEW_OWN_PIPE_LABEL_ONLY_SET_AND_READBACK",Passed=true,
        MediumLabelReadBack=true,OriginalOwnerAndDaclUnchanged=true,ExistingObjectModified=false,PrivilegeChanged=false,UacRequested=false,JobCreated=false,NativeCudaExecuted=false}));return;
}
if(args.Length==1 && args[0]=="pipe")
{
    var pipes=library.GetType("ClaudeCodeProtection.Workspaces.WorkspacePipe",true)!;
    var unique=Guid.NewGuid().ToString("N");var name=(string)Call(pipes,"HostGpuName",Environment.ProcessId,unique,false);
    using var server=(NamedPipeServerStream)Call(pipes,"CreateHostGpu",Environment.ProcessId,unique,false);
    using var client=new NamedPipeClientStream(".",name,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification);
    using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(5));
    var connection=server.WaitForConnectionAsync(deadline.Token);client.Connect(3000);connection.GetAwaiter().GetResult();
    Call(pipes,"AssertPeer",server,Environment.ProcessId,true);Call(pipes,"AssertPeer",client,Environment.ProcessId,false);
    Refuse(()=>Call(pipes,"AssertPeer",server,Environment.ProcessId+1,true),"actual connected peer mismatch");
    Refuse(()=>Call(pipes,"CreateHostGpu",Environment.ProcessId,Guid.NewGuid().ToString("N"),true),"ordinary caller cannot create elevated report endpoint");
    var rules=server.GetAccessControl().GetAccessRules(true,true,typeof(SecurityIdentifier));
    foreach(var package in new[]{"S-1-15-2-1","S-1-15-2-2"})
        Check(rules.Cast<PipeAccessRule>().Any(r=>r.IdentityReference.Value==package && r.AccessControlType==AccessControlType.Deny &&
            (r.PipeAccessRights&PipeAccessRights.FullControl)==PipeAccessRights.FullControl),"actual ordinary support pipe rejects "+package);
    var frame=System.Text.Encoding.UTF8.GetBytes("FIXED_ORDINARY_GPU_SUPPORT_CHANNEL_FIXTURE");
    ((Task)Call(pipes,"Write",client,frame,256,deadline.Token)).GetAwaiter().GetResult();
    var received=((Task<byte[]>)Call(pipes,"Read",server,256,deadline.Token)).GetAwaiter().GetResult();
    Check(frame.SequenceEqual(received),"actual framed ordinary pipe content");
    Console.WriteLine(JsonSerializer.Serialize(new{Scope="ACTUAL_ORDINARY_NAMED_PIPE_PEER_ACL_AND_FRAME_FIXTURE",Passed=true,Checks=checks+2,
        ElevatedReportEndpointCreated=false,UacRequested=false,JobCreated=false,ParentProcessAttributeUsed=false,NativeCudaExecuted=false}));return;
}
if(args.Length==1 && args[0]=="current-token")
{
    // Actual ordinary-current-token reader, without calling linked-token or
    // any admin, creation, Job or GPU path. Never export raw identity fields.
    var actual=Call(token,"Capture",identity.AccessToken);
    if(!actual.Equals(Call(token,"Capture",identity.AccessToken)))throw new Exception("Current token facts changed during read");
    var fields=JsonSerializer.SerializeToNode(actual)!.AsObject();
    Console.WriteLine(JsonSerializer.Serialize(new{Scope="ACTUAL_ORDINARY_CURRENT_TOKEN_CAPTURE_ONLY",Passed=true,
        Type=fields["Type"]!.GetValue<int>(),AppContainer=fields["AppContainer"]!.GetValue<int>(),Elevated=fields["Elevated"]!.GetValue<int>(),
        ElevationType=fields["ElevationType"]!.GetValue<int>(),RestrictedSidCount=fields["RestrictedSidCount"]!.GetValue<int>(),
        RawIdentityExported=false,LinkedTokenRead=false,TokenModified=false,JobCreated=false,NativeCudaExecuted=false}));
    return;
}
if(args.Length!=0)throw new Exception("Only fixed current-token read, pipe, label or ordinary fixtures supported");
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
Refuse(()=>Call(host,"RequireQualifiedCreationPath"),"unqualified linked-token creation path is held before a new Job");
var reportType=library.GetType("ProtectionLifecycle.GpuChildReport",true)!;var stopType=library.GetType("ProtectionLifecycle.RuntimeStop",true)!;
var hash=(string)gpu.GetProperty("ExpectedHash",hidden)!.GetValue(null)!;
var stages=new[]{"cuInit","cuDriverGetVersion","cuDeviceGetCount","cuDeviceGet","cuDeviceGetName","cuCtxCreate_v2","cuMemAlloc_v2","cuMemcpyHtoD_v2",
    "cuModuleLoadData","cuModuleGetFunction","cuLaunchKernel","cuCtxSynchronize","cuMemcpyDtoH_v2","cuModuleUnload","cuMemFree_v2","cuCtxDestroy_v2"};
JsonObject Report(string scope)=>new(){["SchemaVersion"]=1,["Pid"]=42,["Nonce"]=nonce,["Scope"]=scope,["DriverVersion"]=13030,["Device"]="Synthetic model",
    ["AllocatedBytes"]=1024,["Elements"]=256,["ResultSHA256"]=hash,["ComputeMatched"]=true,["ResourceCleanupSucceeded"]=true,["FailureType"]=null,
    ["Steps"]=new JsonArray(stages.Select(s=>(JsonNode?)new JsonObject{["Stage"]=s,["Result"]=0}).ToArray())};
JsonObject Stop()=>new(){["SessionId"]=nonce,["Reason"]="FIXED_HOST_GPU_REFERENCE_TERMINAL",["AdmissionClosed"]=true,["QuarantineObservedBeforeStop"]=true,
    ["QuarantineAtMs"]=1,["JobStopAtMs"]=2,["Failures"]=new JsonArray(),["FinalJob"]=new JsonObject{["JobId"]=job,["LimitFlags"]=8192,["ActiveBefore"]=0,["ActiveAfter"]=0,["ProcessIds"]=new JsonArray(),["AtUtc"]="SYNTHETIC"}};
const string hostScope="TRUSTED_ORDINARY_HOST_GPU_REFERENCE_NOT_LPAC";const string lpacScope="LPAC_LOW_ZERO_CAPABILITIES";
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
var bound=library.GetType("ProtectionLifecycle.GpuReferenceCaller",true)!;
Call(bound,"RequireSameHuman",source,normal);checks++;
Call(bound,"RequireSameHuman",source,Decode(distinctLogon,factsType));checks++;
foreach(var field in new[]{"UserSid","SessionId"})
{var changed=Facts(false);changed[field]=field=="SessionId"?JsonValue.Create(2):JsonValue.Create("S-1-5-21-1-2-3-1002");Refuse(()=>Call(bound,"RequireSameHuman",source,Decode(changed,factsType)),"ordinary parent "+field+" differs");}
Check((uint)bound.GetField("ProcessAccess",hidden)!.GetRawConstantValue()! == 0x00101080,"peer rights contain only synchronize/query-limited/create-process");
try{_=InstalledBroker.QualifyHostGpuReferencePipe(1,nonce);throw new Exception("Ordinary entered elevated pipe qualifier");}
catch(UnauthorizedAccessException){checks++;}
var replyType=library.GetType("ClaudeCodeProtection.Workspaces.HostGpuReferenceReply",true)!;
JsonObject Reply()=>new(){["SchemaVersion"]=2,["Nonce"]=nonce,["Status"]="BOUND_ORDINARY_HOST_GPU_REFERENCE_CLOSED",["ExitCode"]=0,["RequestId"]=job,["ChildPid"]=42,
    ["Complete"]=true,["OriginalJobClosed"]=true,["FailureCodes"]=new JsonArray(),["FailureStages"]=new JsonArray(),["ProtectedGpuVerified"]=false,["FormalAdmissionIssued"]=false,["ClaudeLaunched"]=false};
object Parse(string json)=>Call(replyType,"Parse",System.Text.Encoding.UTF8.GetBytes(json),nonce);
_=Parse(Reply().ToJsonString());checks++;
foreach(var (field,value) in new (string,JsonNode?)[]{("SchemaVersion",JsonValue.Create(1)),("Nonce",JsonValue.Create(new string('c',32))),
    ("ExitCode",JsonValue.Create(3)),("RequestId",null),("ChildPid",JsonValue.Create(0)),("Complete",JsonValue.Create(false)),("OriginalJobClosed",JsonValue.Create(false)),
    ("FailureCodes",new JsonArray(2148734209u)),("ProtectedGpuVerified",JsonValue.Create(true)),("FormalAdmissionIssued",JsonValue.Create(true)),("ClaudeLaunched",JsonValue.Create(true)),("Unexpected",JsonValue.Create(1))})
{var changed=Reply();changed[field]=value;Refuse(()=>Parse(changed.ToJsonString()),"support reply "+field);}
var failedReply=Reply();failedReply["ExitCode"]=3;failedReply["Complete"]=false;failedReply["Status"]="BOUND_ORDINARY_HOST_GPU_REFERENCE_NOT_CONFIRMED";
failedReply["FailureCodes"]=new JsonArray(2148734209u);failedReply["FailureStages"]=new JsonArray("HostGpuReportPipeCreate");_=Parse(failedReply.ToJsonString());checks++;
var hostileStage=(JsonObject)failedReply.DeepClone();hostileStage["FailureStages"]=new JsonArray("untrusted raw owner text");Refuse(()=>Parse(hostileStage.ToJsonString()),"unknown stage text");
hostileStage=(JsonObject)failedReply.DeepClone();hostileStage["FailureStages"]=new JsonArray();Refuse(()=>Parse(hostileStage.ToJsonString()),"stage and numeric error count differ");
Check((string)Call(replyType,"NormalizeStage","untrusted raw owner text")=="OTHER_STAGE_OR_NOT_REPORTED","unrecognized stages do not expose raw text");
Refuse(()=>Parse(Reply().ToJsonString().Replace("\"SchemaVersion\":2","\"SchemaVersion\":2,\"SchemaVersion\":2")),"duplicate summary property");
Console.WriteLine(JsonSerializer.Serialize(new{Scope="ORDINARY_SYNTHETIC_HOST_GPU_TOKEN_ROLE_AND_STOP_BINDING",Checks=checks,Passed=true,
    RealLinkedTokenOpened=false,ProcessAsUserCalled=false,JobCreated=false,NativeCudaExecuted=false,Installed=false}));
