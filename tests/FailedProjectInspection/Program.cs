using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ProtectionLifecycle;

// Ordinary parser tests against the built library. No installed command,
// protected file, token, process, GPU or network collector is invoked.
var parser=typeof(InstalledBroker).Assembly.GetType("ProtectionLifecycle.FailedProjectInspection",true)!
    .GetMethod("Parse",BindingFlags.Static|BindingFlags.NonPublic)!;
var installation=new string('a',32);var session=new string('b',32);var hash=new string('A',64);var checks=0;
const string secret="PRIVATE_DO_NOT_EXPORT_C:\\host\\raw-identity";
JsonObject Sample()=>new()
{
    ["SchemaVersion"]=1,["InstallationId"]=installation,["SessionId"]=session,["Release"]=new string('c',32),["ManifestHash"]=new string('B',64),
    ["Scope"]="EXPLICIT_CALLER_CSHARP_LITERAL_EDITS_BUILD_RUN_TEST",["Status"]="OFFLINE_RESOURCE_SESSION_NOT_CONFIRMED",
    ["WorkspaceBaselineSHA256"]=hash,["FormalAdmissionIssued"]=false,["LaunchAuthorized"]=false,["NetworkOpened"]=false,["ClaudeLaunched"]=false,
    ["ChildExit"]=3,["Child"]=new JsonObject
    {
        ["SchemaVersion"]=1,["Pid"]=123,["Nonce"]=session,["ToolExit"]=null,["FailureType"]="TimeoutException",
        ["FailureCode"]=-2146233083,["FailureStage"]="WAIT_PROJECT_COMPILER",["ProjectFailure"]=null,
        ["ToolDiagnostic"]=secret,["Cases"]=new JsonArray(new JsonObject{["Role"]=secret})
    },
    ["Failures"]=new JsonArray(new JsonObject{["Type"]="InvalidDataException",["Code"]=2146233087u,["Stage"]="ResourceSessionFailed"}),
    ["Job"]=new JsonObject{["Name"]=secret},["Stop"]=new JsonObject{["Raw"]=secret},["HostPrivacy"]=secret,["stderr"]=secret
};
JsonElement Parse(byte[] bytes,string? i=null,string? s=null,string? h=null)
{
    var result=parser.Invoke(null,new object[]{bytes,i??installation,s??session,h??hash})!;
    return JsonSerializer.SerializeToElement(result,result.GetType());
}
byte[] Bytes(JsonObject value)=>Encoding.UTF8.GetBytes(value.ToJsonString());
void Check(bool condition,string name){checks++;if(!condition)throw new Exception("FAILED: "+name);}
void Reject(byte[] bytes,string name,string? i=null,string? s=null,string? h=null)
{
    try{_=Parse(bytes,i,s,h);}catch(TargetInvocationException ex)when(ex.InnerException is InvalidDataException or JsonException or InvalidOperationException)
    {checks++;return;}throw new Exception("ACCEPTED: "+name);
}
void Change(string key,JsonNode? value,string name){var sample=Sample();sample[key]=value;Reject(Bytes(sample),name);}
var bytes=Bytes(Sample());var parsed=Parse(bytes);
Check(parsed.GetProperty("ReportedChild").GetProperty("Worker").GetProperty("Kind").GetString()=="ProjectCompilerWaitTimeout","timeout normalized");
Check(parsed.GetProperty("ChildExit").GetUInt32()==3,"unsigned root exit");
Check(parsed.GetProperty("TerminalRecordSHA256").GetString()==Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)),"exact record digest");
Check(!parsed.GetRawText().Contains("PRIVATE",StringComparison.Ordinal) && !parsed.TryGetProperty("Job",out _) && !parsed.TryGetProperty("Stop",out _),"private content excluded");
foreach(var key in new[]{"LaunchAuthorized","RecoveryAuthorized","ResultReleaseAuthorized"})Check(!parsed.GetProperty(key).GetBoolean(),key);
Check(parsed.GetProperty("EvidenceScope").GetString()=="REPORTED_TERMINAL_METADATA_NOT_CURRENT_OS_PROOF","historical only");
Reject(bytes,"foreign installation",i:new string('d',32));Reject(bytes,"foreign session",s:new string('e',32));Reject(bytes,"foreign input",h:new string('C',64));
Reject(bytes,"path session",s:"../resource-session-after");Reject(bytes,"lowercase hash",h:new string('a',64));
Change("Status","OFFLINE_CALLER_CSHARP_PROJECT_BUILD_AND_TEST_OBSERVED","success record");Change("Scope","OTHER","other scope");Change("SchemaVersion",2,"unknown schema");
foreach(var key in new[]{"FormalAdmissionIssued","LaunchAuthorized","NetworkOpened","ClaudeLaunched"})Change(key,true,key);
Change("Release",secret,"release injection");Change("ManifestHash",secret,"manifest injection");Change("ChildExit",-1,"negative native exit");
var noChild=Sample();noChild["Child"]=null;noChild["ChildExit"]=null;
Check(Parse(Bytes(noChild)).GetProperty("ReportedChild").ValueKind==JsonValueKind.Null,"unknown child retained");
foreach(var field in new[]{"Nonce","Pid","SchemaVersion","FailureCode","ToolExit"})
{
    var sample=Sample();sample["Child"]![field]=field=="Nonce"?JsonValue.Create(new string('f',32)):JsonValue.Create("bad");Reject(Bytes(sample),"child "+field);
}
var unknown=Sample();unknown["Child"]!["FailureType"]=secret;unknown["Child"]!["FailureStage"]=secret;
unknown["Failures"]![0]!["Type"]=secret;unknown["Failures"]![0]!["Stage"]=secret;
var unknownResult=Parse(Bytes(unknown));Check(!unknownResult.GetRawText().Contains("PRIVATE",StringComparison.Ordinal),"unknown strings excluded");
Check(unknownResult.GetProperty("ReportedChild").GetProperty("Stage").GetString()=="UNKNOWN","unknown stage preserved");
var exited=Sample();exited["Child"]!["FailureStage"]="WAIT_PROJECT_COMPILER/ProjectDevelopmentNotConfirmed";
exited["Child"]!["FailureType"]="InvalidDataException";exited["Child"]!["ToolExit"]=7;
Check(Parse(Bytes(exited)).GetProperty("ReportedChild").GetProperty("Worker").GetProperty("Kind").GetString()=="ProjectCompilerExited","nonzero worker exit");
var many=Sample();many["Failures"]=new JsonArray(Enumerable.Range(0,25).Select(_=>(JsonNode?)new JsonObject{["Type"]="IOException",["Code"]=5,["Stage"]=secret}).ToArray());
var limited=Parse(Bytes(many));Check(limited.GetProperty("ReportedFailures").GetArrayLength()==16 && limited.GetProperty("OmittedFailureCount").GetInt32()==9,"bounded normalized failures");
many["Failures"]=new JsonArray(Enumerable.Range(0,1025).Select(_=>(JsonNode?)new JsonObject{["Type"]="IOException",["Code"]=5,["Stage"]=null}).ToArray());Reject(Bytes(many),"failure count");
var text=Encoding.UTF8.GetString(bytes);Reject(Encoding.UTF8.GetBytes(text.Replace("\"SchemaVersion\":1","\"SchemaVersion\":1,\"SchemaVersion\":1",StringComparison.Ordinal)),"duplicate authority field");
Reject(Encoding.UTF8.GetBytes(text.Replace("\"Raw\":","\"Raw\":0,\"Raw\":",StringComparison.Ordinal)),"duplicate ignored private field");
Reject(new byte[131073],"size bound");Reject(Array.Empty<byte>(),"empty");Reject(Encoding.UTF8.GetBytes("{bad}"),"malformed");
var deep=Sample();JsonNode nested=JsonValue.Create(0)!;for(var j=0;j<40;j++)nested=new JsonArray(nested);deep["unused"]=nested;Reject(Bytes(deep),"depth bound");
Console.WriteLine(JsonSerializer.Serialize(new{Scope="ORDINARY_BUILT_LIBRARY_TERMINAL_PROJECTION_FIXTURES",Checks=checks,Passed=true,NativeExecuted=false,PrivateRecordRead=false,Installed=false}));
