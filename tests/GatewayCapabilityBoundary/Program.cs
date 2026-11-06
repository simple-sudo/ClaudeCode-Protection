using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;

using var human=WindowsIdentity.GetCurrent();
if(new WindowsPrincipal(human).IsInRole(WindowsBuiltInRole.Administrator))throw new InvalidOperationException("Ordinary checks only");
var library=Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory,"ProtectionLifecycle.dll"));
const BindingFlags nonpublic=BindingFlags.NonPublic|BindingFlags.Static;
int checks=0;
void Check(bool value){if(!value)throw new InvalidDataException("GatewayCapabilityFixtureFailed");checks++;}
object? Call(MethodInfo method,params object?[] values)
{try{return method.Invoke(null,values);}catch(TargetInvocationException error)when(error.InnerException is not null){ExceptionDispatchInfo.Capture(error.InnerException).Throw();throw;}}
void Reject(Action run,string? reason=null)
{bool denied=false;try{run();}catch(InvalidDataException error)when(reason is null || error.Message==reason){denied=true;}Check(denied);}
Type T(string name)=>library.GetType("ProtectionLifecycle."+name,true)!;
if(args.Length==1 && args[0]=="host-reference")
{
    var observation=Call(T("GatewayCapabilityContent").GetMethod("Capture",nonpublic)!)!;
    Console.WriteLine(JsonSerializer.Serialize(observation,observation.GetType()));return 0;
}
if(args.Length!=0)return 125;
var profiles=T("LpacCapabilityProfile");var none=profiles.GetField("None",nonpublic)!.GetValue(null)!;
var internet=profiles.GetField("InternetClientQualification",nonpublic)!.GetValue(null)!;
Check(profiles.GetConstructors().Length==0);
var session=T("ProtectedSession");Check((bool)session.GetProperty("SystemTestingBlocked",nonpublic)!.GetValue(null)!);
var ctor=session.GetConstructors(BindingFlags.NonPublic|BindingFlags.Instance).Single();
var arguments=new object?[]{null,null,null,false,false,false,false,true,false,false};
Reject(()=>{try{_=ctor.Invoke(arguments);}catch(TargetInvocationException e)when(e.InnerException is InvalidDataException cause){throw cause;}},"InternetClientRequiresFixedGatewayAndExactWinsockQualification");
arguments[7]=false;arguments[8]=true;
Reject(()=>{try{_=ctor.Invoke(arguments);}catch(TargetInvocationException e)when(e.InnerException is InvalidDataException cause){throw cause;}},"InternetClientRequiresFixedGatewayAndExactWinsockQualification");
var broker=T("InstalledBroker");var entry=broker.GetMethod("QualifyInternetClientSessionGateway")!;
Check(entry.GetParameters().Length==0);
bool ordinaryDenied=false;try{Call(entry);}catch(UnauthorizedAccessException){ordinaryDenied=true;}Check(ordinaryDenied);
entry=broker.GetMethod("QualifyZeroCapabilityComparisonGateway")!;Check(entry.GetParameters().Length==0);
ordinaryDenied=false;try{Call(entry);}catch(UnauthorizedAccessException){ordinaryDenied=true;}Check(ordinaryDenied);
entry=broker.GetMethod("QualifyNoContentHttpsCanary")!;Check(entry.GetParameters().Length==0);
ordinaryDenied=false;try{Call(entry);}catch(UnauthorizedAccessException){ordinaryDenied=true;}Check(ordinaryDenied);
arguments[8]=false;arguments[9]=true;
Reject(()=>{try{_=ctor.Invoke(arguments);}catch(TargetInvocationException e)when(e.InnerException is InvalidDataException cause){throw cause;}},"NoContentHttpsCanaryRequiresFixedInternetClient");

object Snapshot(string sid,uint attributes)
{
    var identity=new SecurityIdentifier(sid);var n=24+identity.BinaryLength;var p=Marshal.AllocHGlobal(n);
    try{Marshal.Copy(new byte[n],0,p,n);Marshal.WriteInt32(p,1);Marshal.WriteIntPtr(p,8,IntPtr.Add(p,24));Marshal.WriteInt32(p,16,unchecked((int)attributes));
        var bytes=new byte[identity.BinaryLength];identity.GetBinaryForm(bytes,0);Marshal.Copy(bytes,0,IntPtr.Add(p,24),bytes.Length);
        return Call(T("TokenCapabilitySnapshot").GetMethod("Parse",nonpublic)!,p,n)!;}
    finally{Marshal.FreeHGlobal(p);}
}
var tokenType=T("AdmissionToken");var membersType=T("OwnedMemberInspection");var jobType=T("JobSnapshot");var failureType=T("WfpErrorEvidence");
object Token(int count,object? actual,bool lpac=true)
{
    var token=Activator.CreateInstance(tokenType,true,"S-1-15-2-123",count,"S-1-16-4096",lpac,lpac?2u:3u)!;
    tokenType.GetProperty("Capabilities",BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(token,actual);return token;
}
var exact=Snapshot("S-1-15-3-1",4);var other=Snapshot("S-1-15-3-2",4);var wrongFlags=Snapshot("S-1-15-3-1",7);
var policy=T("WatchdogMemberPolicy");var oldVerify=policy.GetMethod("Verify",nonpublic)!;var verify=policy.GetMethod("VerifyWithCapabilities",nonpublic)!;
object Job()=>Activator.CreateInstance(jobType,new string('a',32),0x2000u,2u,2u,new uint[]{10,11},DateTime.UtcNow.ToString("o"))!;
void Verify(object root,object child,object? profile,bool lpac=true)
{
    var job=Job();var members=Array.CreateInstance(membersType,2);
    members.SetValue(Activator.CreateInstance(membersType,10u,true,(long?)1000,@"C:\fixture\root.exe",root,Array.CreateInstance(failureType,0)),0);
    members.SetValue(Activator.CreateInstance(membersType,11u,true,(long?)1001,@"C:\fixture\conhost.exe",child,Array.CreateInstance(failureType,0)),1);
    var args=new object?[]{job,members,job,10u,1000L,"S-1-15-2-123",@"C:\fixture\root.exe",@"C:\fixture\conhost.exe",lpac};
    Call(profile is null?oldVerify:verify,profile is null?args:args.Append(profile).ToArray());
}
Verify(Token(0,null),Token(0,null),null);checks++;
Verify(Token(1,exact),Token(1,exact),internet);checks++;
foreach(var bad in new[]{Token(0,null),Token(1,null),Token(1,other),Token(1,wrongFlags),Token(0,exact),Token(1,exact,false)})
{Reject(()=>Verify(bad,Token(1,exact),internet));Reject(()=>Verify(Token(1,exact),bad,internet));}
Reject(()=>Verify(Token(1,exact),Token(1,exact),null));
Reject(()=>Verify(Token(1,exact),Token(1,exact),none));
Reject(()=>Verify(Token(1,exact),Token(1,exact),internet,false),"NetworkQualificationRequiresLpacMemberChecks");
// Valid-looking environment cannot manufacture the exact real singleton token.
var names=new[]{"CPC_SESSION_ID","CPC_SESSION_SECRET","CPC_PUBLIC_TIMEZONE_ID","CPC_RESOURCE_PLAN","CPC_NETWORK_PLAN","CPC_GPU_PLAN"};
var saved=names.Select(Environment.GetEnvironmentVariable).ToArray();var output=Console.Out;
try
{
    foreach(var name in names)Environment.SetEnvironmentVariable(name,null);
    Environment.SetEnvironmentVariable(names[0],new string('a',32));Environment.SetEnvironmentVariable(names[1],new string('B',64));Environment.SetEnvironmentVariable(names[2],"UTC");
    using var capture=new StringWriter();Console.SetOut(capture);
    var code=(int)Call(broker.GetMethod("RunInternetClientGatewayQualificationCanary")!)!;
    using var observed=JsonDocument.Parse(capture.ToString());Check(code==125 && observed.RootElement.GetProperty("Gateway").GetProperty("Phase").GetString()=="IDENTITY" && observed.RootElement.GetProperty("Network").ValueKind==JsonValueKind.Null);
    capture.GetStringBuilder().Clear();code=(int)Call(broker.GetMethod("RunZeroCapabilityComparisonCanary")!)!;
    using var zeroObserved=JsonDocument.Parse(capture.ToString());Check(code==125 && zeroObserved.RootElement.GetProperty("Gateway").GetProperty("Phase").GetString()=="IDENTITY" && zeroObserved.RootElement.GetProperty("Endpoint").ValueKind==JsonValueKind.Null);
    capture.GetStringBuilder().Clear();code=(int)Call(broker.GetMethod("RunNoContentHttpsCanary")!)!;
    using var functionObserved=JsonDocument.Parse(capture.ToString());Check(code==125 && functionObserved.RootElement.GetProperty("Gateway").GetProperty("Phase").GetString()=="IDENTITY" && functionObserved.RootElement.GetProperty("Network").ValueKind==JsonValueKind.Null);
}
finally{Console.SetOut(output);for(int i=0;i<names.Length;i++)Environment.SetEnvironmentVariable(names[i],saved[i]);}
checks+=CapabilityContentCases.Run(library);
Console.WriteLine(JsonSerializer.Serialize(new{Scope="ORDINARY_PRODUCTION_GATEWAY_CAPABILITY_IDENTITY_BOUNDARIES",Passed=checks,
    SourceLibraryLoaded=true,OwnTokenQueryOnly=true,NoProfileJobWfpOrNetworkStarted=true,NoTokenModified=true,NetworkAdmission=false}));
return 0;
