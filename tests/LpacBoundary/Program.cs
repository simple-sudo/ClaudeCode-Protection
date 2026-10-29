using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

// Bound to the reviewed production library. These two modes do not create or
// resume a process/profile/Job or open private resources. The token reader may
// create a temporary query-only Identification duplicate, never impersonate it.
if(args.Length!=1 || args[0] is not ("policy" or "self-token" or "runtime-paths"))return 125;
using var identity=WindowsIdentity.GetCurrent();
if(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))throw new InvalidOperationException("Ordinary test only");
var library=Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory,"ProtectionLifecycle.dll"));
const BindingFlags flags=BindingFlags.Static|BindingFlags.NonPublic;
static object? Call(MethodInfo method,params object?[] values)
{
    try{return method.Invoke(null,values);}
    catch(TargetInvocationException ex)when(ex.InnerException is not null){ExceptionDispatchInfo.Capture(ex.InnerException).Throw();throw;}
}
static void Require(bool value,string reason){if(!value)throw new InvalidOperationException("LPAC: "+reason);}
if(args[0]=="runtime-paths")
{
    var planType=library.GetType("ProtectionLifecycle.ResourceProbePlan",true)!;
    var gitType=library.GetType("ProtectionLifecycle.SessionGitToolchain",true)!;
    var gitHash=(string)gitType.GetProperty("AssetSetSHA256",flags)!.GetValue(null)!;
    var id=new string('a',32);var release=new string('b',32);var digest=new string('A',64);
    object Plan(string root)=>Activator.CreateInstance(planType,3,id,id,release,Environment.ProcessId,digest,gitHash,digest,root)!;
    var plan=Plan("C:\\lpac-runtime-case");planType.GetMethod("Validate",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(plan,null);
    object? Get(string property)=>planType.GetProperty(property,BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(plan);
    Require((string)Get("ExpectedChildImage")! == "C:\\lpac-runtime-case\\ClaudeCodeProtection\\versions\\"+release+"\\bin\\admin\\ProtectionBroker.exe","fixed installed image derived from runtime fact");
    Require((string)Get("GitDirectory")! == "C:\\lpac-runtime-case\\Git\\mingw64\\bin","fixed Git subdirectory only");
    Require((string)Get("Fixture")! == "C:\\lpac-runtime-case\\ClaudeCodeProtection-State\\resource-fixture-"+id+".json","non-secret fixture fixed leaf");
    var workspace=(string)planType.GetMethod("Workspace",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(plan,new object[]{"unused"})!;
    Require(workspace=="C:\\lpac-runtime-case\\ClaudeCodeProtection-Task-"+id,"task derives from owner root and nonce");
    foreach(var root in new[]{"relative","\\\\server\\share","C:\\a\\..\\b","C:\\a.","C:\\a\\"})
    {
        var refused=false;try{planType.GetMethod("Validate",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(Plan(root),null);}
        catch(TargetInvocationException ex)when(ex.InnerException is InvalidDataException){refused=true;}
        Require(refused,"ambiguous runtime root refused");
    }
    Console.WriteLine("PASS production runtime paths: fixed image/tool/task/fixture derivation and ambiguous-root rejection; no folder lookup, host read or workload");return 0;
}
if(args[0]=="self-token")
{
    var read=library.GetType("ProtectionLifecycle.AtomicChild",true)!.GetMethod("ReadToken",flags)!;
    using var self=new SafeProcessHandle((IntPtr)(-1),false);var token=Call(read,self,true)!;
    Require(!(bool)token.GetType().GetProperty("IsAppContainer")!.GetValue(token)!,"ordinary process is not an AppContainer");
    Require(!(bool)token.GetType().GetProperty("LpacAccessCheckObserved")!.GetValue(token)!,"ordinary process must never qualify as LPAC");
    Require((uint)token.GetType().GetProperty("ApplicationPackageAccessMask")!.GetValue(token)! == 3u,"ordinary access mask is exactly both synthetic bits");
    var basic=Call(read,self,false)!;
    Require(!(bool)basic.GetType().GetProperty("LpacAccessCheckObserved")!.GetValue(basic)! &&
        (uint)basic.GetType().GetProperty("ApplicationPackageAccessMask")!.GetValue(basic)! == 0u,"query-only child reading cannot manufacture access-check evidence");
    Console.WriteLine("PASS production own-token AccessCheck mask3; ordinary identity cannot qualify as LPAC; no AppContainer, other process, Job or private data");return 0;
}
var tokenType=library.GetType("ProtectionLifecycle.AdmissionToken",true)!;
var memberType=library.GetType("ProtectionLifecycle.OwnedMemberInspection",true)!;
var jobType=library.GetType("ProtectionLifecycle.JobSnapshot",true)!;
var errorType=library.GetType("ProtectionLifecycle.WfpErrorEvidence",true)!;
object Token(bool lpac)=>Activator.CreateInstance(tokenType,true,"S-1-15-2-123",0,"S-1-16-4096",lpac,lpac?2u:3u)!;
object Member(uint pid,string path,bool lpac)=>Activator.CreateInstance(memberType,pid,true,(long?)1000,path,Token(lpac),Array.CreateInstance(errorType,0))!;
object Snapshot(uint[] pids)=>Activator.CreateInstance(jobType,new string('a',32),0x2000u,(uint)pids.Length,(uint)pids.Length,pids,DateTime.UtcNow.ToString("o"))!;
void Verify(bool rootLpac,bool childLpac,bool hasChild=true)
{
    var pids=hasChild?new uint[]{10,11}:new uint[]{10};var snapshot=Snapshot(pids);var members=Array.CreateInstance(memberType,pids.Length);
    members.SetValue(Member(10,"C:\\lpac-test\\root.exe",rootLpac),0);
    if(hasChild)members.SetValue(Member(11,"C:\\lpac-test\\conhost.exe",childLpac),1);
    Call(library.GetType("ProtectionLifecycle.WatchdogMemberPolicy",true)!.GetMethod("Verify",flags)!,snapshot,members,snapshot,
        10u,1000L,"S-1-15-2-123","C:\\lpac-test\\root.exe","C:\\lpac-test\\conhost.exe",true);
}
Verify(true,true);Verify(true,false,false);
foreach(var pair in new[]{(false,false),(true,false),(false,true)})
{
    var rejected=false;try{Verify(pair.Item1,pair.Item2);}catch(InvalidDataException ex)when(ex.Message=="WatchdogMemberIdentityNotQualified"){rejected=true;}
    Require(rejected,"regular AppContainer root/descendant rejected by actual LPAC policy");
}
var descriptor=(string)Call(library.GetType("ProtectionLifecycle.SessionResources",true)!.GetMethod("AllPackagesFixtureSddl",flags)!,identity.User!.Value)!;
var security=new RawSecurityDescriptor(descriptor);var acl=security.DiscretionaryAcl!;
Require((security.ControlFlags&ControlFlags.DiscretionaryAclProtected)!=0 && acl.Count==4,"fixture explicit protected four-ACE DACL");
var rules=acl.Cast<CommonAce>().ToArray();
Require(rules.All(a=>a.AceQualifier==AceQualifier.AccessAllowed),"fixture allows only exact reviewed principals");
Require(rules.Single(r=>r.SecurityIdentifier.Value=="S-1-15-2-1").AccessMask==0x120089,"AAP read-only positive control grant");
Require(rules.All(r=>r.SecurityIdentifier.Value!="S-1-15-2-2" && r.SecurityIdentifier.Value!="S-1-15-2-123"),"fixture has no restricted-package or package grant");
Require(rules.Single(r=>r.SecurityIdentifier==identity.User).AccessMask==0x120089,"human positive control read-only");
Console.WriteLine("PASS production LPAC member policy rejects regular roots/children; exact AAP-only non-secret fixture DACL; no native creation or privacy claims");return 0;
