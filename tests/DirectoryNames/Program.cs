using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

// Qualification only. No Broker/Bootstrap, AppContainer/Job/WFP, elevation,
// existing private state, host directory enumeration, project code or network.
// This program has NOT been cleared to run by its presence in the repository.
if(args.Length!=1 || args[0] is not ("pages-only" or "owned-fixture"))return 125;
ProtectionLifecycle.DirectoryNamePageCases.Run();
if(args[0]=="pages-only")return 0;
using(var identity=System.Security.Principal.WindowsIdentity.GetCurrent())
    if(new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
        throw new InvalidOperationException("Ordinary user qualification only");
var root=Path.Combine(AppContext.BaseDirectory,"names-fixture-"+Guid.NewGuid().ToString("N"));
if(Directory.Exists(root) || File.Exists(root))throw new IOException("Fresh fixture required");
Directory.CreateDirectory(root);
// Leave fixture and receipt for exact later inspection; never recursive erase.
var assembly=Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory,"ProtectionLifecycle.dll"));
var seal=assembly.GetType("ProtectionLifecycle.WindowsPathSeal",true)!;
var lease=assembly.GetType("ProtectionLifecycle.PathLease",true)!;
var policy=assembly.GetType("ProtectionLifecycle.PathPolicy",true)!;
const BindingFlags flags=BindingFlags.Static|BindingFlags.NonPublic;
var open=seal.GetMethod("LockDirectory",flags,null,new[]{typeof(string),policy},null)!;
var scan=seal.GetMethod("EnumerateNames",flags,null,new[]{lease,typeof(int)},null)!;
static object? Invoke(MethodInfo method,params object[] arguments)
{
    try{return method.Invoke(null,arguments);}
    catch(TargetInvocationException ex)when(ex.InnerException is not null)
    {ExceptionDispatchInfo.Capture(ex.InnerException).Throw();throw;}
}
using var held=(IDisposable)Invoke(open,root,Enum.Parse(policy,"Source"))!;
string[] Scan(int maximum=512)=>(string[])Invoke(scan,held,maximum)!;
if(Scan().Length!=0)throw new Exception("Fresh names not empty");
var expected=new List<string>{"alpha.json","项目.bin","nested"};
File.WriteAllText(Path.Combine(root,"alpha.json"),"{}");
File.WriteAllBytes(Path.Combine(root,"项目.bin"),new byte[]{0,255,1,128});
Directory.CreateDirectory(Path.Combine(root,"nested"));
File.WriteAllText(Path.Combine(root,"nested","outside-top-level.txt"),"no traversal");
for(var i=0;i<480;i++)
{
    var name="entry-"+i.ToString("D3")+"-"+new string('x',58)+".txt";
    File.WriteAllText(Path.Combine(root,name),"fixed fixture");expected.Add(name);
}
// Require a real continuation, not just multiple records in one native page.
if(expected.Sum(n=>(12+n.Length*2+3)&~3)<=65536)throw new Exception("Fixture does not exceed one native page");
void Match()
{
    if(!Scan().OrderBy(n=>n,StringComparer.Ordinal).SequenceEqual(expected.OrderBy(n=>n,StringComparer.Ordinal)))
        throw new Exception("Names differ, nested traversal, or shared cursor reused");
}
Match();Match();
var bounded=false;try{_=Scan(1);}catch(InvalidDataException){bounded=true;}
if(!bounded)throw new Exception("Inventory bound did not refuse");
File.WriteAllText(Path.Combine(root,"late.txt"),"fresh independent cursor");expected.Add("late.txt");Match();
held.Dispose();
// Exact removal holds a DELETE-capable directory handle. Exercise the same
// sharing contract on our own fixture without marking/deleting any object.
var create=seal.GetMethod("CreateFile",flags)!;
using var deletionHandle=(SafeFileHandle)Invoke(create,root,0x130080u,1u,IntPtr.Zero,3u,0x02200000u,IntPtr.Zero)!;
if(deletionHandle.IsInvalid)throw new Exception("Fixture DELETE-capable handle failed");
var scanHeld=seal.GetMethod("EnumerateNames",flags,null,new[]{typeof(SafeFileHandle),typeof(string),typeof(int)},null)!;
var deletionNames=(string[])Invoke(scanHeld,deletionHandle,root,512)!;
if(!deletionNames.OrderBy(n=>n,StringComparer.Ordinal).SequenceEqual(expected.OrderBy(n=>n,StringComparer.Ordinal)))
    throw new Exception("Names query incompatible with exact-removal held handle");
var report=new{Scope="ORDINARY_OWNED_TEMP_NAMES_ONLY",Root=root,Names=expected.OrderBy(n=>n,StringComparer.Ordinal).ToArray(),
    Status="NAMES_ONLY_FIXTURE_PASSED",PrivateStateRead=false,BrokerExecuted=false,ProductInstalled=false,NetworkOpened=false,SettingsChanged=false,
    Claim="Parser and names-only query behavior only; does not prove old crash fixed or general filesystem stability"};
File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"names-fixture-result-"+Path.GetFileName(root)+".json"),JsonSerializer.Serialize(report));
Console.WriteLine(JsonSerializer.Serialize(report));return 0;
