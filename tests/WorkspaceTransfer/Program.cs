using System.ComponentModel;
using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Workspaces;

static void Require(bool value,string name)
{if(!value)throw new InvalidOperationException("WorkspaceTransfer: "+name);}
static void Refuse(Action action,string name)
{
    try{action();}catch(Exception ex)when(ex is InvalidDataException or JsonException or IOException or UnauthorizedAccessException or Win32Exception){return;}
    throw new InvalidOperationException("WorkspaceTransfer: accepted "+name);
}
static byte[] Bytes(string value)=>Encoding.UTF8.GetBytes(value);
var original=WorkspaceBundle.Create(new[]{("src/main.txt",Bytes("before")),("empty.txt",Array.Empty<byte>()),("raw.bin",new byte[]{0,255,1,128})}).Serialize();
using(var input=new MemoryStream(original))Require(WorkspaceFiles.ReadInput(input,WorkspaceBundle.MaxBundleBytes).AsSpan().SequenceEqual(original),"bounded stdin exact bytes");
using(var over=new MemoryStream(new byte[33]))Refuse(()=>WorkspaceFiles.ReadInput(over,32),"stdin maximum plus one");
Require(WorkspaceBundle.Parse(original).Files.Length==3,"binary and empty roundtrip");
foreach(var name in new[]{"../outside","/absolute","C:/outside","a\\b","a:b","a//b","a/./b","a/../b","CON.txt","CON .txt","PRN .txt","AUX .txt","NUL .dat","COM1 .dat","LPT9 .dat","nul","COM1.dat","LPT9","a.","a ",".git/config","a/.GIT/config","a/*","a/é"})
    Refuse(()=>WorkspaceBundle.Create(new[]{(name,Bytes("x"))}),"path "+name);
foreach(var pair in new[]{("a.txt","A.txt"),("src","src/a.txt"),("src/A.txt","SRC/b.txt"),("src/a.txt","SRC")})
    Refuse(()=>WorkspaceBundle.Create(new[]{(pair.Item1,Bytes("a")),(pair.Item2,Bytes("b"))}),"collision");
Refuse(()=>WorkspaceBundle.Create(Enumerable.Range(0,513).Select(i=>(i+".txt",Array.Empty<byte>()))),"file count");
Refuse(()=>WorkspaceBundle.Create(new[]{("large.bin",new byte[WorkspaceBundle.MaxFileBytes+1])}),"file bytes");
Refuse(()=>WorkspaceBundle.Create(Enumerable.Range(0,9).Select(i=>(i+".bin",new byte[WorkspaceBundle.MaxFileBytes]))),"total bytes");
var bad=WorkspaceBundle.Parse(original);bad.Files.First(f=>f.Content.Length>0).Content[0]^=1;Refuse(()=>bad.Serialize(),"digest tamper");
var duplicate=Encoding.UTF8.GetString(original).Replace("\"SchemaVersion\":1","\"SchemaVersion\":1,\"SchemaVersion\":1",StringComparison.Ordinal);
Refuse(()=>WorkspaceBundle.Parse(Bytes(duplicate)),"duplicate JSON field");
Refuse(()=>WorkspaceBundle.Parse(Bytes(Encoding.UTF8.GetString(original).Replace("\"Scope\":","\"Unknown\":0,\"Scope\":",StringComparison.Ordinal))),"unknown JSON field");
Refuse(()=>WorkspaceBundle.Parse(new byte[WorkspaceBundle.MaxBundleBytes+1]),"serialized size");
var result=WorkspaceBundle.Create(new[]{("src/main.txt",Bytes("after")),("new.txt",Bytes("added")),("raw.bin",new byte[]{0,255,1,128})},WorkspaceBundle.Hash(original)).Serialize();
var changes=WorkspaceBundle.Compare(original,result);
Require(changes.Select(c=>c.Kind).Order().SequenceEqual(new[]{"ADD","DELETE","MODIFY"}),"add modify delete and unchanged");
Refuse(()=>WorkspaceBundle.Compare(original,original),"unbound result");
Refuse(()=>WorkspaceBundle.Compare(result,result),"result cannot be baseline");
Refuse(()=>WorkspaceBundle.Compare(original,WorkspaceBundle.Create(new[]{("EMPTY.txt",Array.Empty<byte>())},WorkspaceBundle.Hash(original)).Serialize()),"case-only rename");
var gitTask=WorkspaceBundle.CreateGitWorkflow(original,"Initial offline import");
var parsedGit=WorkspaceBundle.Parse(gitTask);var gitPlan=parsedGit.GitPlan??throw new InvalidDataException("Git plan missing");
Require(parsedGit.SchemaVersion==2 && gitPlan.BranchName=="main" && parsedGit.Files.Length==3,"explicit Git workflow schema and selected files");
Refuse(()=>WorkspaceBundle.CreateGitWorkflow(original,"bad\nmessage"),"multiline Git commit message");
Refuse(()=>WorkspaceBundle.CreateGitWorkflow(original,"bad\u2028message"),"Unicode line separator commit message");
Refuse(()=>WorkspaceBundle.CreateGitWorkflow(original,"bad\u2029message"),"Unicode paragraph separator commit message");
Refuse(()=>WorkspaceBundle.CreateGitWorkflow(original,new string('x',161)),"oversized Git commit message");
var gitFiles=WorkspaceBundle.Create(parsedGit.Files.Select(f=>(f.Path,f.Content)),WorkspaceBundle.Hash(gitTask)).Serialize();
Refuse(()=>WorkspaceBundle.Compare(gitTask,gitFiles),"Git result without verified workflow receipt");
var gitReceipt=new WorkspaceGitReceipt(1,WorkspaceBundle.GitPlanHash(gitPlan),"main",new string('a',40),new string('b',40),
    gitPlan.CommitMessage,WorkspaceGitPlan.AuthorName,WorkspaceGitPlan.AuthorEmail,gitPlan.CommitUnixTime,
    parsedGit.Files.Length,12,0,1,true,true);
var gitResult=WorkspaceBundle.AttachGitReceipt(gitFiles,gitTask,gitReceipt);
Require(WorkspaceBundle.Compare(gitTask,gitResult).Length==0 && WorkspaceBundle.Parse(gitResult).GitReceipt?.CommitId==gitReceipt.CommitId,
    "Git receipt binds exact plan, branch, message, timestamp and file inventory");
var wrongGitReceipt=gitReceipt with {PlanSHA256=new string('C',64)};
Refuse(()=>WorkspaceBundle.AttachGitReceipt(gitFiles,gitTask,wrongGitReceipt),"foreign Git plan receipt");
Refuse(()=>WorkspaceBundle.Compare(original,gitResult),"Git receipt cannot be attached to data-only baseline");
var reordered=Bytes(Encoding.UTF8.GetString(original)+" ");
Refuse(()=>WorkspaceBundle.Compare(reordered,result),"different exact baseline bytes");

if(args.Length!=1)throw new InvalidDataException("One fresh tool-owned fixture root required");
WorkspaceFiles.RequireOrdinaryUser();
var fixture=args[0];var source=Path.Combine(fixture,"source");var task=Path.Combine(fixture,"task");
if(!Directory.Exists(source) || !Directory.Exists(task))throw new InvalidDataException("Prepared fixture missing");
// The control script supplies only new non-secret fixture paths and two NTFS
// junctions. No host credential/configuration is read by this test.
var selected=new[]{"src/main.txt","raw.bin","empty.txt"};
var captured=WorkspaceFiles.Capture(source,selected);
Require(WorkspaceBundle.Parse(captured).Files.Select(f=>f.Path).SequenceEqual(WorkspaceBundle.Parse(original).Files.Select(f=>f.Path)),"only explicit selection captured");
Require(WorkspaceBundle.Parse(captured).Files.Zip(WorkspaceBundle.Parse(original).Files).All(pair=>pair.First.Content.AsSpan().SequenceEqual(pair.Second.Content)),"selected bytes exact, unselected data absent");
var output=Path.Combine(fixture,"input.bundle.json");WorkspaceFiles.WriteBundleNew(output,captured);
Require(WorkspaceFiles.ReadBundle(output).AsSpan().SequenceEqual(captured),"new bundle persisted");
Refuse(()=>WorkspaceFiles.WriteBundleNew(output,result),"existing output overwrite");
Require(File.ReadAllBytes(output).AsSpan().SequenceEqual(captured),"existing bundle unchanged");
WorkspaceFiles.MaterializeNew(task,"project",captured);
Require(File.ReadAllBytes(Path.Combine(task,"project","raw.bin")).AsSpan().SequenceEqual(new byte[]{0,255,1,128}),"materialized binary");
Refuse(()=>WorkspaceFiles.MaterializeNew(task,"project",captured),"existing directory adoption");
Refuse(()=>WorkspaceFiles.MaterializeNew(task,"../outside",captured),"materialization escape");
File.WriteAllText(Path.Combine(task,"project","src","main.txt"),"edited");
File.WriteAllText(Path.Combine(task,"project","new.txt"),"added");
File.Delete(Path.Combine(task,"project","empty.txt"));
Directory.CreateDirectory(Path.Combine(task,"project",".git"));File.WriteAllText(Path.Combine(task,"project",".git","config"),"EXCLUDED_GIT_METADATA");
var actual=WorkspaceFiles.SnapshotResult(task,"project",captured);
Require(WorkspaceBundle.Compare(captured,actual).Select(c=>c.Kind).Order().SequenceEqual(new[]{"ADD","DELETE","MODIFY"}),"real files result comparison");
Require(WorkspaceBundle.Parse(actual).Files.All(f=>!f.Path.StartsWith(".git/",StringComparison.OrdinalIgnoreCase)),"host Git metadata not exported");
WorkspaceFiles.WriteBundleNew(Path.Combine(fixture,"result.bundle.json"),actual);
var extracted=Path.Combine(fixture,"extracted");WorkspaceFiles.ExtractResultNew(extracted,captured,actual);
Require(File.ReadAllText(Path.Combine(extracted,"src","main.txt"))=="edited" && !File.Exists(Path.Combine(extracted,"empty.txt")),"fresh result extraction add modify delete");
Require(File.ReadAllBytes(Path.Combine(extracted,"raw.bin")).AsSpan().SequenceEqual(new byte[]{0,255,1,128}),"binary extraction exact");
Require(File.ReadAllText(Path.Combine(source,"src","main.txt"))=="before","extraction does not alter original project");
Refuse(()=>WorkspaceFiles.ExtractResultNew(extracted,captured,actual),"existing extraction destination");
var mismatched=Path.Combine(fixture,"wrong-baseline-output");
Refuse(()=>WorkspaceFiles.ExtractResultNew(mismatched,reordered,actual),"wrong baseline extraction");
Require(!Directory.Exists(mismatched),"wrong baseline preflight before mutation");
Refuse(()=>WorkspaceFiles.ExtractResultNew(Path.Combine(fixture,"redirect-output","escaped"),captured,actual),"extraction reparse parent");
var largeBytes=new byte[256*1024];new Random(1729).NextBytes(largeBytes);
var largeInput=WorkspaceBundle.Create(new[]{("data/large.bin",largeBytes)}).Serialize();
var largeResult=WorkspaceBundle.Create(new[]{("data/large.bin",largeBytes)},WorkspaceBundle.Hash(largeInput)).Serialize();
var largeDestination=Path.Combine(fixture,"large-extracted");WorkspaceFiles.ExtractResultNew(largeDestination,largeInput,largeResult);
Require(File.ReadAllBytes(Path.Combine(largeDestination,"data","large.bin")).AsSpan().SequenceEqual(largeBytes),"result exceeds security-ledger bound without truncation");
using(var writer=File.Open(Path.Combine(source,"src","main.txt"),FileMode.Open,FileAccess.Write,FileShare.ReadWrite))
    Refuse(()=>WorkspaceFiles.Capture(source,new[]{"src/main.txt"}),"concurrent writer");
File.AppendAllText(Path.Combine(source,"src","main.txt")," after capture");
Refuse(()=>WorkspaceFiles.Capture(source,new[]{"hardlink.txt"}),"hardlinked source");
Refuse(()=>WorkspaceFiles.Capture(source,new[]{"redirect/outside.txt"}),"reparse ancestor source");
Refuse(()=>WorkspaceFiles.Capture(Path.Combine(source,"redirect"),new[]{"outside.txt"}),"reparse root source");
Refuse(()=>WorkspaceFiles.WriteBundleNew(Path.Combine(fixture,"redirect-output","escaped.json"),captured),"reparse output ancestor");
Refuse(()=>WorkspaceFiles.Capture(source,new[]{"src/main.txt","../outside.txt"}),"selection preflight escape");
Require(!File.Exists(Path.Combine(fixture,"outside","escaped.json")),"outside output absent");
Console.WriteLine(JsonSerializer.Serialize(new {Status="WORKSPACE_TRANSFER_CASES_PASSED",Scope="OWNED_NTFS_FIXTURE_AND_PRODUCTION_TRANSFER_CODE_ONLY",
    BaseSHA256=WorkspaceBundle.Hash(captured),ResultSHA256=WorkspaceBundle.Hash(actual),Changes=WorkspaceBundle.Compare(captured,actual),
    ProductSessionExecuted=false,AppContainerQualified=false,HostPrivacyQualified=false}));
