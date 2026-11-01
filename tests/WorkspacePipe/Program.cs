using System.Buffers.Binary;
using System.ComponentModel;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using ClaudeCodeProtection.Workspaces;

WorkspaceFiles.RequireOrdinaryUser();
if(args.Length!=1 || args[0] is not ("frames" or "local-pipe" or "output" or "snapshot" or "token-membership" or "reply" or "project-contract"))return 125;
static void Require(bool condition,string reason){if(!condition)throw new Exception("WorkspacePipe: "+reason);}
static async Task Refuse(Func<Task> operation,string reason)
{
    try{await operation();}catch(Exception ex)when(ex is InvalidDataException or EndOfStreamException or OperationCanceledException or IOException){return;}
    throw new Exception("WorkspacePipe accepted "+reason);
}
if(args[0]=="project-contract")
{
    var baseline=TextSummarySource.Baseline();var hash=TextSummarySource.BaselineHash;
    Require(hash=="ED3DDCB2F29D378F02186C808A68F2689EAF62B542C079B8F0892F5EAE7E475B","previous actual baseline bytes preserved");
    Require(WorkspaceBundle.Parse(baseline).Files.Length==4,"data-only embedded source inventory");
    TextSummarySource.RequireBaseline(baseline);
    void Reject(Action action,string reason){var rejected=false;try{action();}catch(InvalidDataException){rejected=true;}Require(rejected,reason);}
    var changed=(byte[])baseline.Clone();changed[^2]^=1;
    Reject(()=>TextSummarySource.RequireBaseline(changed),"different caller bytes refused before any execution");
    Dictionary<string,object?> Reply(bool success)=>new(){["SchemaVersion"]=4,["Scope"]=WorkspacePipe.ProjectScope,["ExitCode"]=success?0:3,
        ["SessionId"]=new string('a',32),["BaseSHA256"]=hash,["ResultSHA256"]=success?new string('B',64):null,
        ["Status"]=success?"BUNDLED_PROJECT_DEVELOPED_AND_CLEANED":"BUNDLED_PROJECT_NOT_CONFIRMED",
        ["FailureStage"]=success?null:"processing",["FailureKind"]=success?null:"ResourceSessionFailed",["FailureCode"]=success?null:3,
        ["CreationEvidence"]=null,["StopEvidence"]=null};
    var success=JsonSerializer.SerializeToUtf8Bytes(Reply(true));
    Require(WorkspacePipe.ParseReply(success,hash,true).ExitCode==0,"explicit fixed project success");
    Require(WorkspacePipe.ParseReply(JsonSerializer.SerializeToUtf8Bytes(Reply(false)),hash,true).ResultSHA256 is null,"project failure never releases output");
    Reject(()=>WorkspacePipe.ParseReply(success,hash),"DATA parser refuses project reply");
    foreach(var successMode in new[]{true,false})
    {
        foreach(var field in new[]{"Scope","SchemaVersion","BaseSHA256","Status"})
        {
            var reply=Reply(successMode);reply[field]=field switch {"Scope"=>"DATA", "SchemaVersion"=>3,"BaseSHA256"=>new string('C',64),_=>"WORKSPACE_DATA_PROCESSED_AND_CLEANED"};
            Reject(()=>WorkspacePipe.ParseReply(JsonSerializer.SerializeToUtf8Bytes(reply),hash,true),"mixed project/data contract "+field);
        }
    }
    var v3=Reply(true);v3.Remove("Scope");v3["SchemaVersion"]=3;v3["Status"]="WORKSPACE_DATA_PROCESSED_AND_CLEANED";
    Require(WorkspacePipe.ParseReply(JsonSerializer.SerializeToUtf8Bytes(v3),hash).ExitCode==0,"unchanged DATA contract");
    Reject(()=>WorkspacePipe.ParseReply(JsonSerializer.SerializeToUtf8Bytes(v3),hash,true),"project parser refuses DATA receipt");
    var unpinned=Reply(true);unpinned["BaseSHA256"]=new string('C',64);
    Reject(()=>WorkspacePipe.ParseReply(JsonSerializer.SerializeToUtf8Bytes(unpinned),new string('C',64),true),"arbitrary expected digest cannot authorize project");
    using var self=WindowsIdentity.GetCurrent();WorkspaceFiles.RequireOrdinaryToken(self.AccessToken);
    using var invalid=new Microsoft.Win32.SafeHandles.SafeAccessTokenHandle(IntPtr.Zero);
    var queryFailed=false;try{WorkspaceFiles.RequireOrdinaryToken(invalid);}catch(Win32Exception ex)when(ex.NativeErrorCode==6){queryFailed=true;}
    Require(queryFailed,"failed token query refuses caller");
    Console.WriteLine("PASS fixed project IPC contract: unchanged actual baseline, caller-byte refusal, explicit v4/scope, v3 DATA separation, failure-no-output, own ordinary token and failed-query refusal; no UAC/product/Job/project execution or actual LPAC-token qualification");return 0;
}
if(args[0]=="token-membership")
{
    using(var queryOnly=WindowsIdentity.GetCurrent(TokenAccessLevels.Query))
    {
        var refused=false;try{_=new WindowsPrincipal(queryOnly).IsInRole(WindowsBuiltInRole.Administrator);}
        catch(System.Security.SecurityException){refused=true;}
        Require(refused,"original query-only membership failure reproduced");
    }
    using var reviewed=WindowsIdentity.GetCurrent((TokenAccessLevels)WorkspacePipe.CallerTokenQueryAccess);
    Require(!new WindowsPrincipal(reviewed).IsInRole(WindowsBuiltInRole.Administrator),"reviewed ordinary caller classification");
    Require(WorkspacePipe.CallerTokenQueryAccess==(uint)(TokenAccessLevels.Query|TokenAccessLevels.Duplicate),"membership-only token rights");
    Console.WriteLine("PASS self token membership: original query-only refusal, production query/duplicate succeeds as ordinary; no other process, impersonation, elevation or Job");return 0;
}
if(args[0]=="reply")
{
    var hash=new string('A',64);var session=new string('a',32);
    Dictionary<string,object?> Success()=>new(){["SchemaVersion"]=3,["ExitCode"]=0,["SessionId"]=session,["BaseSHA256"]=hash,["ResultSHA256"]=hash,
        ["Status"]="WORKSPACE_DATA_PROCESSED_AND_CLEANED",["FailureStage"]=null,["FailureKind"]=null,["FailureCode"]=null,["CreationEvidence"]=null,["StopEvidence"]=null};
    Dictionary<string,object?> Failure()=>new(){["SchemaVersion"]=3,["ExitCode"]=125,["SessionId"]=null,["BaseSHA256"]=hash,["ResultSHA256"]=null,
        ["Status"]="WORKSPACE_DATA_NOT_CONFIRMED",["FailureStage"]="caller",["FailureKind"]="SecurityException",["FailureCode"]=-2146233078,["CreationEvidence"]=null,["StopEvidence"]=null};
    void Reject(Dictionary<string,object?> value,string reason)
    {
        var refused=false;try{_=WorkspacePipe.ParseReply(JsonSerializer.SerializeToUtf8Bytes(value),hash);}catch(InvalidDataException){refused=true;}
        Require(refused,"reply "+reason);
    }
    Require(WorkspacePipe.ParseReply(JsonSerializer.SerializeToUtf8Bytes(Success()),hash).ExitCode==0,"success contract");
    var failed=WorkspacePipe.ParseReply(JsonSerializer.SerializeToUtf8Bytes(Failure()),hash);
    Require(failed.FailureStage=="caller" && failed.ResultSHA256 is null && failed.SessionId is null && failed.ExitCode==125,"actionable pre-session refusal without result");
    var runtime=Failure();runtime["SessionId"]=session;runtime["FailureStage"]="processing";runtime["ExitCode"]=3;runtime["FailureKind"]="ResourceSessionFailed";runtime["FailureCode"]=3;
    Require(WorkspacePipe.ParseReply(JsonSerializer.SerializeToUtf8Bytes(runtime),hash).SessionId==session,"exact resource receipt binding on failure");
    var value=Success();value["Extra"]=0;Reject(value,"unknown field");
    value=Success();value.Remove("FailureCode");Reject(value,"missing field");
    value=Success();value["BaseSHA256"]=new string('B',64);Reject(value,"wrong input binding");
    value=Success();value["SessionId"]=null;Reject(value,"missing success session");
    value=Success();value["FailureStage"]="caller";Reject(value,"contradictory success");
    value=Failure();value["ResultSHA256"]=hash;Reject(value,"result on failure");
    value=Failure();value["FailureStage"]="C:\\private";Reject(value,"host path as stage");
    value=Failure();value["FailureKind"]="private data";Reject(value,"arbitrary failure text");
    value=Failure();value["SessionId"]="../bad";Reject(value,"invalid session");
    Dictionary<string,object?> Creation()=>new(){["ChildProcessPolicy"]=0,["ChildPolicyQueryError"]=null,["ImageLoadPolicy"]=0,["ImagePolicyQueryError"]=null,["ImageExecuteOpenError"]=0};
    Dictionary<string,object?> Stop()=>new(){["AdmissionClosed"]=true,["QuarantineObservedBeforeStop"]=true,["FinalJobZero"]=true,["StopFailureCount"]=0};
    Dictionary<string,object?> Diagnostic(){var v=Failure();v["SessionId"]=session;v["FailureStage"]="processing";v["FailureKind"]="PowerShellCreateProcess";v["FailureCode"]=5;v["CreationEvidence"]=Creation();v["StopEvidence"]=Stop();return v;}
    var diag=WorkspacePipe.ParseReply(JsonSerializer.SerializeToUtf8Bytes(Diagnostic()),hash);
    Require(diag.CreationEvidence?.ImageExecuteOpenError==0 && diag.StopEvidence?.FinalJobZero==true && diag.ResultSHA256 is null,"failure diagnostics never release a result");
    var unknown=Diagnostic();var observed=Creation();observed["ChildProcessPolicy"]=null;observed["ChildPolicyQueryError"]=87;unknown["CreationEvidence"]=observed;
    var unknownStop=Stop();unknownStop["FinalJobZero"]=null;unknown["StopEvidence"]=unknownStop;
    var retained=WorkspacePipe.ParseReply(JsonSerializer.SerializeToUtf8Bytes(unknown),hash);
    Require(retained.CreationEvidence?.ChildProcessPolicy is null && retained.CreationEvidence?.ChildPolicyQueryError==87 && retained.StopEvidence?.FinalJobZero is null,"unobserved values retain null and actual error");
    var execute=Diagnostic();observed=Creation();observed["ImageExecuteOpenError"]=5;execute["CreationEvidence"]=observed;execute["FailureKind"]="PowerShellImageExecuteOpen";
    Require(WorkspacePipe.ParseReply(JsonSerializer.SerializeToUtf8Bytes(execute),hash).CreationEvidence?.ImageExecuteOpenError==5,"exact image access denial distinguished");
    foreach(var key in new[]{"ChildProcessPolicy","ImageLoadPolicy"})foreach(var invalid in new object[]{-1,4294967296UL,"C:\\private"})
    {value=Diagnostic();observed=Creation();observed[key]=invalid;value["CreationEvidence"]=observed;Reject(value,"invalid policy value");}
    foreach(var key in new[]{"ChildPolicyQueryError","ImagePolicyQueryError","ImageExecuteOpenError"})
    {value=Diagnostic();observed=Creation();observed[key]=-1;value["CreationEvidence"]=observed;Reject(value,"negative native error");}
    value=Diagnostic();observed=Creation();observed["ChildProcessPolicy"]=null;value["CreationEvidence"]=observed;Reject(value,"missing policy observation and error");
    value=Diagnostic();observed=Creation();observed["ChildPolicyQueryError"]=5;value["CreationEvidence"]=observed;Reject(value,"contradictory policy observation");
    value=Diagnostic();observed=Creation();observed["ImageExecuteOpenError"]=null;value["CreationEvidence"]=observed;Reject(value,"missing execute observation");
    value=Diagnostic();observed=Creation();observed["Path"]="C:\\private";value["CreationEvidence"]=observed;Reject(value,"unknown diagnostic field");
    value=Diagnostic();var stopFields=Stop();stopFields["PrivateCleanupConfirmed"]=true;value["StopEvidence"]=stopFields;Reject(value,"cleanup claim outside stop scope");
    foreach(var invalid in new object[]{-1,1025,"private"}){value=Diagnostic();stopFields=Stop();stopFields["StopFailureCount"]=invalid;value["StopEvidence"]=stopFields;Reject(value,"invalid stop count");}
    value=Diagnostic();stopFields=Stop();stopFields["FinalJobZero"]=1;value["StopEvidence"]=stopFields;Reject(value,"numeric stop observation");
    value=Diagnostic();value["SessionId"]=null;Reject(value,"unbound diagnostics");
    value=Diagnostic();value["FailureStage"]="input";Reject(value,"pre-session diagnostics");
    value=Success();value["CreationEvidence"]=Creation();Reject(value,"diagnostic masquerading as success");
    value=Success();value["StopEvidence"]=Stop();Reject(value,"stop observation masquerading as result authority");
    value=Diagnostic();value["SchemaVersion"]=2;Reject(value,"mixed-version package");
    var duplicate=JsonSerializer.Serialize(Success()).Replace("\"SchemaVersion\":3","\"SchemaVersion\":3,\"SchemaVersion\":3",StringComparison.Ordinal);
    var refusedDuplicate=false;try{_=WorkspacePipe.ParseReply(System.Text.Encoding.UTF8.GetBytes(duplicate),hash);}catch(InvalidDataException){refusedDuplicate=true;}
    Require(refusedDuplicate,"duplicate reply fields");
    duplicate=JsonSerializer.Serialize(Diagnostic()).Replace("\"ChildProcessPolicy\":0","\"ChildProcessPolicy\":0,\"ChildProcessPolicy\":0",StringComparison.Ordinal);
    refusedDuplicate=false;try{_=WorkspacePipe.ParseReply(System.Text.Encoding.UTF8.GetBytes(duplicate),hash);}catch(InvalidDataException){refusedDuplicate=true;}
    Require(refusedDuplicate,"duplicate nested diagnostic fields");
    Console.WriteLine("PASS reply v3: bounded native/stop diagnostics, null stays unknown, exact session, no failed result/private text/cleanup or admission authority; no IPC/UAC/Job");return 0;
}
if(args[0]=="frames")
{
    using var limit=new CancellationTokenSource(TimeSpan.FromSeconds(15));
    foreach(var length in new[]{1,4096,WorkspaceBundle.MaxBundleBytes})
    {
        var content=new byte[length];content[0]=17;content[^1]=255;
        using var stream=new MemoryStream();await WorkspacePipe.Write(stream,content,WorkspaceBundle.MaxBundleBytes,limit.Token);
        stream.Position=0;var result=await WorkspacePipe.Read(stream,WorkspaceBundle.MaxBundleBytes,limit.Token);
        Require(result.AsSpan().SequenceEqual(content),"frame content");
    }
    foreach(var length in new[]{-1,0,WorkspaceBundle.MaxBundleBytes+1,int.MaxValue})
    {
        var header=new byte[4];BinaryPrimitives.WriteInt32LittleEndian(header,length);
        await Refuse(async()=>{using var stream=new MemoryStream(header);_=await WorkspacePipe.Read(stream,WorkspaceBundle.MaxBundleBytes,limit.Token);},"oversized/negative/empty frame");
    }
    await Refuse(async()=>{using var stream=new MemoryStream(new byte[3]);_=await WorkspacePipe.Read(stream,10,limit.Token);},"partial header");
    var truncated=new byte[8];BinaryPrimitives.WriteInt32LittleEndian(truncated,10);
    await Refuse(async()=>{using var stream=new MemoryStream(truncated);_=await WorkspacePipe.Read(stream,10,limit.Token);},"partial payload");
    await Refuse(async()=>{using var stream=new MemoryStream();await WorkspacePipe.Write(stream,Array.Empty<byte>(),10,limit.Token);},"empty write");
    foreach(var nonce in new[]{"","../bad",new string('A',32),new string('g',32),new string('a',33)})
    {
        var refused=false;try{_=WorkspacePipe.Name(Environment.ProcessId,nonce);}catch(InvalidDataException){refused=true;}
        Require(refused,"ambiguous pipe name");
    }
    Console.WriteLine("PASS bounded frames: exact content, max size, invalid lengths, truncation, malformed names; no pipe or file query");return 0;
}
if(args[0]=="local-pipe")
{
    var nonce=Guid.NewGuid().ToString("N");
    using var server=WorkspacePipe.Create(Environment.ProcessId,nonce);
    using var current=WindowsIdentity.GetCurrent();
    var security=server.GetAccessControl();
    var allows=security.GetAccessRules(true,true,typeof(SecurityIdentifier)).Cast<PipeAccessRule>().Where(r=>r.AccessControlType==AccessControlType.Allow).ToArray();
    Require(security.AreAccessRulesProtected && allows.Length==1 && allows[0].IdentityReference.Value==current.User!.Value,"pipe ACL only human SID");
    var duplicateRefused=false;
    try{using var duplicate=WorkspacePipe.Create(Environment.ProcessId,nonce);}catch(IOException){duplicateRefused=true;}
    Require(duplicateRefused,"first instance exclusivity");
    using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(10));
    using var client=new NamedPipeClientStream(".",WorkspacePipe.Name(Environment.ProcessId,nonce),PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification);
    var accepted=server.WaitForConnectionAsync(deadline.Token);await client.ConnectAsync(deadline.Token);await accepted;
    WorkspacePipe.AssertPeer(server,Environment.ProcessId,true);WorkspacePipe.AssertPeer(client,Environment.ProcessId,false);
    var wrongPeer=false;try{WorkspacePipe.AssertPeer(server,Environment.ProcessId+1,true);}catch(InvalidDataException){wrongPeer=true;}
    Require(wrongPeer,"different PID rejected");
    var baseline=WorkspaceBundle.Create(new[]{("README.md",new byte[]{17,255}), ("src/main.cs",new byte[]{1,2})}).Serialize();
    var send=WorkspacePipe.Write(server,baseline,WorkspaceBundle.MaxBundleBytes,deadline.Token);
    var input=await WorkspacePipe.Read(client,WorkspaceBundle.MaxBundleBytes,deadline.Token);await send;
    Require(input.AsSpan().SequenceEqual(baseline),"ordinary selected input transferred");
    var result=WorkspaceBundle.Create(new[]{("README.md",new byte[]{17,255}), ("src/main.cs",new byte[]{3,4})},WorkspaceBundle.Hash(input)).Serialize();
    var response=WorkspacePipe.Write(client,result,WorkspaceBundle.MaxBundleBytes,deadline.Token);
    var received=await WorkspacePipe.Read(server,WorkspaceBundle.MaxBundleBytes,deadline.Token);await response;
    Require(WorkspaceBundle.Compare(baseline,received).Length==1,"result baseline binding");
    await client.WriteAsync(new byte[]{1,2},deadline.Token);client.Dispose();
    await Refuse(async()=>{_=await WorkspacePipe.Read(server,10,deadline.Token);},"peer disconnected during header");
    Console.WriteLine("PASS local pipe: owner ACL, first instance, both peer PIDs, wrong PID rejection, selected-data roundtrip; no UAC or Broker");return 0;
}
if(args[0]=="snapshot")
{
    var task=Path.Combine(AppContext.BaseDirectory,"s-"+Guid.NewGuid().ToString("N")[..8]);Directory.CreateDirectory(task);
    var baseline=WorkspaceBundle.Create(new[]{("src/main.txt",new byte[]{1,2}), ("raw.bin",new byte[]{0,255,128}), ("empty.txt",Array.Empty<byte>())}).Serialize();
    WorkspaceFiles.MaterializeNew(task,"project",baseline);var project=Path.Combine(task,"project");
    File.WriteAllBytes(Path.Combine(project,"src","main.txt"),new byte[]{3,4});File.Delete(Path.Combine(project,"empty.txt"));
    Directory.CreateDirectory(Path.Combine(project,".git"));File.WriteAllText(Path.Combine(project,".git","config"),"EXCLUDED_OWNED_FIXTURE");
    Directory.CreateDirectory(Path.Combine(project,"unused"));
    // More than one 64KiB FILE_NAMES_INFORMATION page, within existing bundle
    // count/size/path bounds. No host project/private state or product session.
    var added=Enumerable.Range(0,450).Select(i=>WorkspaceBundle.Relative(i.ToString("D3")+new string('x',73)+".txt")).ToArray();
    foreach(var leaf in added)File.WriteAllBytes(Path.Combine(project,leaf),new byte[]{42});
    var result=WorkspaceFiles.SnapshotResult(task,"project",baseline);var files=WorkspaceBundle.Parse(result).Files;
    Require(files.Length==452 && added.All(n=>files.Any(f=>f.Path==n && f.Content.AsSpan().SequenceEqual(new byte[]{42}))),"multi-page names and exact added content");
    Require(files.Single(f=>f.Path=="raw.bin").Content.AsSpan().SequenceEqual(new byte[]{0,255,128}),"binary snapshot exact");
    var changes=WorkspaceBundle.Compare(baseline,result);
    Require(changes.Count(c=>c.Kind=="ADD")==450 && changes.Count(c=>c.Kind=="MODIFY")==1 && changes.Count(c=>c.Kind=="DELETE")==1,"nested changes and baseline binding");
    Require(files.All(f=>!f.Path.StartsWith(".git/",StringComparison.OrdinalIgnoreCase)),"Git metadata excluded");
    using(var writer=File.Open(Path.Combine(project,"raw.bin"),FileMode.Open,FileAccess.Write,FileShare.ReadWrite))
    {
        var refused=false;try{_=WorkspaceFiles.SnapshotResult(task,"project",baseline);}
        catch(Win32Exception ex)when(ex.NativeErrorCode==32){refused=true;}
        Require(refused,"snapshot concurrent writer refused with sharing violation");
    }
    WorkspaceFiles.WriteBundleNew(Path.Combine(task,"result.bundle.json"),result);
    Console.WriteLine("PASS owned names-only snapshot: multiple pages, nested/binary/empty directories, add/modify/delete, Git exclusion, concurrent writer refusal; no Broker or cleanup");return 0;
}
var root=Path.Combine(AppContext.BaseDirectory,"output-fixture-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
var path=Path.Combine(root,"result.bundle.json");var bytes=WorkspaceBundle.Create(new[]{("answer.txt",new byte[]{1,2,255})}).Serialize();
using(var output=WorkspaceFiles.ReserveBundleNew(path))
{
    Require(new FileInfo(path).Length==0,"reserved empty result");output.Complete(bytes);
    var repeat=false;try{output.Complete(bytes);}catch(IOException){repeat=true;}Require(repeat,"repeat output rejected");
}
Require(WorkspaceFiles.ReadBundle(path).AsSpan().SequenceEqual(bytes),"complete result bytes");
var existing=false;try{using var duplicate=WorkspaceFiles.ReserveBundleNew(path);}catch(Win32Exception ex)when(ex.NativeErrorCode is 80 or 183){existing=true;}Require(existing,"existing result refused");
var canceled=Path.Combine(root,"canceled.bundle.json");using(var output=WorkspaceFiles.ReserveBundleNew(canceled)){}
Require(File.Exists(canceled) && new FileInfo(canceled).Length==0,"canceled reservation preserved");
Console.WriteLine("PASS owned output: new-only, exact bytes, repeat/overwrite refusal and preserved canceled reservation; no UAC or Broker");return 0;
