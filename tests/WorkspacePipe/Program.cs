using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using ClaudeCodeProtection.Workspaces;

WorkspaceFiles.RequireOrdinaryUser();
if(args.Length!=1 || args[0] is not ("frames" or "local-pipe" or "output"))return 125;
static void Require(bool condition,string reason){if(!condition)throw new Exception("WorkspacePipe: "+reason);}
static async Task Refuse(Func<Task> operation,string reason)
{
    try{await operation();}catch(Exception ex)when(ex is InvalidDataException or EndOfStreamException or OperationCanceledException or IOException){return;}
    throw new Exception("WorkspacePipe accepted "+reason);
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
    Console.WriteLine("PASS bounded frames: exact content, max size, invalid lengths, truncation, malformed names; no native calls");return 0;
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
var root=Path.Combine(AppContext.BaseDirectory,"output-fixture-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
var path=Path.Combine(root,"result.bundle.json");var bytes=WorkspaceBundle.Create(new[]{("answer.txt",new byte[]{1,2,255})}).Serialize();
using(var output=WorkspaceFiles.ReserveBundleNew(path))
{
    Require(new FileInfo(path).Length==0,"reserved empty result");output.Complete(bytes);
    var repeat=false;try{output.Complete(bytes);}catch(IOException){repeat=true;}Require(repeat,"repeat output rejected");
}
Require(WorkspaceFiles.ReadBundle(path).AsSpan().SequenceEqual(bytes),"complete result bytes");
var existing=false;try{using var duplicate=WorkspaceFiles.ReserveBundleNew(path);}catch(IOException){existing=true;}Require(existing,"existing result refused");
var canceled=Path.Combine(root,"canceled.bundle.json");using(var output=WorkspaceFiles.ReserveBundleNew(canceled)){}
Require(File.Exists(canceled) && new FileInfo(canceled).Length==0,"canceled reservation preserved");
Console.WriteLine("PASS owned output: new-only, exact bytes, repeat/overwrite refusal and preserved canceled reservation; no UAC or Broker");return 0;
