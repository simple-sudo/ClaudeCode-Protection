using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ProtectionLifecycle;

using var identity=WindowsIdentity.GetCurrent();
if(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))throw new InvalidOperationException("Ordinary context required");
if(args.Length==2 && args[0]=="host-wddm")
{
    const BindingFlags hidden=BindingFlags.NonPublic|BindingFlags.Static;
    var library=typeof(InstalledBroker).Assembly;
    var probe=library.GetType("ProtectionLifecycle.WddmAdapterProbe",true)!;
    var job=new string('a',32);
    var actor=probe.GetMethod("Capture",hidden)!.Invoke(null,[job])!;
    var actorJson=JsonSerializer.SerializeToElement(actor,actor.GetType());
    var parse=probe.GetMethod("Parse",hidden)!;
    var created=actorJson.GetProperty("CreatedFileTime").GetInt64();
    using var stream=new MemoryStream(Encoding.UTF8.GetBytes(actorJson.GetRawText()));
    _=parse.Invoke(null,[stream,job,(uint)Environment.ProcessId,created]);
    stream.Position=0;
    var wrongActorRefused=false;
    try{_=parse.Invoke(null,[stream,job,(uint)Environment.ProcessId+1,created]);}
    catch(TargetInvocationException ex)when(ex.InnerException is InvalidDataException){wrongActorRefused=true;}
    var cuda=library.GetType("ProtectionLifecycle.GpuIdentityObservation",true)!.GetMethod("Read",hidden)!.Invoke(null,null)!;
    var wddmJson=actorJson.GetProperty("Result");
    var cudaJson=JsonSerializer.SerializeToElement(cuda,cuda.GetType());
    var adapters=wddmJson.GetProperty("Adapters").EnumerateArray().ToArray();
    var luid=cudaJson.GetProperty("Luid").GetString();
    var matches=luid is null?0:adapters.Count(row=>row.GetProperty("Luid").GetString()==luid);
    var allClosed=adapters.All(row=>row.GetProperty("CloseStatus").GetInt32()==0);
    using(var raw=new FileStream(args[1],FileMode.CreateNew,FileAccess.Write,FileShare.None))
    {
        JsonSerializer.Serialize(raw,new{Wddm=wddmJson,Cuda=cudaJson});
        raw.Flush(flushToDisk:true);
    }
    Console.WriteLine(JsonSerializer.Serialize(new{Scope="ORDINARY_WDDM_CUDA_REAL_LUID_COMPARISON",
        Count=adapters.Length,AdapterSizeStatus=wddmJson.GetProperty("SizeStatus"),
        AdapterReadStatus=wddmJson.GetProperty("ReadStatus"),Matches=matches,AllAdapterHandlesClosed=allClosed,
        WrongActorRefused=wrongActorRefused,RestrictedActorExecuted=false}));
    return matches==1 && allClosed && wrongActorRefused?0:3;
}
if(args.Length==2 && args[0] is "access-fault-child" or "access-cuda-child")
{
    Console.WriteLine(GetCurrentThreadId());
    Console.Out.Flush();
    TraceType().GetMethod("WaitForObserver",BindingFlags.NonPublic|BindingFlags.Static)!.Invoke(null,null);
    if(args[0]=="access-fault-child")
    {
        RaiseException(0xc0000005,1,2,[0,16]);
        return 125;
    }
    args[0]="split-native-child";
}
if(args.Length==1 && args[0] is "host-access-trace" or "host-access-cuda")
{
    var actualCuda=args[0]=="host-access-cuda";
    var traceNonce=new string('a',32);
    using var child=Start(actualCuda?"access-cuda-child":"access-fault-child",traceNonce);
    using var trace=(IDisposable)Activator.CreateInstance(TraceType(),nonPublic:true)!;
    var stderr=child.StandardError.ReadToEndAsync();
    var line=await child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5));
    var thread=uint.Parse(line!,System.Globalization.CultureInfo.InvariantCulture);
    var stdout=child.StandardOutput.ReadToEndAsync();
    var health=(Action)(()=>{});
    const BindingFlags hidden=BindingFlags.NonPublic|BindingFlags.Instance;
    TraceType().GetMethod("Observe",hidden)!.Invoke(trace,[child.SafeHandle,(uint)child.Id,thread,health]);
    await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
    var evidence=TraceType().GetMethod("Snapshot",hidden)!.Invoke(trace,null)!;
    var result=JsonSerializer.SerializeToElement(evidence,evidence.GetType());
    Console.WriteLine(JsonSerializer.Serialize(new{Scope=actualCuda?"ORDINARY_OWN_CUDA_MAPPING_WITH_ACCESS_TRACE":"ORDINARY_OWN_SOFTWARE_RAISED_ACCESS_VIOLATION",ExitCode=(uint)child.ExitCode,
        StderrLength=(await stderr).Length,Trace=result,RestrictedExecution=false}));
    if(actualCuda)
    {
        var progressReader=new GpuCallProgressReader(traceNonce,true,splitInit:true);
        progressReader.Bind(child.Id);
        var report=await progressReader.ReadClosedCaptureAsync(new StringReader(await stdout));
        return report is not null && progressReader.ReportsCompleteSuccessfulSequence && child.ExitCode==0 &&
            result.GetProperty("DriverMappingObserved").GetBoolean() && result.GetProperty("ExitEventContinued").GetBoolean()?0:3;
    }
    var first=result.GetProperty("FirstChance");
    return result.GetProperty("ExitEventContinued").GetBoolean() &&
        first.GetProperty("Access").GetString()=="READ" &&
        first.GetProperty("TargetAddressClass").GetString()=="LOW_ADDRESS" &&
        first.GetProperty("InstructionImage").GetString()=="kernelbase.dll" &&
        first.GetProperty("RelativeVirtualAddress").GetUInt32()>0?0:3;
}
if(args.Length==2 && args[0]=="host-loader" && args[1] is "default" or "deferred-jit")
{
    var optOut=args[1]=="deferred-jit";
    Environment.SetEnvironmentVariable("CUDA_FORCE_PRELOAD_LIBRARIES",optOut?"0":null);
    var steps=new List<GpuInitLoader.Checkpoint>();
    void ObserveLoader(GpuInitLoader.Checkpoint step)
    {
        steps.Add(step);
        Console.WriteLine(JsonSerializer.Serialize(new{Actor="ORDINARY_REFERENCE",Phase=step.Phase.ToString(),step.Returned,step.Code,
            step.InDriverImage,ProcessLocalPreloadOptOut=optOut}));
        Console.Out.Flush();
    }
    using var loader=GpuInitLoader.Open(ObserveLoader);
    if(loader.Invoke(ObserveLoader)!=0 || !steps.SequenceEqual(new GpuInitLoader.Checkpoint[]{
        new(GpuInitLoader.Phase.Load,false,null),new(GpuInitLoader.Phase.Load,true,0),
        new(GpuInitLoader.Phase.Resolve,false,null),new(GpuInitLoader.Phase.Resolve,true,0,true),
        new(GpuInitLoader.Phase.Invoke,false,null),new(GpuInitLoader.Phase.Invoke,true,0)}))return 3;
    try{_=loader.Invoke(ObserveLoader);return 4;}
    catch(InvalidOperationException) when(steps.Count==6){return 0;}
}
if(args.Length==2 && args[0] is "fixture-child" or "native-child" or "split-native-child")
{
    var childNonce=args[1];var childPid=Environment.ProcessId;
    if(args[0]=="fixture-child")
    {
        var writer=new GpuCallProgressWriter(Console.Out,childNonce,childPid);writer.Emit(0,0,null);
        if(await Console.In.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5))!="GO")return 125;
        writer.Emit(0,1,0);Console.WriteLine(Final(childNonce,childPid));return 0;
    }
    var library=typeof(InstalledBroker).Assembly;const BindingFlags hidden=BindingFlags.NonPublic|BindingFlags.Instance|BindingFlags.Public;
    var plan=Activator.CreateInstance(library.GetType("ProtectionLifecycle.GpuProbePlan",true)!,hidden,null,new object[]{childNonce,1},null)!;
    var progress=Activator.CreateInstance(library.GetType("ProtectionLifecycle.GpuCallProgressWriter",true)!,hidden,null,new object[]{Console.Out,childNonce,childPid},null)!;
    var gpu=library.GetType("ProtectionLifecycle.GpuQualification",true)!;
    var method=args[0]=="split-native-child"?"ComputeWithSplitInit":"Compute";
    var report=gpu.GetMethod(method,BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,new[]{plan,"ORDINARY_HOST_GPU_PROGRESS_REFERENCE",progress})!;
    Console.WriteLine(JsonSerializer.Serialize(report,report.GetType()));
    return (bool)gpu.GetMethod("Qualified",BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,new[]{report})!?0:3;
}
if(args.Length!=1 || args[0] is not ("policy" or "host-compute" or "host-split-compute"))return 64;
var nonce=new string('a',32);const int pid=42;var checks=0;
void Check(bool condition,string name){checks++;if(!condition)throw new Exception("FAILED: "+name);}
GpuCallProgressReader Reader(bool required=true){var value=new GpuCallProgressReader(nonce,required);value.Bind(pid);return value;}
string Frame(int sequence,int api,int phase,int? code=null,string? n=null,int p=pid)=>JsonSerializer.Serialize(new{Kind="GPU_CALL_PROGRESS_V1",Nonce=n??nonce,Pid=p,Sequence=sequence,Api=api,Phase=phase,Code=code})+"\n";
async Task Reject(string input,string name)
{
    try{_=await Reader().ReadAsync(new StringReader(input));}
    catch(Exception error)when(error is InvalidDataException or JsonException){checks++;return;}
    throw new Exception("ACCEPTED: "+name);
}
if(args[0] is "host-compute" or "host-split-compute")
{
    var split=args[0]=="host-split-compute";
    using var child=Start(split?"split-native-child":"native-child",nonce);
    var reader=new GpuCallProgressReader(nonce,true,splitInit:split);reader.Bind(child.Id);
    var text=child.StandardOutput.ReadToEndAsync();var errors=child.StandardError.ReadToEndAsync();
    if(!child.WaitForExit(20000)){Console.Error.WriteLine("HOST_GPU_REFERENCE_STILL_RUNNING_ORIGINAL_HANDLE_HELD");child.WaitForExit();}
    var captured=await text;
    var finalText=await reader.ReadClosedCaptureAsync(new StringReader(captured))??throw new InvalidDataException("ClosedCaptureFinalMissing");
    var stderr=await errors;using var final=JsonDocument.Parse(finalText);
    var root=final.RootElement;var last=reader.Snapshot();
    // Preserve the actual native return/cleanup evidence before assertions.
    Console.WriteLine(JsonSerializer.Serialize(new{Scope="ORDINARY_HOST_REAL_CUDA_1KIB_256_ELEMENTS_AND_PROGRESS_PIPE",Checks=4,
        ChildPid=child.Id,ChildExit=child.ExitCode,StderrLength=stderr.Length,CaptureBytes=System.Text.Encoding.UTF8.GetByteCount(captured),
        FinalReport=final.RootElement,LastReportedCall=last,LastInit=reader.InitSnapshot(),
        LpacExecuted=false,OriginalOwnerExecuted=false,SystemPolicyChanged=false}));
    Check(child.ExitCode==0 && stderr.Length==0,"host process completion");
    Check(root.GetProperty("ComputeMatched").GetBoolean() && root.GetProperty("ResourceCleanupSucceeded").GetBoolean(),"real kernel and owned cleanup");
    Check(root.GetProperty("AllocatedBytes").GetInt32()==1024 && root.GetProperty("Elements").GetInt32()==256,"fixed allocation");
    Check(root.GetProperty("Steps").GetArrayLength()==16 && reader.ReportsCompleteSuccessfulSequence && last is {Sequence:32,ApiIndex:15,Phase:"RETURNED",Code:0},"all native call boundaries transported");
    if(split)Check(Encoding.UTF8.GetByteCount(captured)<=8192 && reader.InitSnapshot() is
        {Phase:GpuInitLoader.Phase.Invoke,Returned:true,Code:0},"split init succeeded within the product capture limit");
    Console.WriteLine(JsonSerializer.Serialize(new{Scope="ORDINARY_HOST_REAL_CUDA_REFERENCE_ASSERTIONS",Passed=true,Checks=checks}));return 0;
}
var full=new StringWriter();var emitter=new GpuCallProgressWriter(full,nonce,pid);
for(var api=0;api<16;api++){emitter.Emit(api,0,null);emitter.Emit(api,1,0);}full.WriteLine(Final(nonce,pid));
var complete=Reader();_=await complete.ReadAsync(new StringReader(full.ToString()));
Check(complete.Snapshot() is {Sequence:32,ApiIndex:15,Api:"cuCtxDestroy_v2",Phase:"RETURNED",Code:0},"complete progress");
Check(complete.ReportsCompleteSuccessfulSequence,"all successful reports required for positive transport consistency");
Check(await Reader(false).ReadAsync(new StringReader(Final(nonce,pid)))==Final(nonce,pid),"legacy final without newline");
await Reject(Final(nonce,pid),"missing required progress");
await Reject(Frame(1,0,0)+Final(nonce,pid),"pending native call cannot be completed by final");
await Reject(Frame(1,0,0,n:new string('b',32)),"foreign nonce");await Reject(Frame(1,0,0,p:43),"foreign PID");
await Reject(Frame(2,0,0),"sequence gap");await Reject(Frame(1,1,0),"skipped first call");await Reject(Frame(1,16,0),"unknown API");
await Reject(Frame(1,0,3),"unknown phase");await Reject(Frame(1,0,0,1),"entry code");await Reject(Frame(1,0,1,0),"return without entry");
await Reject(Frame(1,0,0)+Frame(2,1,1,0),"wrong return API");
await Reject(Frame(1,0,0)+Frame(2,1,0),"overlapping call");await Reject(Frame(1,0,0)+Frame(1,0,1,0),"replay");
await Reject(Frame(1,0,0)+Frame(2,0,1,0)+Frame(3,0,0),"backwards call");
await Reject(Frame(1,0,0).Replace("\"Api\":0","\"Api\":0,\"Api\":0",StringComparison.Ordinal),"duplicate field");
await Reject(Frame(1,0,0).Replace("\"Api\":0","\"Api\":0,\"Message\":\"PRIVATE\"",StringComparison.Ordinal),"extra field");
await Reject(new string('x',16385),"line bound");await Reject("\n","empty frame");await Reject("{bad}\n","invalid JSON");
await Reject(Frame(1,0,0)+Frame(2,0,1,0)+Final(nonce,pid)+"\n"+Frame(3,1,0),"data after final");
var abrupt=Reader();try{_=await abrupt.ReadAsync(new StringReader(Frame(1,0,0)));}catch(InvalidDataException){}
Check(abrupt.Snapshot() is {Sequence:1,Api:"cuInit",Phase:"ENTERED_NOT_RETURNED"},"last entered call retained after EOF failure");
var closedPartial=Reader();
Check(await closedPartial.ReadClosedCaptureAsync(new StringReader(Frame(1,0,0)+"{\"Kind\":")) is null &&
    closedPartial.Snapshot() is {Api:"cuInit",Phase:"ENTERED_NOT_RETURNED"} && !closedPartial.ReportsCompleteSuccessfulSequence,
    "a stopped child's complete frames survive a torn last frame");
var closedTornFinal=Reader();var truncated=full.ToString().TrimEnd('\r','\n');
Check(await closedTornFinal.ReadClosedCaptureAsync(new StringReader(truncated)) is null &&
    closedTornFinal.Snapshot() is {Sequence:32,ApiIndex:15,Code:0} && !closedTornFinal.ReportsCompleteSuccessfulSequence,
    "even complete call progress does not qualify without a terminated final frame");
var closedComplete=Reader();
Check(await closedComplete.ReadClosedCaptureAsync(new StringReader(full.ToString()))==Final(nonce,pid) &&
    closedComplete.ReportsCompleteSuccessfulSequence,"complete closed capture retains bound final report");
try{_=await Reader().ReadClosedCaptureAsync(new StringReader(full+"extra"));throw new Exception("ACCEPTED: closed capture tail after final");}
catch(InvalidDataException){checks++;}
var cleanup=Reader();_=await cleanup.ReadAsync(new StringReader(Frame(1,0,0)+Frame(2,0,2,-1)+Frame(3,15,0)+Frame(4,15,1,0)+Final(nonce,pid)));
Check(cleanup.Snapshot() is {ApiIndex:15,Code:0},"cleanup after failure retained");
Check(cleanup.FirstFailure() is {ApiIndex:0,Code:-1,Phase:"THREW"},"successful cleanup does not erase the initial native failure");
Check(!cleanup.ReportsCompleteSuccessfulSequence && !abrupt.ReportsCompleteSuccessfulSequence,"failure or missing calls cannot become successful sequence");
var product=typeof(InstalledBroker).Assembly;
var productOutput=product.GetType("ProtectionLifecycle.OfflineConsoleOutput",true)!;
var observe=product.GetType("ProtectionLifecycle.IndependentGpuWorkload",true)!.GetMethod("Observe",BindingFlags.NonPublic|BindingFlags.Static)!;
JsonElement Observe(string transcript,uint childExit=0,string error="",bool overflow=false)
{
    object Capture(string text,bool truncated=false)=>Activator.CreateInstance(productOutput,Encoding.UTF8.GetBytes(text),truncated)!;
    var result=observe.Invoke(null,new[]{nonce,(object)(uint)pid,childExit,Capture(transcript,overflow),Capture(error)})!;
    return JsonSerializer.SerializeToElement(result,result.GetType());
}
var values=Enumerable.Range(0,256).Select(i=>i*3+7).ToArray();var payload=new byte[1024];
Buffer.BlockCopy(values,0,payload,0,payload.Length);
const string scope="LPAC_LOW_ZERO_CAPABILITIES";
var fixtureReport=JsonSerializer.Serialize(new{SchemaVersion=1,Pid=pid,Nonce=nonce,Scope=scope,DriverVersion=13030,Device="fixture-device",
    AllocatedBytes=1024,Elements=256,ResultSHA256=Convert.ToHexString(SHA256.HashData(payload)),ComputeMatched=true,ResourceCleanupSucceeded=true,
    Steps=GpuCallProgressReader.Stages.Select(stage=>new{Stage=stage,Result=0}).ToArray(),FailureType=(string?)null});
var transcript=full.ToString().Replace(Final(nonce,pid),fixtureReport,StringComparison.Ordinal);
var initFrames=new StringWriter{NewLine="\n"};
var initEmitter=new GpuCallProgressWriter(initFrames,nonce,pid);
foreach(var phase in Enum.GetValues<GpuInitLoader.Phase>())
{
    initEmitter.EmitInit(new(phase,false,null));
    initEmitter.EmitInit(new(phase,true,0,phase==GpuInitLoader.Phase.Resolve?true:null));
}
var splitFrames=initFrames.ToString();
var firstNewline=transcript.IndexOf('\n')+1;
var splitTranscript=transcript.Insert(firstNewline,splitFrames);
Check(Observe(splitTranscript).GetProperty("ComputationQualified").GetBoolean(),"bound completed split capture accepted");
Check(!Observe(transcript).GetProperty("ComputationQualified").GetBoolean(),"missing split init cannot qualify");
Check(!Observe(splitTranscript.Replace("\"Phase\":2,\"Returned\":true,\"Code\":0","\"Phase\":2,\"Returned\":true,\"Code\":1",StringComparison.Ordinal))
    .GetProperty("ComputationQualified").GetBoolean(),"disagreeing initializer result refused");
var initPartial=Observe(Frame(1,0,0)+string.Join('\n',splitFrames.Split('\n').Take(5))+"\n{\"Kind\":",0xc0000005);
Check(initPartial.GetProperty("Status").GetString()=="BOUND_PROGRESS_ONLY" &&
    initPartial.GetProperty("LastInit").GetProperty("Phase").GetString()=="Invoke" &&
    !initPartial.GetProperty("LastInit").GetProperty("Returned").GetBoolean(),"torn capture retains entered driver call");
Check(Observe(Frame(1,0,0)+splitFrames.Replace(nonce,new string('c',32),StringComparison.Ordinal),3).GetProperty("Status").GetString()
    =="CAPTURE_PROTOCOL_REFUSED","foreign init checkpoints refused");
Check(Observe(splitFrames+transcript).GetProperty("Status").GetString()=="CAPTURE_PROTOCOL_REFUSED","init checkpoints outside first call refused");
Check(Observe(splitTranscript.Replace("\"InDriverImage\":true","\"InDriverImage\":false",StringComparison.Ordinal)).GetProperty("Status").GetString()
    =="CAPTURE_PROTOCOL_REFUSED","invoke after foreign module address refused");
Check(!Observe(splitTranscript,3).GetProperty("ComputationQualified").GetBoolean(),"nonzero exit disqualifies completed capture");
Check(!Observe(splitTranscript,error:"extra").GetProperty("ComputationQualified").GetBoolean(),"nonempty stderr disqualifies completed capture");
Check(Observe(splitTranscript.Replace(scope,"ORDINARY",StringComparison.Ordinal)).GetProperty("Status").GetString()=="REPORT_BINDING_REFUSED","foreign scope refused");
Check(Observe(Frame(1,0,0),3).GetProperty("Status").GetString()=="BOUND_PROGRESS_ONLY","bound partial progress retained without success");
Check(Observe(transcript,overflow:true).GetProperty("Status").GetString()=="CAPTURE_OVERFLOW","truncated capture refused");
using(var child=Start("fixture-child",nonce))
{
    var reader=new GpuCallProgressReader(nonce,true);reader.Bind(child.Id);var task=reader.ReadAsync(child.StandardOutput);
    var clock=Stopwatch.StartNew();while(reader.Snapshot() is null && clock.ElapsedMilliseconds<3000)await Task.Delay(5);
    Check(reader.Snapshot() is {ApiIndex:0,Phase:"ENTERED_NOT_RETURNED"} && !task.IsCompleted,"entered frame visible while original child and pipe still live");
    await child.StandardInput.WriteLineAsync("GO");await child.StandardInput.FlushAsync();await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
    _=await task;Check(child.ExitCode==0 && reader.Snapshot() is {Phase:"RETURNED",Code:0},"fixture resumes and closes normally");
}
Console.WriteLine(JsonSerializer.Serialize(new{Scope="ORDINARY_GPU_PROGRESS_PROTOCOL_AND_LIVE_PIPE_FIXTURE",Checks=checks,Passed=true,NativeGpuExecuted=false,Installed=false}));return 0;

static string Final(string nonce,int pid)=>JsonSerializer.Serialize(new{SchemaVersion=1,Pid=pid,Nonce=nonce});
static Type TraceType()=>typeof(InstalledBroker).Assembly.GetType("ProtectionLifecycle.SessionZeroStartupBranchTrace+CudaAccessTrace",true)!;

[DllImport("kernel32.dll",ExactSpelling=true)]
static extern uint GetCurrentThreadId();
[DllImport("kernel32.dll",ExactSpelling=true)]
static extern void RaiseException(uint code,uint flags,uint count,nuint[] arguments);

static Process Start(string mode,string nonce)
{
    var start=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"dotnet","dotnet.exe"))
    {UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,RedirectStandardInput=true};
    start.ArgumentList.Add(typeof(InstalledBroker).Assembly==Assembly.GetExecutingAssembly()?throw new Exception("Test entry required"):Assembly.GetExecutingAssembly().Location);
    start.ArgumentList.Add(mode);start.ArgumentList.Add(nonce);return Process.Start(start)??throw new Exception("Own test child did not start");
}
