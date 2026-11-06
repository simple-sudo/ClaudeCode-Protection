using System.Globalization;
using System.Text.Json;
using AfdTraceAnalysis;
using AfdObserverProtocol;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

if(args.Length==1 && args[0]=="--own-stage-exit")return ObserverOutcome.Failure(ObserverStage.TokenBefore);
if(args.Length!=0)return 125;
int passed=0;
void Check(bool condition,string reason){if(!condition)throw new InvalidDataException(reason);passed++;}
void Reject(Action action,string reason)
{try{action();}catch(Exception error)when(error is InvalidDataException or OverflowException or System.Xml.XmlException){passed++;return;}throw new InvalidDataException(reason);}
long created=DateTime.Parse("2026-11-06T12:00:00Z",CultureInfo.InvariantCulture,DateTimeStyles.AdjustToUniversal).ToFileTimeUtc();
var iso="2026-11-06T11:01:45.2442188Z";
var utc=DateTime.Parse(iso,CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind);
Check(AfdAnalysisBridge.UtcFileTime(iso)==AfdAnalysisBridge.UtcFileTime(utc) && DateTime.FromFileTimeUtc(AfdAnalysisBridge.UtcFileTime(utc)).ToString("o")==iso,"JSON UTC string/object preserve exact ticks without local-time reparse");
Reject(()=>AfdAnalysisBridge.UtcFileTime(DateTime.SpecifyKind(utc,DateTimeKind.Unspecified)),"ambiguous DateTime not treated as UTC");
Reject(()=>AfdAnalysisBridge.UtcFileTime(DateTime.SpecifyKind(utc,DateTimeKind.Local)),"local DateTime not silently accepted as UTC");
Reject(()=>AfdAnalysisBridge.UtcFileTime("2026-11-06T11:01:45"),"unqualified timestamp string refused");
Reject(()=>AfdAnalysisBridge.UtcFileTime("2026-11-06T12:01:45+01:00"),"offset string cannot replace original UTC");
string Xml(uint location=1009,uint status=0xc0000022,uint pid=101,uint tid=201,long? at=null)
{
    var time=DateTime.FromFileTimeUtc(at??created+150).ToString("o",CultureInfo.InvariantCulture);
    return $"""
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
    <Provider Guid="e53c6823-7bb8-44bb-90dc-3f86090d48a6"/><EventID>1000</EventID><Version>0</Version>
    <TimeCreated SystemTime="{time}"/><Execution ProcessID="{pid}" ThreadID="{tid}"/></System><EventData>
    <Data Name="EnterExit">0</Data><Data Name="Location">{location}</Data><Data Name="Process">0xFFFFD00000123456</Data>
    <Data Name="Endpoint">0x0</Data><Data Name="AddressFamily">2</Data><Data Name="SocketType">1</Data><Data Name="Protocol">6</Data>
    <Data Name="ProcessId">0x65</Data><Data Name="Status">0x{status:X8}</Data></EventData></Event>
    """;
}
var xml=Xml();var parsed=AfdCreateEvent.Parse(xml);
Check(parsed.PayloadPid==101 && parsed.HeaderPid==101 && parsed.HeaderTid==201 && parsed.Status==0xc0000022 && parsed.Location==1009,"manifest values and hex NTSTATUS");
Check(!JsonSerializer.Serialize(parsed).Contains("FFFFD000",StringComparison.Ordinal),"kernel pointers omitted from decoded projection");
Reject(()=>AfdCreateEvent.Parse(xml.Replace("<Version>0</Version>","<Version>1</Version>")),"foreign version");
Reject(()=>AfdCreateEvent.Parse(xml.Replace("e53c6823","a53c6823")),"foreign provider");
Reject(()=>AfdCreateEvent.Parse(xml.Replace("<EventID>1000</EventID>","<EventID>1</EventID>")),"wrong event");
Reject(()=>AfdCreateEvent.Parse(xml.Replace("<Version>0</Version>","<Version>0</Version><Version>0</Version>")),"duplicate system field");
Reject(()=>AfdCreateEvent.Parse(xml.Replace("Name=\"Location\"","Name=\"Status\"")),"duplicate/reordered payload");
Reject(()=>AfdCreateEvent.Parse(xml.Replace("0xC0000022","0x100000000")),"status overflow");
Reject(()=>AfdCreateEvent.Parse(xml.Replace("0x65","0x100000000")),"payload PID overflow");
Reject(()=>AfdCreateEvent.Parse(xml.Replace("0xC0000022","-1")),"signed status text refused");
Reject(()=>AfdCreateEvent.Parse(xml.Replace("0xC0000022"," 0xC0000022")),"numeric whitespace refused");
Reject(()=>AfdCreateEvent.Parse(xml.Replace("0xC0000022","0x")),"empty hex refused");
Reject(()=>AfdCreateEvent.Parse(xml.Replace("Z\"", "+01:00\"")),"non UTC timestamp refused");
Reject(()=>AfdCreateEvent.Parse("<!DOCTYPE Event [<!ENTITY ext SYSTEM 'file:///C:/Windows/win.ini'>]>"+xml),"DTD prohibited");
Reject(()=>AfdCreateEvent.Parse(new string('a',32769)),"XML length bound");
AfdRequestWindow[] windows={new("valid-ipv4-tcp-control",101,created,201,created+100,created+200,0xc0000022),
    new("invalid-family-35-marker",101,created,201,created+300,created+400,0xc000000d),
    new("invalid-flags-2-marker",101,created,201,created+500,created+600,0xc000000d)};
var rows=new[]{parsed,AfdCreateEvent.Parse(Xml(1003,0xc000000d,at:created+350)),AfdCreateEvent.Parse(Xml(1001,0xc000000d,at:created+550))};
var result=AfdCreateCorrelation.Correlate(windows,rows);
Check(result[0].MatchingEvents==1 && result[0].MappedStages.SequenceEqual(new[]{"CreatorSecurityCaptureFailure"}) && result[0].ReturnStatusObserved,"valid request location/status scoped correlation");
Check(result[1].ExpectedEarlyMarkerObserved && result[2].ExpectedEarlyMarkerObserved,"both independent markers");
Check(result.All(r=>!r.NetworkAdmission),"correlation never grants admission");
var completed=AfdCreateCorrelation.Correlate(windows,new[]{parsed with {Location=1006,Status=0},parsed with {Location=1013,EnterExit=1}})[0];
Check(completed.MappedStages.SequenceEqual(new[]{"EndpointAllocated","TransportLayerEndpointCreateCompleted"}) &&
    completed.Observations[0].Status==0 && completed.Observations[1].Status==0xc0000022 && completed.Observations[1].EnterExit==1,
    "retained allocated/success then transport-completion/denied observations do not conflate stage with outcome");
Check(!JsonSerializer.Serialize(completed).Contains("FFFFD000",StringComparison.Ordinal),"expanded observations still omit kernel pointers");
foreach(var altered in new[]{parsed with {HeaderPid=102},parsed with {PayloadPid=102},parsed with {HeaderTid=202},parsed with {FileTime=created+250}})
    Check(AfdCreateCorrelation.Correlate(windows,new[]{altered})[0].MatchingEvents==0,"foreign actor/thread or time excluded");
var empty=AfdCreateCorrelation.Correlate(windows,Array.Empty<AfdCreateEvent>());
Check(empty.All(r=>r.Interpretation.StartsWith("UNKNOWN_",StringComparison.Ordinal) && !r.ReturnStatusObserved),"no event is UNKNOWN, never no-execution proof");
Check(AfdCreateCorrelation.Correlate(windows,new[]{parsed with {Status=0}})[0].ReturnStatusObserved==false,"different return status retained");
Check(AfdCreateCorrelation.Correlate(windows,new[]{parsed with {Location=uint.MaxValue}})[0].MappedStages.Single()=="UNKNOWN_LOCATION","future locations stay unknown without integer wrap");
Reject(()=>AfdCreateCorrelation.Correlate(windows[..2],rows),"exact three calls");
foreach(var altered in new[]{windows[1] with {ActorPid=102},windows[1] with {ActorCreatedFileTime=created+1},
    windows[1] with {StartedFileTime=created+200},windows[1] with {FinishedFileTime=created+299},windows[1] with {ThreadId=0},
    windows[1] with {Role="supplied-command"},windows[1] with {StartedFileTime=created-1},windows[1] with {FinishedFileTime=created+TimeSpan.TicksPerMinute}})
    Reject(()=>AfdCreateCorrelation.Correlate(new[]{windows[0],altered,windows[2]},rows),"invalid actor/request window");
Reject(()=>AfdCreateCorrelation.Correlate(windows,Enumerable.Repeat(parsed,4097).ToArray()),"event count bounded");
foreach(var stage in Enum.GetValues<ObserverStage>())
    Check(ObserverOutcome.Decode(ObserverOutcome.Failure(stage))==stage,"finite first-failure stage survives exit code");
foreach(var code in new[]{0,125,-1,unchecked((int)0xc0000005),0x43500000,0x435000ff,0x43500101})
    Check(ObserverOutcome.Decode(code) is null,"unrecognized native/legacy exit is UNKNOWN, not a stage or cleanup proof");
Reject(()=>ObserverOutcome.Failure((ObserverStage)255),"undefined stage cannot be encoded");
EventIdFilter.AssertLayout();
var source=Guid.Parse("426ef2b7-7538-448b-b54e-5fd4d9cba26d");
using(var filter=new EventIdFilter(source))
{
    var parameters=Marshal.PtrToStructure<EventIdFilter.Parameters>(filter.Pointer);
    var descriptor=Marshal.PtrToStructure<EventIdFilter.Descriptor>(parameters.Descriptors);
    var ids=Marshal.PtrToStructure<EventIdFilter.EventIds>(new IntPtr(unchecked((long)descriptor.Pointer)));
    Check(parameters.Version==2 && parameters.Source==source && parameters.EnableProperty==0 && parameters.ControlFlags==0 && parameters.Count==1,"fixed version2 event-filter parameters");
    Check(descriptor.Type==0x80000200 && descriptor.Size==6 && ids.FilterIn==1 && ids.Reserved==0 && ids.Count==1 && ids.Event==1000,"only manifest event1000 requested");
    filter.Dispose();filter.Dispose();Check(filter.Pointer==IntPtr.Zero,"event-filter data released idempotently without native tracing");
}
using(var filter=EventIdFilter.TcpipCreate(source))
{
    var parameters=Marshal.PtrToStructure<EventIdFilter.Parameters>(filter.Pointer);
    var descriptor=Marshal.PtrToStructure<EventIdFilter.Descriptor>(parameters.Descriptors);
    var pointer=new IntPtr(unchecked((long)descriptor.Pointer));
    Check(descriptor.Size==16 && Marshal.ReadByte(pointer)==1 && Marshal.ReadInt16(pointer,2)==6,"TCP filter exact six-ID data size");
    Check(Enumerable.Range(0,6).Select(i=>(int)Marshal.ReadInt16(pointer,4+i*2)).SequenceEqual(new[]{1001,1010,1011,1012,1013,1562}),"TCP filter contains no extra network events");
}
var creation=NativeBoundary.ReadOwnCreation();
Check(creation.Success && creation.Win32Error==0 && creation.FileTime>0 && creation.FileTime<=NativeBoundary.PreciseFileTime(),"actual own process creation read via pseudo handle without OpenProcess");
var host=@"C:\Program Files\dotnet\dotnet.exe";
var info=new ProcessStartInfo(host){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
info.Environment.Clear();
foreach(var name in new[]{"SystemRoot","windir","SystemDrive","TEMP","TMP"})
    if(Environment.GetEnvironmentVariable(name) is string value)info.Environment[name]=value;
foreach(var arg in new[]{"exec","--fx-version","8.0.28",Assembly.GetExecutingAssembly().Location,"--own-stage-exit"})info.ArgumentList.Add(arg);
using(var child=Process.Start(info)??throw new IOException("Own exit fixture did not start"))
{
    await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
    Check(ObserverOutcome.Decode(child.ExitCode)==ObserverStage.TokenBefore && child.StandardOutput.ReadToEnd().Length==0 && child.StandardError.ReadToEnd().Length==0,
        "actual ordinary Win32 process exit preserves full finite stage without output file or UAC");
}
passed+=TcpipCases.Run();
Console.WriteLine(JsonSerializer.Serialize(new{Scope="ORDINARY_AFD_TCPIP_ANALYSIS_PROTOCOL_AND_OWN_PROCESS_METADATA",Passed=passed,
    OwnOrdinaryExitFixtureExecuted=true,OwnProcessTimesRead=true,NativeCapture=false,ProtectedExecution=false,NetworkAdmission=false,NoEventIsNoExecutionProof=false}));return 0;
