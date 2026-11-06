using System.Globalization;
using System.IO;
using System.Xml;
using System.Xml.Linq;
using System.Text.Json;

namespace AfdTraceAnalysis;

// Decoding is separate from capture and has no native, process or network API.
// Pointers stay private: the selected projection contains no kernel addresses.
internal sealed record AfdCreateEvent(long FileTime,uint HeaderPid,uint HeaderTid,uint PayloadPid,uint EnterExit,uint Location,
    uint AddressFamily,uint SocketType,uint Protocol,uint Status)
{
    internal static readonly Guid Provider=new("e53c6823-7bb8-44bb-90dc-3f86090d48a6");
    private static readonly XNamespace Ns="http://schemas.microsoft.com/win/2004/08/events/event";
    private static readonly string[] Names={"EnterExit","Location","Process","Endpoint","AddressFamily","SocketType","Protocol","ProcessId","Status"};
    internal static AfdCreateEvent Parse(string xml)
    {
        if(xml.Length is <1 or >32768)throw new InvalidDataException("AfdEventXmlBounds");
        using var input=new StringReader(xml);
        using var reader=XmlReader.Create(input,new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=32768});
        var root=XDocument.Load(reader).Root??throw new InvalidDataException("AfdEventRootMissing");
        if(root.Name!=Ns+"Event")throw new InvalidDataException("AfdEventNamespaceMismatch");
        XElement One(XContainer parent,string name)
        {var nodes=parent.Elements(Ns+name).ToArray();return nodes.Length==1?nodes[0]:throw new InvalidDataException("AfdEventDuplicateOrMissingField");}
        string Attr(XElement element,string name)=>element.Attribute(name)?.Value??throw new InvalidDataException("AfdEventAttributeMissing");
        var system=One(root,"System");var provider=One(system,"Provider");
        if(!Guid.TryParse(Attr(provider,"Guid"),out var id) || id!=Provider || U32(One(system,"EventID").Value)!=1000 ||
            U32(One(system,"Version").Value)!=0)throw new InvalidDataException("AfdEventProviderOrVersionMismatch");
        var execution=One(system,"Execution");
        var text=Attr(One(system,"TimeCreated"),"SystemTime");
        if(!text.EndsWith('Z') || !DateTimeOffset.TryParse(text,CultureInfo.InvariantCulture,DateTimeStyles.None,out var time) || time.Offset!=TimeSpan.Zero)
            throw new InvalidDataException("AfdEventUtcTimeRequired");
        var fields=One(root,"EventData").Elements().ToArray();
        if(fields.Length!=Names.Length)throw new InvalidDataException("AfdEventFieldCountMismatch");
        var values=new ulong[Names.Length];
        for(int i=0;i<fields.Length;i++)
        {
            if(fields[i].Name!=Ns+"Data" || Attr(fields[i],"Name")!=Names[i] || fields[i].HasElements)
                throw new InvalidDataException("AfdEventFieldOrderMismatch");
            values[i]=Number(fields[i].Value);
            if(i is not (2 or 3) && values[i]>uint.MaxValue)throw new InvalidDataException("AfdEventScalarOverflow");
        }
        return new(time.UtcDateTime.ToFileTimeUtc(),U32(Attr(execution,"ProcessID")),U32(Attr(execution,"ThreadID")),
            (uint)values[7],(uint)values[0],(uint)values[1],(uint)values[4],(uint)values[5],(uint)values[6],(uint)values[8]);
    }
    private static uint U32(string value)=>checked((uint)Number(value));
    private static ulong Number(string value)
    {
        bool hex=value.StartsWith("0x",StringComparison.OrdinalIgnoreCase);var digits=hex?value[2..]:value;
        if(digits.Length is <1 or >20 || hex && digits.Length>16 ||
            !digits.All(c=>hex?char.IsAsciiHexDigit(c):char.IsAsciiDigit(c)) ||
            !ulong.TryParse(digits,hex?NumberStyles.AllowHexSpecifier:NumberStyles.None,CultureInfo.InvariantCulture,out var result))
            throw new InvalidDataException("AfdEventNumericValueInvalid");
        return result;
    }
}

internal sealed record AfdRequestWindow(string Role,uint ActorPid,long ActorCreatedFileTime,uint ThreadId,long StartedFileTime,long FinishedFileTime,uint NativeStatus);
internal sealed record AfdEventObservation(long FileTime,uint EnterExit,uint Location,uint Status,uint AddressFamily,uint SocketType,uint Protocol);
internal sealed record AfdRequestCorrelation(string Role,int MatchingEvents,uint[] ObservedLocations,string[] MappedStages,AfdEventObservation[] Observations,
    bool ReturnStatusObserved,bool ExpectedEarlyMarkerObserved,string Interpretation)
{
    internal bool NetworkAdmission=>false;
}
internal static class AfdCreateCorrelation
{
    internal static AfdRequestCorrelation[] Correlate(AfdRequestWindow[] requests,IReadOnlyList<AfdCreateEvent> events)
    {
        string[] roles={"valid-ipv4-tcp-control","invalid-family-35-marker","invalid-flags-2-marker"};
        if(requests.Length!=3 || events.Count>4096)throw new InvalidDataException("AfdCorrelationInputBounds");
        for(int i=0;i<3;i++)
        {
            var r=requests[i];
            if(r.Role!=roles[i] || r.ActorPid==0 || r.ThreadId==0 || r.ActorCreatedFileTime<=0 || r.StartedFileTime<r.ActorCreatedFileTime ||
                r.FinishedFileTime<r.StartedFileTime || r.FinishedFileTime-r.StartedFileTime>TimeSpan.TicksPerSecond*30 ||
                i>0 && (r.ActorPid!=requests[0].ActorPid || r.ActorCreatedFileTime!=requests[0].ActorCreatedFileTime || r.StartedFileTime<=requests[i-1].FinishedFileTime))
                throw new InvalidDataException("AfdCorrelationActorOrWindowMismatch");
        }
        return requests.Select((r,i)=>
        {
            var matching=events.Where(e=>e.PayloadPid==r.ActorPid && e.HeaderPid==r.ActorPid && e.HeaderTid==r.ThreadId &&
                e.FileTime>=r.StartedFileTime && e.FileTime<=r.FinishedFileTime).ToArray();
            var locations=matching.Select(e=>e.Location).Distinct().Order().ToArray();
            int marker=i==1?1003:i==2?1001:-1;
            return new AfdRequestCorrelation(r.Role,matching.Length,locations,locations.Select(Stage).ToArray(),
                matching.Select(e=>new AfdEventObservation(e.FileTime,e.EnterExit,e.Location,e.Status,e.AddressFamily,e.SocketType,e.Protocol)).ToArray(),
                matching.Any(e=>e.Status==r.NativeStatus),marker!=-1 && matching.Any(e=>e.Location==marker && e.Status==0xc000000d),
                matching.Length==0?"UNKNOWN_NO_MATCHING_EVENT_NOT_PROOF_OF_NO_EXECUTION":"OBSERVED_CALL_WINDOW_LOCATION_NOT_UNIQUE_ROOT_CAUSE");
        }).ToArray();
    }
    private static string Stage(uint location)=>location switch {
        1001=>"PacketFlagsFailure",1003=>"FamilyTypeProtocolFailure",1006=>"EndpointAllocated",1009=>"CreatorSecurityCaptureFailure",
        1010=>"CreatorSecurityCaptureOrMissingDescriptor",1011=>"TransportCreateFailure",1012=>"AfdCreateSuccessTail",
        1013=>"TransportLayerEndpointCreateCompleted",
        _=>"UNKNOWN_LOCATION"};
}

public static class AfdAnalysisBridge
{
    // ConvertFrom-Json may already have produced a DateTime. Re-parsing that
    // object as a culture-formatted string loses Kind and fractional ticks.
    public static long UtcFileTime(DateTime value)
        =>value.Kind==DateTimeKind.Utc?value.ToFileTimeUtc():throw new InvalidDataException("UtcDateTimeKindRequired");
    public static long UtcFileTime(string value)
    {
        if(value.Length is <20 or >28 || !value.EndsWith('Z'))throw new InvalidDataException("OriginalIsoUtcTimestampRequired");
        var parsed=JsonSerializer.Deserialize<DateTime>(JsonSerializer.Serialize(value));
        return UtcFileTime(parsed);
    }
    // Ordinary trusted decoder only. Inputs are data; no path, process, ETW
    // control or activation operation is exposed by this bridge.
    public static string Analyze(string windowsJson,string[] eventXml)
    {
        if(windowsJson.Length>8192 || eventXml.Length>4096)throw new InvalidDataException("AfdAnalysisBounds");
        var windows=JsonSerializer.Deserialize<AfdRequestWindow[]>(windowsJson)??throw new InvalidDataException("AfdWindowsMissing");
        if(windows.Any(w=>w is null))throw new InvalidDataException("AfdWindowMissing");
        var events=eventXml.Select(AfdCreateEvent.Parse).ToArray();
        return JsonSerializer.Serialize(AfdCreateCorrelation.Correlate(windows,events));
    }
}
