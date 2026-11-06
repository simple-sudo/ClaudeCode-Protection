using System.Xml;
using System.Xml.Linq;
using System.Text.Json;

namespace AfdTraceAnalysis;

// Fixed locally inspected manifest contracts. Native capture, admission and
// cause attribution are deliberately outside this data-only decoder.
internal sealed record TcpipCreateEvent(long FileTime,uint HeaderPid,uint HeaderTid,uint PayloadPid,int EventId,int Version,
    uint Status,uint AddressFamily,uint? CompartmentId,ulong? ProcessStartKey,string? LocalAddressHex)
{
    internal static readonly Guid Provider=new("2f07e2ee-15db-40f1-90ef-9d7ba282188a");
    private static readonly XNamespace Ns="http://schemas.microsoft.com/win/2004/08/events/event";
    public string Stage=>EventId switch {1001=>"TcpEndpointCreateCompleted",1010=>"TcpFamilyNotAttached",
        1011=>"TcpCompartmentNotFound",1012=>"TcpCreateInspectionFailure",1013=>"TcpEndpointCreatedEvent",
        1562=>"TcpEndpointCreateAccessDeniedEvent",_=>"UNKNOWN"};
    internal static TcpipCreateEvent Parse(string xml)
    {
        if(xml.Length is <1 or >32768)throw Bad("XmlBounds");
        using var input=new StringReader(xml);
        using var reader=XmlReader.Create(input,new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=32768});
        var root=XDocument.Load(reader).Root??throw Bad("RootMissing");
        if(root.Name!=Ns+"Event")throw Bad("NamespaceMismatch");
        XElement One(XContainer parent,string name)
        {var nodes=parent.Elements(Ns+name).ToArray();return nodes.Length==1?nodes[0]:throw Bad("DuplicateOrMissingField");}
        string Attr(XElement element,string name)=>element.Attribute(name)?.Value??throw Bad("AttributeMissing");
        uint U32(string value)=>checked((uint)AfdCreateEvent.Number(value));
        var system=One(root,"System");
        if(!Guid.TryParse(Attr(One(system,"Provider"),"Guid"),out var provider) || provider!=Provider)throw Bad("ProviderMismatch");
        int id=checked((int)U32(One(system,"EventID").Value)),version=checked((int)U32(One(system,"Version").Value));
        bool common=(id is 1010 or 1011 or 1012 && version is 0 or 1) || (id==1013 && version is 0 or 1 or 2) || (id==1562 && version==0);
        if(!(id==1001 && version==0) && !common)throw Bad("EventOrVersionMismatch");
        var expected=id==1001?new[]{"Status","Endpoint","AddressFamily","Pid"}:
            new[]{"LocalAddressLength","LocalAddress","Status","ProcessId","CompartmentId","AddressFamily"};
        if(id==1013 && version==2)expected=new[]{"Endpoint"}.Concat(expected).ToArray();
        if(version==1 || id==1013 && version==2 || id==1562)expected=expected.Append("ProcessStartKey").ToArray();
        var nodes=One(root,"EventData").Elements().ToArray();
        if(nodes.Length!=expected.Length)throw Bad("FieldCountMismatch");
        var fields=new Dictionary<string,string>(StringComparer.Ordinal);
        for(int i=0;i<nodes.Length;i++)
        {
            if(nodes[i].Name!=Ns+"Data" || Attr(nodes[i],"Name")!=expected[i] || nodes[i].HasElements)throw Bad("FieldOrderMismatch");
            fields.Add(expected[i],nodes[i].Value);
        }
        if(fields.TryGetValue("Endpoint",out var pointer))_=AfdCreateEvent.Number(pointer); // never exported
        string? address=null;uint? compartment=null;ulong? key=null;
        if(id!=1001)
        {
            var bytes=U32(fields["LocalAddressLength"]);address=fields["LocalAddress"];
            if(bytes>128 || address.Length!=bytes*2 || !address.All(char.IsAsciiHexDigit))throw Bad("SocketAddressBounds");
            compartment=U32(fields["CompartmentId"]);
        }
        if(fields.TryGetValue("ProcessStartKey",out var startKey))key=AfdCreateEvent.Number(startKey);
        var execution=One(system,"Execution");
        return new(AfdAnalysisBridge.UtcFileTime(Attr(One(system,"TimeCreated"),"SystemTime")),U32(Attr(execution,"ProcessID")),
            U32(Attr(execution,"ThreadID")),U32(fields[id==1001?"Pid":"ProcessId"]),id,version,U32(fields["Status"]),
            U32(fields["AddressFamily"]),compartment,key,address);
    }
    private static InvalidDataException Bad(string reason)=>new("TcpipCreate:"+reason);
}

internal sealed record TcpipRequestCorrelation(string Role,int MatchingEvents,TcpipCreateEvent[] Observations)
{
    public bool UniqueRootCauseProven=>false;
    public bool NetworkAdmission=>false;
}
public static class TcpipAnalysisBridge
{
    public static string Analyze(string windowsJson,string[] eventXml)
    {
        if(windowsJson.Length>8192 || eventXml.Length>4096)throw new InvalidDataException("TcpipAnalysisBounds");
        var windows=JsonSerializer.Deserialize<AfdRequestWindow[]>(windowsJson)??throw new InvalidDataException("TcpipWindowsMissing");
        if(windows.Any(w=>w is null))throw new InvalidDataException("TcpipWindowMissing");
        _=AfdCreateCorrelation.Correlate(windows,Array.Empty<AfdCreateEvent>());
        var events=eventXml.Select(TcpipCreateEvent.Parse).ToArray();
        var result=windows.Select(w=>new TcpipRequestCorrelation(w.Role,0,events.Where(e=>e.HeaderPid==w.ActorPid && e.PayloadPid==w.ActorPid &&
            e.HeaderTid==w.ThreadId && e.FileTime>=w.StartedFileTime && e.FileTime<=w.FinishedFileTime).ToArray()))
            .Select(r=>r with {MatchingEvents=r.Observations.Length}).ToArray();
        return JsonSerializer.Serialize(result);
    }
}
