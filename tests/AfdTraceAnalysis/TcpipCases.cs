using System.Text.Json;
using System.Xml.Linq;

namespace AfdTraceAnalysis;

internal static class TcpipCases
{
    internal static int Run()
    {
        int passed=0;void Check(bool ok,string name){if(!ok)throw new InvalidDataException(name);passed++;}
        void Reject(Action action,string name)
        {try{action();}catch(Exception error)when(error is InvalidDataException or OverflowException or System.Xml.XmlException or JsonException){passed++;return;}throw new InvalidDataException(name);}
        long created=AfdAnalysisBridge.UtcFileTime("2026-11-06T12:00:00Z");
        XNamespace ns="http://schemas.microsoft.com/win/2004/08/events/event";
        string Xml(int id,int version,uint pid=101,uint tid=201)
        {
            var fields=new List<(string Name,string Value)>();
            if(id==1001)fields.AddRange(new[]{("Status","0xC0000022"),("Endpoint","0xFFFFD00000123456"),("AddressFamily","2"),("Pid","101")});
            else
            {
                if(id==1013 && version==2)fields.Add(("Endpoint","0xFFFFD00000123456"));
                fields.AddRange(new[]{("LocalAddressLength","16"),("LocalAddress","02000000000000000000000000000000"),("Status",id==1013?"0":"0xC0000022"),
                    ("ProcessId","101"),("CompartmentId","1"),("AddressFamily","2")});
                if(version==1 || id==1013 && version==2 || id==1562)fields.Add(("ProcessStartKey","18446744073709551615"));
            }
            return new XElement(ns+"Event",new XElement(ns+"System",new XElement(ns+"Provider",new XAttribute("Guid",TcpipCreateEvent.Provider)),
                new XElement(ns+"EventID",id),new XElement(ns+"Version",version),new XElement(ns+"TimeCreated",new XAttribute("SystemTime",DateTime.FromFileTimeUtc(created+150).ToString("o"))),
                new XElement(ns+"Execution",new XAttribute("ProcessID",pid),new XAttribute("ThreadID",tid))),
                new XElement(ns+"EventData",fields.Select(f=>new XElement(ns+"Data",new XAttribute("Name",f.Name),f.Value)))).ToString(SaveOptions.DisableFormatting);
        }
        foreach(var pair in new[]{(1001,0),(1010,0),(1010,1),(1011,0),(1011,1),(1012,0),(1012,1),(1013,0),(1013,1),(1013,2),(1562,0)})
        {
            var value=TcpipCreateEvent.Parse(Xml(pair.Item1,pair.Item2));
            Check(value.EventId==pair.Item1 && value.Version==pair.Item2 && value.PayloadPid==101 && value.HeaderTid==201 && value.AddressFamily==2,"fixed local TCPIP manifest version");
            Check(!JsonSerializer.Serialize(value).Contains("FFFFD000",StringComparison.Ordinal),"TCPIP pointer omitted from projection");
        }
        Check(TcpipCreateEvent.Parse(Xml(1562,0)).ProcessStartKey==ulong.MaxValue,"process start key retains full UInt64 without treating it as FILETIME");
        var xml=Xml(1562,0);
        Reject(()=>TcpipCreateEvent.Parse(Xml(1562,1)),"unknown denial version rejected");
        Reject(()=>TcpipCreateEvent.Parse(Xml(1013,3)),"unknown success version rejected");
        Reject(()=>TcpipCreateEvent.Parse(Xml(1563,0)),"UDP event outside fixed TCP scope");
        Reject(()=>TcpipCreateEvent.Parse(xml.Replace(TcpipCreateEvent.Provider.ToString(),AfdCreateEvent.Provider.ToString())),"foreign provider rejected");
        Reject(()=>TcpipCreateEvent.Parse(xml.Replace("Name=\"ProcessId\"","Name=\"Status\"")),"duplicate/incorrect order rejected");
        Reject(()=>TcpipCreateEvent.Parse(xml.Replace(">16<",">129<")),"socket-address bound rejected");
        Reject(()=>TcpipCreateEvent.Parse(xml.Replace("02000000000000000000000000000000","00")),"socket-address declared length exact");
        Reject(()=>TcpipCreateEvent.Parse(xml.Replace("02000000000000000000000000000000",new string('G',32))),"socket-address hex rejected");
        Reject(()=>TcpipCreateEvent.Parse(xml.Replace("0xC0000022","0x100000000")),"TCP status width exact");
        Reject(()=>TcpipCreateEvent.Parse(xml.Replace("18446744073709551615","18446744073709551616")),"start key overflow rejected");
        Reject(()=>TcpipCreateEvent.Parse("<!DOCTYPE Event [<!ENTITY x SYSTEM 'file:///C:/Windows/win.ini'>]>"+xml),"TCP XML DTD prohibited");
        Reject(()=>TcpipCreateEvent.Parse(new string('X',32769)),"TCP XML bound");
        AfdRequestWindow[] windows={new("valid-ipv4-tcp-control",101,created,201,created+100,created+200,0xc0000022),
            new("invalid-family-35-marker",101,created,201,created+300,created+400,0xc000000d),
            new("invalid-flags-2-marker",101,created,201,created+500,created+600,0xc000000d)};
        var encoded=JsonSerializer.Serialize(windows);
        using var result=JsonDocument.Parse(TcpipAnalysisBridge.Analyze(encoded,new[]{xml,Xml(1012,1),Xml(1562,0,pid:102),Xml(1562,0,tid:202)}));
        var first=result.RootElement[0];
        Check(first.GetProperty("MatchingEvents").GetInt32()==2 && !first.GetProperty("UniqueRootCauseProven").GetBoolean() && !first.GetProperty("NetworkAdmission").GetBoolean(),"same owner thread/call only, no unique cause or admission");
        Check(first.GetProperty("Observations")[0].GetProperty("Stage").GetString()=="TcpEndpointCreateAccessDeniedEvent" &&
            first.GetProperty("Observations")[1].GetProperty("Stage").GetString()=="TcpCreateInspectionFailure","explicit-denial and inspection events remain distinct");
        using var empty=JsonDocument.Parse(TcpipAnalysisBridge.Analyze(encoded,Array.Empty<string>()));
        Check(empty.RootElement.EnumerateArray().All(r=>r.GetProperty("MatchingEvents").GetInt32()==0),"missing TCP event is empty evidence, no denial proof");
        Reject(()=>TcpipAnalysisBridge.Analyze(JsonSerializer.Serialize(windows[..2]),new[]{xml}),"TCP correlation keeps original three-call contract");
        return passed;
    }
}
