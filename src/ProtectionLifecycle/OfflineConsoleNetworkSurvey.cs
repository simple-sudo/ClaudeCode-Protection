using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record OfflineConsoleNetworkSurvey(int SchemaVersion,string SessionId,GatewayNetworkContent Network,
    OfflineConsoleNetworkSurvey.ProcessView Processes)
{
    private const string Leaf="offline-console-network-survey.json";
    private const int MaximumBytes=280000,MaximumProcesses=48;
    private static readonly string[] ProcessNames=["FlClash","FlClashCore","GameViewerService",
        "MuMuRemoteBackend","MumuRemoteHealthd","MuMuRemoteService"];
    internal sealed record ProcessRow(string Name,int Pid,long? CreatedFileTime);
    internal sealed record ProcessView(int Error,ProcessRow[] Rows);
    internal sealed record ReadSummary(string Status,uint? SizeStatus,uint? ReadStatus,int CapturedBytes,int? TrustedRows,int? RestrictedRows);
    internal sealed record Summary(string ReceiptSHA256,ReadSummary Adapters,ReadSummary TcpV4,ReadSummary TcpV6,
        int MatchingAdapterNames,int MatchingAdapterMacs,int MatchingUnicast,int MatchingGateways,int MatchingDns,
        int MatchingTcpV4,int MatchingTcpV6,int TrustedStableProxyProcesses,int TrustedStableRemoteProcesses,
        int RestrictedProcessQueryError,int RestrictedNamedProcesses,int MatchingProxyProcesses,int MatchingRemoteProcesses,
        int MatchingProxyTcpRows,int MatchingRemoteTcpRows)
    {
        internal bool ConfirmedForFixedReads=>new[]{Adapters,TcpV4,TcpV6}.All(read=>read is {Status:"DENIED",TrustedRows:>0}) &&
            RestrictedProcessQueryError==5 && TrustedStableProxyProcesses>0 && TrustedStableRemoteProcesses>0;
    }

    internal static OfflineConsoleNetworkSurvey Capture(string session)=>
        new(1,session,GatewayCapabilityContent.Capture(),CaptureProcesses());

    internal static ProcessView CaptureProcesses()
    {
        Process[] processes=[];
        try
        {
            processes=Process.GetProcesses();
            var rows=new List<ProcessRow>();
            foreach(var process in processes)
            {
                var name=ProcessNames.FirstOrDefault(item=>string.Equals(item,process.ProcessName,StringComparison.OrdinalIgnoreCase));
                if(name is null)continue;
                if(rows.Count==MaximumProcesses)return new(122,[]);
                rows.Add(new(name,process.Id,Created(process)));
            }
            return new(0,rows.ToArray());
        }
        catch(Win32Exception error){return new(error.NativeErrorCode>0?error.NativeErrorCode:13,[]);}
        catch(InvalidOperationException){return new(13,[]);}
        finally{foreach(var process in processes)process.Dispose();}
    }

    private static long? Created(Process process)
    {
        try{return process.StartTime.ToFileTimeUtc();}
        catch(Win32Exception){return null;}
        catch(InvalidOperationException){return null;}
    }

    internal void Write(string workspace)
    {
        var bytes=JsonSerializer.SerializeToUtf8Bytes(this);
        AssertLength(bytes.Length);
        using var file=new FileStream(WindowsPathSeal.Child(workspace,Leaf),FileMode.CreateNew,FileAccess.Write,FileShare.None);
        file.Write(bytes);
        file.Flush(true);
    }

    internal static OfflineConsoleNetworkSurvey Read(string workspace,string session,uint pid,long created)
    {
        using var file=new FileStream(WindowsPathSeal.Open(WindowsPathSeal.Child(workspace,Leaf),false,true),FileAccess.Read);
        AssertLength(file.Length);
        var bytes=new byte[checked((int)file.Length)];
        file.ReadExactly(bytes);
        return Parse(bytes,session,pid,created);
    }

    internal static OfflineConsoleNetworkSurvey Parse(byte[] bytes,string session,uint pid,long created)
    {
        AssertLength(bytes.Length);
        using var document=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=6});
        var root=document.RootElement;
        StrictJson.Fields(root,"SchemaVersion","SessionId","Network","Processes");
        if(root.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(root,"SessionId")!=session || pid==0)
            throw WfpNative.Contract("OfflineNetworkSurveyActorMismatch");
        var network=GatewayNetworkContent.Parse(root.GetProperty("Network"),pid,created);
        if(network.FinishedFileTime>DateTime.UtcNow.ToFileTimeUtc())throw WfpNative.Contract("OfflineNetworkSurveyTime");
        var processData=root.GetProperty("Processes");
        StrictJson.Fields(processData,"Error","Rows");
        var rows=processData.GetProperty("Rows");
        if(rows.GetArrayLength()>MaximumProcesses)throw WfpNative.Contract("OfflineNetworkSurveyProcessBound");
        foreach(var row in rows.EnumerateArray())StrictJson.Fields(row,"Name","Pid","CreatedFileTime");
        var processes=processData.Deserialize<ProcessView>()??throw WfpNative.Contract("OfflineNetworkSurveyProcessMissing");
        if(processes.Error<0 || processes.Error!=0 && processes.Rows.Length!=0 ||
            processes.Rows.Any(row=>!ProcessNames.Contains(row.Name) || row.Pid<=0 ||
                row.CreatedFileTime is long time && (time<=0 || time>DateTime.UtcNow.ToFileTimeUtc())) ||
            processes.Rows.Select(row=>row.Pid).Distinct().Count()!=processes.Rows.Length)
            throw WfpNative.Contract("OfflineNetworkSurveyProcessValue");
        return new(1,session,network,processes);
    }

    private static void AssertLength(long length)
    {
        if(length is <1 or >MaximumBytes)throw WfpNative.Contract("OfflineNetworkSurveySize");
    }

    internal Summary Seal(ProtectedState state,VerifiedVersion version,string jobId,OfflineConsoleNetworkSurvey host,ProcessView hostAfter)
    {
        if(SessionId!=jobId || host.SessionId!=jobId || Network.Pid==host.Network.Pid ||
            host.Network.FinishedFileTime>Network.StartedFileTime)
            throw WfpNative.Contract("OfflineNetworkSurveyReferenceMismatch");
        var hash=state.WriteNew("offline-console-network-"+jobId+".json",JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,state.InstallationId,JobId=jobId,version.Package.Release,version.Package.ManifestHash,
            Restricted=SealActor(this,"restricted"),Trusted=SealActor(host,"trusted"),TrustedProcessesAfter=hostAfter
        }));
        return Compare(host,hostAfter,hash);

        object SealActor(OfflineConsoleNetworkSurvey actor,string role)
        {
            var receipts=actor.Network.Reads.Select((read,index)=>state.WriteNew(
                $"offline-net-{role}-{index}-{jobId}.json",JsonSerializer.SerializeToUtf8Bytes(new {
                    SchemaVersion=1,state.InstallationId,JobId=jobId,version.Package.Release,version.Package.ManifestHash,Actor=role,
                    actor.Network.Pid,actor.Network.StartedFileTime,actor.Network.FinishedFileTime,Read=read
                }))).ToArray();
            return new{actor.Network.Pid,actor.Network.StartedFileTime,actor.Network.FinishedFileTime,ReadsSHA256=receipts,actor.Processes};
        }
    }

    internal Summary Compare(OfflineConsoleNetworkSurvey host,ProcessView hostAfter,string hash)
    {
        var reads=Network.Reads;
        var hostReads=host.Network.Reads;
        var adapters=Decode(reads[0],read=>NetworkContentSnapshot.DecodeAdapters(read.Content,read.NativeBase,8));
        var trustedAdapters=Decode(hostReads[0],read=>NetworkContentSnapshot.DecodeAdapters(read.Content,read.NativeBase,8));
        var linked=(from restricted in ByUniqueGuid(adapters)
                    join trusted in ByUniqueGuid(trustedAdapters) on restricted.Key equals trusted.Key
                    select (restricted:restricted.Value,trusted:trusted.Value)).ToArray();
        var stable=host.Processes.Rows.Intersect(hostAfter.Rows).Where(row=>row.CreatedFileTime is not null).ToArray();
        var observed=Processes.Rows.Where(read=>stable.Any(reference=>read.Pid==reference.Pid && read.Name==reference.Name &&
            (read.CreatedFileTime is null || read.CreatedFileTime==reference.CreatedFileTime))).ToArray();
        var tcpV4=CompareTcp(1,2);
        var tcpV6=CompareTcp(2,23);
        var stableProxy=stable.Where(IsProxy).ToArray();
        var stableRemote=stable.Where(process=>!IsProxy(process)).ToArray();
        var matchingTcp=tcpV4.Matches.Concat(tcpV6.Matches).ToArray();
        return new(hash,Classify(reads[0],trustedAdapters?.Length,adapters?.Length),tcpV4.Summary,tcpV6.Summary,
            linked.Length,
            linked.Count(pair=>pair.restricted.Mac.Length>0 && pair.restricted.Mac==pair.trusted.Mac),
            linked.Sum(pair=>pair.restricted.Unicast.Intersect(pair.trusted.Unicast).Count()),
            linked.Sum(pair=>pair.restricted.Gateways.Intersect(pair.trusted.Gateways).Count()),
            linked.Sum(pair=>pair.restricted.Dns.Intersect(pair.trusted.Dns).Count()),
            tcpV4.Matches.Length,tcpV6.Matches.Length,stableProxy.Length,stableRemote.Length,Processes.Error,Processes.Rows.Length,
            observed.Count(IsProxy),observed.Count(process=>!IsProxy(process)),
            matchingTcp.Count(row=>stableProxy.Any(process=>process.Pid==row.Pid)),
            matchingTcp.Count(row=>stableRemote.Any(process=>process.Pid==row.Pid)));

        (ReadSummary Summary,NetworkContentSnapshot.Tcp[] Matches) CompareTcp(int index,uint family)
        {
            var restricted=Decode(reads[index],read=>NetworkContentSnapshot.DecodeTcp(read.Content,family));
            var trusted=Decode(hostReads[index],read=>NetworkContentSnapshot.DecodeTcp(read.Content,family));
            return (Classify(reads[index],trusted?.Length,restricted?.Length),(restricted??[]).Intersect(trusted??[]).ToArray());
        }
    }

    private static bool IsProxy(ProcessRow process)=>process.Name is "FlClash" or "FlClashCore";

    private static Dictionary<Guid,NetworkContentSnapshot.Adapter> ByUniqueGuid(NetworkContentSnapshot.Adapter[]? adapters) =>
        (adapters??[]).Select(adapter=>(Adapter:adapter,Id:Guid.TryParse(adapter.Name,out var id)?id:Guid.Empty))
            .Where(item=>item.Id!=Guid.Empty).GroupBy(item=>item.Id).Where(group=>group.Count()==1)
            .ToDictionary(group=>group.Key,group=>group.Single().Adapter);

    private static T[]? Decode<T>(NetworkContentRead read,Func<NetworkContentRead,T[]> decode)
    {
        if(read.Content.Length==0)return null;
        try{return decode(read);}
        catch(Exception error)when(error is InvalidDataException or OverflowException or DecoderFallbackException){return null;}
    }

    private static ReadSummary Classify(NetworkContentRead read,int? trustedRows,int? restrictedRows)
    {
        var status=read.Content.Length>0
            ?restrictedRows switch {null=>"UNDECODABLE",0=>"EMPTY",_=>"CONTENT_READ"}
            :read.ErrorKind is null && (read.SizeStatus==5 && read.ReadStatus is null || read.ReadStatus==5)
                ?"DENIED":"UNAVAILABLE";
        return new(status,read.SizeStatus,read.ReadStatus,read.Content.Length,trustedRows,restrictedRows);
    }
}
