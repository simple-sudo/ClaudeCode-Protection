using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Workspaces;

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
        internal string? ProfileReceiptSHA256 {get;init;}
        internal bool ProfileP0Exposure {get;init;}
        internal bool ProfileP0Unknown {get;init;}
        internal int ProfileDirectEvidenceCount {get;init;}
        internal int ProfileInferredClaimCount {get;init;}
        internal bool ConfirmedForFixedReads=>new[]{Adapters,TcpV4,TcpV6}.All(read=>read is {Status:"DENIED",TrustedRows:>0}) &&
            RestrictedProcessQueryError==5 && TrustedStableProxyProcesses>0 && TrustedStableRemoteProcesses>0;
    }
    private sealed record ActorReceipts(string[] Reads,string Processes);

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
        var restrictedReceipts=SealActor(this,"restricted");
        var trustedReceipts=SealActor(host,"trusted");
        var trustedAfterReceipt=state.WriteNew("offline-net-trusted-after-"+jobId+".json",
            JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,JobId=jobId,version.Package.Release,
                version.Package.ManifestHash,Actor="trusted-after",hostAfter}));
        var hash=state.WriteNew("offline-console-network-"+jobId+".json",JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,state.InstallationId,JobId=jobId,version.Package.Release,version.Package.ManifestHash,
            Restricted=SealActorSummary(this,restrictedReceipts),Trusted=SealActorSummary(host,trustedReceipts),
            TrustedProcessesAfterSHA256=trustedAfterReceipt
        }));
        var profile=BuildEvidenceProfile(jobId,restrictedReceipts,trustedReceipts,host,hostAfter);
        var profileHash=state.WriteNew("host-privacy-network-profile-"+jobId+".json",JsonSerializer.SerializeToUtf8Bytes(profile));
        var summary=Compare(host,hostAfter,hash);
        return summary with {
            ProfileReceiptSHA256=profileHash,
            ProfileP0Exposure=profile.P0Exposure,
            ProfileP0Unknown=profile.P0Unknown,
            ProfileDirectEvidenceCount=profile.Assessments.Count(item=>item.Classification==HostPrivacyEvidenceClass.ConfirmedDirect),
            ProfileInferredClaimCount=profile.Inferences.Length
        };

        ActorReceipts SealActor(OfflineConsoleNetworkSurvey actor,string role)
        {
            var receipts=actor.Network.Reads.Select((read,index)=>state.WriteNew(
                $"offline-net-{role}-{index}-{jobId}.json",JsonSerializer.SerializeToUtf8Bytes(new {
                    SchemaVersion=1,state.InstallationId,JobId=jobId,version.Package.Release,version.Package.ManifestHash,Actor=role,
                    actor.Network.Pid,actor.Network.StartedFileTime,actor.Network.FinishedFileTime,Read=read
                }))).ToArray();
            var processReceipt=state.WriteNew($"offline-net-process-{role}-{jobId}.json",
                JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,JobId=jobId,
                    version.Package.Release,version.Package.ManifestHash,Actor=role,actor.Network.Pid,
                    actor.Network.StartedFileTime,actor.Processes}));
            return new(receipts,processReceipt);
        }
        static object SealActorSummary(OfflineConsoleNetworkSurvey actor,ActorReceipts receipts)=>
            new {actor.Network.Pid,actor.Network.StartedFileTime,actor.Network.FinishedFileTime,
                ReadsSHA256=receipts.Reads,ProcessesSHA256=receipts.Processes,actor.Processes};
    }

    private HostPrivacyEvidenceProfile BuildEvidenceProfile(string jobId,ActorReceipts restrictedReceipts,
        ActorReceipts trustedReceipts,OfflineConsoleNetworkSurvey trusted,ProcessView trustedAfter)
    {
        var evidence=new List<HostPrivacyEvidenceRecord>();
        var now=DateTimeOffset.UtcNow;
        var actorId=$"{Network.Pid}:{Network.StartedFileTime}";
        var required=new[]{"network.adapter.guid","network.adapter.mac","network.adapter.address","network.adapter.dns",
            "network.adapter.gateway","network.tcp.v4","network.tcp.v6","network.processes"};
        for(var i=0;i<3;i++)
        {
            AddRead(this,restrictedReceipts.Reads[i],false,i);
            AddRead(trusted,trustedReceipts.Reads[i],true,i);
        }
        var stable=trusted.Processes.Rows.Intersect(trustedAfter.Rows)
            .Where(row=>row.CreatedFileTime is not null).ToArray();
        AddProcesses(this.Processes,restrictedReceipts.Processes,false,stable);
        AddProcesses(trusted.Processes,trustedReceipts.Processes,true,stable);
        return HostPrivacyEvidenceRules.Evaluate(jobId,actorId,evidence,now,required);

        void AddRead(OfflineConsoleNetworkSurvey actor,string receipt,bool hostReference,int index)
        {
            var read=actor.Network.Reads[index];
            var target=index switch {0=>"network.adapter.metadata",1=>"network.tcp.v4",_=>"network.tcp.v6"};
            var sourceFamily=index==0?"iphelper-adapters":"iphelper-tcp";
            var sourceId=index switch {0=>"GetAdaptersAddresses",1=>"GetExtendedTcpTable-v4",_=>"GetExtendedTcpTable-v6"};
            var readTime=DateTimeOffset.FromFileTime(actor.Network.FinishedFileTime);
            void Add(string field,string value,string rowId,string claim="",string key="",string? targetOverride=null,
                bool p0=true,bool sensitive=true)
            {
                evidence.Add(Create(targetOverride??target,field,value,rowId,sourceFamily,claim,key,hostReference,p0,
                    sensitive && value.Length>0,HostPrivacyEvidenceOutcome.ContentRead,true,null,receipt,readTime));
            }
            if(read.Content.Length==0)
            {
                if(hostReference)return;
                var denied=read.ErrorKind is null && (read.SizeStatus==5 && read.ReadStatus is null || read.ReadStatus==5);
                var affected=index==0?new[]{"network.adapter.guid","network.adapter.mac","network.adapter.address",
                    "network.adapter.dns","network.adapter.gateway"}:new[]{target};
                foreach(var affectedTarget in affected)
                    evidence.Add(Create(affectedTarget,"buffer-status","",sourceId,sourceFamily,"","",false,true,false,
                        denied?HostPrivacyEvidenceOutcome.AccessDenied:HostPrivacyEvidenceOutcome.Unknown,
                        false,denied?5:null,receipt,readTime));
                return;
            }
            if(index==0)
            {
                var rows=Decode(read,item=>NetworkContentSnapshot.DecodeAdapters(item.Content,item.NativeBase,8));
                if(rows is null){AddUnknown(target,sourceId,sourceFamily,receipt,readTime,hostReference);return;}
                if(rows.Length==0)
                {
                    foreach(var affectedTarget in new[]{"network.adapter.guid","network.adapter.mac","network.adapter.address",
                        "network.adapter.dns","network.adapter.gateway"})
                        evidence.Add(Create(affectedTarget,"inventory","[]",sourceId,sourceFamily,"","",hostReference,true,false,
                            HostPrivacyEvidenceOutcome.ContentRead,true,null,receipt,readTime));
                    return;
                }
                foreach(var row in rows)
                {
                    var rowId=sourceId+":"+row.IfIndex;
                    Add("interface-guid",row.Name,rowId,"network.interface.guid",row.Name,"network.adapter.guid");
                    Add("mac",row.Mac,rowId,"network.adapter.mac",row.Mac,"network.adapter.mac");
                    Add("description",row.Description,rowId,targetOverride:"network.adapter.metadata",p0:false,sensitive:false);
                    Add("friendly-name",row.FriendlyName,rowId,targetOverride:"network.adapter.metadata",p0:false,sensitive:false);
                    Add("dns-suffix",row.DnsSuffix,rowId,targetOverride:"network.adapter.metadata",p0:false,sensitive:false);
                    if(row.Unicast.Length==0)Add("unicast-inventory","[]",rowId+":u-empty",targetOverride:"network.adapter.address",sensitive:false);
                    else for(var n=0;n<row.Unicast.Length;n++)Add("unicast",row.Unicast[n].Value,rowId+":u"+n,"network.ip.address",row.Unicast[n].Value,"network.adapter.address");
                    if(row.Dns.Length==0)Add("dns-inventory","[]",rowId+":d-empty",targetOverride:"network.adapter.dns",sensitive:false);
                    else for(var n=0;n<row.Dns.Length;n++)Add("dns",row.Dns[n].Value,rowId+":d"+n,"network.dns.address",row.Dns[n].Value,"network.adapter.dns");
                    if(row.Gateways.Length==0)Add("gateway-inventory","[]",rowId+":g-empty",targetOverride:"network.adapter.gateway",sensitive:false);
                    else for(var n=0;n<row.Gateways.Length;n++)Add("gateway",row.Gateways[n].Value,rowId+":g"+n,"network.gateway.address",row.Gateways[n].Value,"network.adapter.gateway");
                }
                return;
            }
            var family=index==1?2u:23u;
            var tcp=Decode(read,item=>NetworkContentSnapshot.DecodeTcp(item.Content,family));
            if(tcp is null){AddUnknown(target,sourceId,sourceFamily,receipt,readTime,hostReference);return;}
            if(tcp.Length==0){Add("inventory","[]",sourceId,sensitive:false);return;}
            for(var n=0;n<tcp.Length;n++)
            {
                var row=tcp[n];var rowId=sourceId+":"+n;
                var endpoint=$"{row.LocalAddress}:{row.LocalPort}->{row.RemoteAddress}:{row.RemotePort}";
                Add("connection",endpoint,rowId,"network.tcp.endpoint",endpoint,target);
                Add("process-pid",row.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture),rowId,
                    "network.process-owner",row.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture),target);
            }
        }

        void AddProcesses(ProcessView view,string receipt,bool hostReference,ProcessRow[] stableRows)
        {
            var readTime=DateTimeOffset.FromFileTime(hostReference?trusted.Network.FinishedFileTime:Network.FinishedFileTime);
            if(view.Error!=0)
            {
                if(hostReference)return;
                var denied=view.Error==5;
                evidence.Add(Create("network.processes","inventory-status","",
                    "process-enumeration","process-inventory","","",false,true,false,
                    denied?HostPrivacyEvidenceOutcome.AccessDenied:HostPrivacyEvidenceOutcome.Unknown,
                    false,denied?5:view.Error,receipt,readTime));
                return;
            }
            var rows=hostReference?stableRows:view.Rows;
            if(rows.Length==0)
            {
                evidence.Add(Create("network.processes","inventory","[]","process-enumeration",
                    "process-inventory","","",hostReference,true,false,HostPrivacyEvidenceOutcome.ContentRead,true,null,receipt,readTime));
                return;
            }
            foreach(var row in rows)
            {
                var key=row.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture);
                var value=$"{row.Name}|{row.Pid}|{row.CreatedFileTime}";
                evidence.Add(Create("network.processes","process",value,"process-enumeration:"+key,
                    "process-inventory","network.process-owner",key,hostReference,true,true,
                    HostPrivacyEvidenceOutcome.ContentRead,true,null,receipt,readTime));
            }
        }

        void AddUnknown(string target,string sourceId,string sourceFamily,string receipt,DateTimeOffset readTime,bool hostReference)
        {
            if(hostReference)return;
            if(target=="network.adapter.metadata")
            {
                foreach(var affectedTarget in new[]{"network.adapter.guid","network.adapter.mac","network.adapter.address",
                    "network.adapter.dns","network.adapter.gateway"})
                    evidence.Add(Create(affectedTarget,"decode-status","",sourceId,sourceFamily,"","",false,true,false,
                        HostPrivacyEvidenceOutcome.Unknown,false,null,receipt,readTime));
                return;
            }
            evidence.Add(Create(target,"decode-status","",sourceId,sourceFamily,"","",false,true,false,
                HostPrivacyEvidenceOutcome.Unknown,false,null,receipt,readTime));
        }

        HostPrivacyEvidenceRecord Create(string target,string field,string value,string sourceId,string sourceFamily,
            string claim,string key,bool hostReference,bool p0,bool sensitive,HostPrivacyEvidenceOutcome outcome,bool verified,int? error,
            string receipt,DateTimeOffset readTime)=>new(
                EvidenceId(target,field,value,sourceId,hostReference?string.Empty:actorId),jobId,
                hostReference?string.Empty:actorId,target,field,value,sourceId,sourceFamily,claim,key,
                hostReference?HostPrivacyEvidenceVisibility.HostReferenceOnly:HostPrivacyEvidenceVisibility.RestrictedActor,
                outcome,true,verified,p0,sensitive,error,readTime,readTime.AddMinutes(15),receipt);
    }

    private static string EvidenceId(string target,string field,string value,string source,string actor)
    {
        var bytes=Encoding.UTF8.GetBytes(string.Join("\u001f",target,field,value,source,actor));
        return WorkspaceBundle.Hash(bytes)[..32].ToLowerInvariant();
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
