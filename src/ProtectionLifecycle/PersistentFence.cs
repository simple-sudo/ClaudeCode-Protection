using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record FenceRoleObservation(string Role,bool Present,bool Persistent,bool PolicyMatches,ulong? ObservedId);
internal sealed record FenceObservation(string FenceId,bool SubLayerPresent,bool SubLayerHealthy,FenceRoleObservation[] Roles,string AtUtc,
    string Scope,bool LaunchQualified,bool ProxyQualified,bool RebootQualified,ushort? ObservedSubLayerWeight)
{
    internal bool AllAbsent=>!SubLayerPresent && Roles.All(r=>!r.Present);
    internal bool FullQuarantineObserved=>SubLayerHealthy && Roles.Length==6 && Roles.All(r=>r.Present && r.Persistent && r.PolicyMatches);
    internal bool IPv4ProxyOnlyObserved=>SubLayerHealthy && Roles.Length==6 && Roles.Select((r,i)=>i==4?!r.Present:r.Present && r.Persistent && r.PolicyMatches).All(ok=>ok);
}

// A real WFP implementation for a fixed installation package SID. It adds or
// reinstates quarantine and opens only the compiled IPv4 proxy endpoint after
// identity qualification. It cannot remove the final barrier for uninstall or
// manufacture lifecycle quiescence.
internal sealed class PersistentFence : IDisposable
{
    private readonly ProtectedState state;
    private readonly FencePlan plan;
    private readonly SafeWfpEngine engine;
    private readonly InstallationPackageSid package;
    private readonly object gate=new();
    private bool disposed;
    internal bool IsSessionChannel=>plan.Data.PolicySHA256==SessionProxy.PolicySHA256 && plan.Data.ProxyPort==SessionProxy.Port;
    internal string IntentSHA256=>plan.SHA256;
    private PersistentFence(ProtectedState state,FencePlan plan,SafeWfpEngine engine,InstallationPackageSid package)
    {this.state=state;this.plan=plan;this.engine=engine;this.package=package;}
    private static PersistentFence Open(ProtectedState state,FencePlan plan)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();InstallationPackageSid? sid=null;SafeWfpEngine? engine=null;
        try{sid=new(state);engine=WfpNative.Open();return new(state,plan,engine,sid);}
        catch(Exception ex)
        {
            try{state.WriteNew("fence-open-failure-"+plan.Data.FenceId+"-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,InstallationId=state.InstallationId,plan.Data.FenceId,IntentSHA256=plan.SHA256,Status="ENGINE_OR_IDENTITY_NOT_OBSERVED",
                Failures=WfpNative.Describe(ex),AtUtc=DateTime.UtcNow.ToString("o")
            }));}catch(Exception log){throw new AggregateException("WFP open and failure recording both failed",ex,log);}finally{engine?.Dispose();sid?.Dispose();}throw;
        }
    }
    internal static PersistentFence CreateQuarantined(ProtectedState state,VerifiedVersion version)=>CreateQuarantined(state,version,false);
    internal static PersistentFence CreateSessionQuarantined(ProtectedState state,VerifiedVersion version)=>CreateQuarantined(state,version,true);
    private static PersistentFence CreateQuarantined(ProtectedState state,VerifiedVersion version,bool session)
    {
        ProtectedState.RequireAdministrator();var plan=session?FencePlan.CreateSession(state,version):FencePlan.Create(state,version);var owner=Open(state,plan);
        try
        {
            owner.Mutate("CREATE_QUARANTINE",()=>{
                _=WfpNative.Transaction(owner.engine,false,()=>{
                var prior=owner.ReadInTransaction();if(!prior.AllAbsent)throw WfpNative.Contract("Initial fence keys already exist; not adopted");
                owner.AddSubLayer();for(var i=0;i<6;i++)owner.AddFilter(i);var added=owner.ReadInTransaction();
                if(!added.FullQuarantineObserved)throw WfpNative.Contract("NewQuarantinePolicyReadbackMismatch");return added;
                });
                var observed=owner.Observe();if(!observed.FullQuarantineObserved)throw WfpNative.Contract("Committed quarantine readback differs");
                owner.Record("QUARANTINE_READBACK_OBSERVED",observed);return observed;
            });return owner;
        }
        catch{owner.Dispose();throw;}
    }
    internal static PersistentFence OpenExisting(ProtectedState state,string fenceId)=>Open(state,FencePlan.Read(state,Identifiers.Hex32(fenceId)));
    private void AssertHeld()
    {
        if(disposed || engine.IsClosed || engine.IsInvalid || package.Pointer==IntPtr.Zero)throw new ObjectDisposedException(nameof(PersistentFence));
        state.AssertHeld();if(FencePlan.Read(state,plan.Data.FenceId).SHA256!=plan.SHA256)throw WfpNative.Contract("Private fence intent changed");
    }
    internal FenceObservation Observe()
    {lock(gate){AssertHeld();return WfpNative.Transaction(engine,true,ReadInTransaction);}}
    internal FenceObservation ReinstateQuarantine()
    {
        return Mutate("REINSTATE_QUARANTINE",()=>{
            _=WfpNative.Transaction(engine,false,()=>{
            // ALL ownership is verified before any delete. Replacement stays in
            // one transaction; no committed interval intentionally opens scope.
            var old=ReadInTransaction();
            for(var i=0;i<6;i++)if(old.Roles[i].Present)WfpNative.Check(WfpNative.FwpmFilterDeleteByKey0(engine,plan.Key(i)),"ReplaceExactOwnedFilter");
            if(old.SubLayerPresent)WfpNative.Check(WfpNative.FwpmSubLayerDeleteByKey0(engine,plan.SubLayer),"ReplaceExactOwnedSubLayer");
            AddSubLayer();for(var i=0;i<6;i++)AddFilter(i);
            var replacement=ReadInTransaction();if(!replacement.FullQuarantineObserved)throw WfpNative.Contract("Replacement quarantine differs");return replacement;
            });
            var observed=Observe();if(!observed.FullQuarantineObserved)throw WfpNative.Contract("Quarantine commit readback differs");
            Record("QUARANTINE_REINSTATED_READBACK",observed);return observed;
        });
    }
    internal FenceObservation OpenQualifiedIPv4Proxy(ProxyChannelLease proxy)
    {
        proxy.AssertHealthy();
        if(plan.Data.PolicySHA256!=CompiledFencePolicy.SHA256 || plan.Data.ProxyPort!=CompiledFencePolicy.ProxyPort)
            throw WfpNative.Contract("HistoricalFenceCannotGrantProxyAdmission");
        return OpenChannel(proxy.AssertHealthy,"OPEN_QUALIFIED_COMPILED_IPV4_PROXY");
    }
    internal FenceObservation OpenSessionGateway(SessionProxy gateway)
    {
        if(!IsSessionChannel)throw WfpNative.Contract("RawProxyFenceCannotGrantSessionAdmission");
        return OpenChannel(gateway.AssertHealthy,"OPEN_AUTHENTICATED_SESSION_GATEWAY");
    }
    private FenceObservation OpenChannel(Action assertChannel,string operation)
    {
        assertChannel();
        return Mutate(operation,()=>{
            _=WfpNative.Transaction(engine,false,()=>{
                var before=ReadInTransaction();if(!before.FullQuarantineObserved)throw WfpNative.Contract("ProxyOpenRequiresFullQuarantine");
                assertChannel();WfpNative.Check(WfpNative.FwpmFilterDeleteByKey0(engine,plan.Key(4)),"RemoveExactIPv4QuarantineOnly");
                var after=ReadInTransaction();if(!after.IPv4ProxyOnlyObserved)throw WfpNative.Contract("IPv4ProxyPolicyTransactionMismatch");return after;
            });
            var committed=Observe();if(!committed.IPv4ProxyOnlyObserved)throw WfpNative.Contract("IPv4ProxyPolicyCommitMismatch");
            assertChannel();Record("COMPILED_IPV4_PROXY_ONLY_OBSERVED",committed);return committed;
        });
    }
    private T Mutate<T>(string operation,Func<T> body)
    {
        lock(gate)
        {
        AssertHeld();var attempt=Guid.NewGuid().ToString("N");
        state.WriteNew("fence-before-"+plan.Data.FenceId+"-"+attempt+".json",JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,InstallationId=state.InstallationId,plan.Data.FenceId,IntentSHA256=plan.SHA256,Operation=operation,
            Scope="INSTALLATION_PACKAGE_SID_ONLY",LaunchQualified=false,AtUtc=DateTime.UtcNow.ToString("o")
        }));
        try{return body();}
        catch(Exception ex)
        {
            try{state.WriteNew("fence-failure-"+plan.Data.FenceId+"-"+attempt+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,InstallationId=state.InstallationId,plan.Data.FenceId,IntentSHA256=plan.SHA256,Operation=operation,Status="NOT_CONFIRMED",
                FailureType=ex.GetType().Name,FailureCode=ex is WfpFailure native?native.Status:unchecked((uint)ex.HResult),
                FailureStage=ex is WfpFailure failed?failed.Stage:null,Failures=WfpNative.Describe(ex),AtUtc=DateTime.UtcNow.ToString("o")
            }));}catch(Exception log){throw new AggregateException("WFP operation and failure recording both failed",ex,log);}throw;
        }
        }
    }
    private void Record(string status,FenceObservation observed)
    {state.WriteNew("fence-observed-"+plan.Data.FenceId+"-"+Guid.NewGuid().ToString("N")+".json",JsonSerializer.SerializeToUtf8Bytes(new {
        SchemaVersion=1,InstallationId=state.InstallationId,plan.Data.FenceId,IntentSHA256=plan.SHA256,Status=status,Observation=observed
    }));}
    private FenceObservation ReadInTransaction()
    {
        AssertHeld();var layerPresent=false;var layerHealthy=false;ushort? observedWeight=null;
        var layerKey=plan.SubLayer;var layerStatus=WfpNative.FwpmSubLayerGetByKey0(engine,in layerKey,out var pointer);
        if(layerStatus!=WfpNative.SubLayerNotFound)
        {
            try
            {
                WfpNative.Check(layerStatus,"ReadExactSubLayer");if(pointer==IntPtr.Zero)throw WfpNative.Contract("Missing sublayer response");
                var layer=Marshal.PtrToStructure<WfpNative.SubLayer>(pointer);
                if(!LayerIdentityMatches(layer,plan))
                    throw WfpNative.Contract("Foreign or changed sublayer identity refused");
                WfpNative.AssertSecurity(engine,layerKey,WfpNative.FwpmSubLayerGetSecurityInfoByKey0);
                // BFE assigns the closest available weight; the request is
                // not an exact round-trip guarantee. Expose actual priority
                // for a future activation/drift lease, never claim top rank.
                layerPresent=true;layerHealthy=LayerPolicyMatches(layer);observedWeight=layer.Weight;
            }
            finally{if(pointer!=IntPtr.Zero)WfpNative.FwpmFreeMemory0(ref pointer);}
        }
        else if(pointer!=IntPtr.Zero){WfpNative.FwpmFreeMemory0(ref pointer);throw WfpNative.Contract("Unexpected absent sublayer response");}
        var roles=new List<FenceRoleObservation>();
        for(var role=0;role<6;role++)
        {
            var key=plan.Key(role);var status=WfpNative.FwpmFilterGetByKey0(engine,in key,out var filterPointer);
            if(status==WfpNative.FilterNotFound)
            {
                if(filterPointer!=IntPtr.Zero){WfpNative.FwpmFreeMemory0(ref filterPointer);throw WfpNative.Contract("Unexpected absent filter response");}
                roles.Add(new(CompiledFencePolicy.Roles[role],false,false,false,null));continue;
            }
            try
            {
                WfpNative.Check(status,"ReadExactFilter");if(filterPointer==IntPtr.Zero)throw WfpNative.Contract("Missing filter response");
                var filter=Marshal.PtrToStructure<WfpNative.Filter>(filterPointer);
                if(!layerPresent || !FilterIdentityMatches(filter,plan,role,package.Value))throw WfpNative.Contract("Foreign or changed filter ownership refused");
                WfpNative.AssertSecurity(engine,key,WfpNative.FwpmFilterGetSecurityInfoByKey0);
                roles.Add(new(CompiledFencePolicy.Roles[role],true,(filter.Flags&WfpNative.Persistent)!=0,PolicyMatches(filter,role,plan.Data.ProxyPort),filter.Id));
            }
            finally{if(filterPointer!=IntPtr.Zero)WfpNative.FwpmFreeMemory0(ref filterPointer);}
        }
        return new(plan.Data.FenceId,layerPresent,layerHealthy,roles.ToArray(),DateTime.UtcNow.ToString("o"),"INSTALLATION_PACKAGE_SID_ALE_CONNECT_ONLY",false,false,false,observedWeight);
    }
    private static IEnumerable<WfpNative.Condition> Conditions(WfpNative.Filter filter)
    {
        if(filter.ConditionCount is <1 or >16 || filter.Conditions==IntPtr.Zero)throw WfpNative.Contract("Filter condition array invalid");
        var size=Marshal.SizeOf<WfpNative.Condition>();for(var i=0;i<filter.ConditionCount;i++)yield return Marshal.PtrToStructure<WfpNative.Condition>(filter.Conditions+i*size);
    }
    internal static bool LayerIdentityMatches(WfpNative.SubLayer layer,FencePlan plan)=>layer.Key==plan.SubLayer && layer.Provider==IntPtr.Zero &&
        WfpNative.Name(layer.Display.Name)==plan.Name(-1) && WfpNative.BlobMatches(layer.Data,plan.Marker(-1));
    internal static bool LayerPolicyMatches(WfpNative.SubLayer layer)=>layer.Flags==WfpNative.Persistent;
    internal static bool FilterIdentityMatches(WfpNative.Filter filter,FencePlan plan,int role,string packageSid)=>
        filter.Key==plan.Key(role) && filter.Provider==IntPtr.Zero && filter.SubLayer==plan.SubLayer && WfpNative.Name(filter.Display.Name)==plan.Name(role) &&
        WfpNative.BlobMatches(filter.Data,plan.Marker(role)) && PackageMatches(filter,packageSid);
    private static bool PackageMatches(WfpNative.Filter filter,string packageSid)
    {
        var count=0;
        foreach(var condition in Conditions(filter))
        {
            if(condition.Field!=WfpNative.PackageId)continue;count++;
            if(condition.Match!=WfpNative.Equal || condition.Value.Type!=WfpNative.Sid || condition.Value.Pointer==IntPtr.Zero || !WfpNative.IsValidSid(condition.Value.Pointer) ||
                new SecurityIdentifier(condition.Value.Pointer).Value!=packageSid)return false;
        }
        return count==1;
    }
    internal static bool PolicyMatches(WfpNative.Filter filter,int role,int proxyPort)
    {
        if(role is <0 or >5 || proxyPort is <1 or >65535)throw new ArgumentOutOfRangeException(nameof(role));
        if(!WfpNative.ExpectedPersistentFilterFlags(filter.Flags) || filter.Layer!=(role is 3 or 5?WfpNative.ConnectV6:WfpNative.ConnectV4) || filter.Action.Type!=WfpNative.Block || filter.Action.Key!=Guid.Empty ||
            filter.Context.Key!=Guid.Empty || filter.Reserved!=IntPtr.Zero || filter.Weight.Type!=WfpNative.UInt64 || filter.Weight.Pointer==IntPtr.Zero ||
            unchecked((ulong)Marshal.ReadInt64(filter.Weight.Pointer))!=ulong.MaxValue || filter.ConditionCount!=(role<3?2u:1u))return false;
        var extra=Conditions(filter).Where(c=>c.Field!=WfpNative.PackageId).ToArray();
        if(role>=3)return extra.Length==0;
        if(extra.Length!=1 || extra[0].Match!=WfpNative.NotEqual)return false;var c=extra[0];
        return role switch {
            0=>c.Field==WfpNative.RemoteAddress && c.Value.Type==WfpNative.UInt32 && c.Value.U32==0x7f000001,
            1=>c.Field==WfpNative.RemotePort && c.Value.Type==WfpNative.UInt16 && c.Value.U16==proxyPort,
            2=>c.Field==WfpNative.Protocol && c.Value.Type==WfpNative.UInt8 && c.Value.U8==6,
            _=>false
        };
    }
    private void AddSubLayer()
    {
        using var arena=new WfpNative.Arena();using var security=new WfpNative.Descriptor();
        var layer=SubLayerDefinition(plan,arena);
        WfpNative.Check(WfpNative.FwpmSubLayerAdd0(engine,in layer,security.Pointer),"AddExactPersistentSubLayer");
    }
    private void AddFilter(int role)
    {
        using var arena=new WfpNative.Arena();using var security=new WfpNative.Descriptor();
        var filter=FilterDefinition(plan,package,role,arena);
        WfpNative.Check(WfpNative.FwpmFilterAdd0(engine,in filter,security.Pointer,out _),"AddExactPersistentRole");
    }
    internal static WfpNative.SubLayer SubLayerDefinition(FencePlan plan,WfpNative.Arena arena)=>
        new(){Key=plan.SubLayer,Display=new(){Name=arena.Text(plan.Name(-1))},Flags=WfpNative.Persistent,Data=arena.Bytes(plan.Marker(-1)),Weight=ushort.MaxValue};
    internal static WfpNative.Filter FilterDefinition(FencePlan plan,InstallationPackageSid package,int role,WfpNative.Arena arena)
    {
        var conditions=new List<WfpNative.Condition>{new(){Field=WfpNative.PackageId,Match=WfpNative.Equal,Value=new(){Type=WfpNative.Sid,Pointer=package.Pointer}}};
        if(role==0)conditions.Add(new(){Field=WfpNative.RemoteAddress,Match=WfpNative.NotEqual,Value=new(){Type=WfpNative.UInt32,U32=0x7f000001}});
        else if(role==1)conditions.Add(new(){Field=WfpNative.RemotePort,Match=WfpNative.NotEqual,Value=new(){Type=WfpNative.UInt16,U16=checked((ushort)plan.Data.ProxyPort)}});
        else if(role==2)conditions.Add(new(){Field=WfpNative.Protocol,Match=WfpNative.NotEqual,Value=new(){Type=WfpNative.UInt8,U8=6}});
        return new WfpNative.Filter{Key=plan.Key(role),Display=new(){Name=arena.Text(plan.Name(role))},Flags=WfpNative.Persistent,Data=arena.Bytes(plan.Marker(role)),
            Layer=role is 3 or 5?WfpNative.ConnectV6:WfpNative.ConnectV4,SubLayer=plan.SubLayer,Weight=new(){Type=WfpNative.UInt64,Pointer=arena.Struct(ulong.MaxValue)},
            ConditionCount=checked((uint)conditions.Count),Conditions=arena.Conditions(conditions.ToArray()),Action=new(){Type=WfpNative.Block}};
    }
    public void Dispose(){lock(gate){if(disposed)return;disposed=true;try{engine.Dispose();}finally{package.Dispose();}}} // Persistent objects remain; close is not cleanup.
}
