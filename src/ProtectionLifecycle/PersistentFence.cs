using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record FenceRoleObservation(string Role,bool Present,bool Persistent,bool PolicyMatches,ulong? ObservedId);
internal sealed record FenceObservation(string FenceId,bool SubLayerPresent,bool SubLayerHealthy,FenceRoleObservation[] Roles,string AtUtc,
    string Scope,bool LaunchQualified,bool ProxyQualified,bool RebootQualified)
{
    internal bool AllAbsent=>!SubLayerPresent && Roles.All(r=>!r.Present);
    internal bool FullQuarantineObserved=>SubLayerHealthy && Roles.Length==6 && Roles.All(r=>r.Present && r.Persistent && r.PolicyMatches);
}

// A real WFP implementation for a fixed installation package SID. It adds or
// reinstates quarantine; it cannot open a proxy path, launch a process, remove
// the final barrier for uninstall, or manufacture lifecycle quiescence.
internal sealed class PersistentFence : IDisposable
{
    private readonly ProtectedState state;
    private readonly FencePlan plan;
    private readonly SafeWfpEngine engine;
    private readonly InstallationPackageSid package;
    private readonly object gate=new();
    private bool disposed;
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
    internal static PersistentFence CreateQuarantined(ProtectedState state,VerifiedVersion version)
    {
        ProtectedState.RequireAdministrator();var plan=FencePlan.Create(state,version);var owner=Open(state,plan);
        try
        {
            owner.Mutate("CREATE_QUARANTINE",()=>{
                _=WfpNative.Transaction(owner.engine,false,()=>{
                var prior=owner.ReadInTransaction();if(!prior.AllAbsent)throw new InvalidDataException("Initial fence keys already exist; not adopted");
                owner.AddSubLayer();for(var i=0;i<6;i++)owner.AddFilter(i);var added=owner.ReadInTransaction();
                if(!added.FullQuarantineObserved)throw new InvalidDataException("New quarantine policy did not match in its transaction");return added;
                });
                var observed=owner.Observe();if(!observed.FullQuarantineObserved)throw new InvalidDataException("Committed quarantine readback differs");
                owner.Record("QUARANTINE_READBACK_OBSERVED",observed);return observed;
            });return owner;
        }
        catch{owner.Dispose();throw;}
    }
    internal static PersistentFence OpenExisting(ProtectedState state,string fenceId)=>Open(state,FencePlan.Read(state,Identifiers.Hex32(fenceId)));
    private void AssertHeld()
    {
        if(disposed || engine.IsClosed || engine.IsInvalid || package.Pointer==IntPtr.Zero)throw new ObjectDisposedException(nameof(PersistentFence));
        state.AssertHeld();if(FencePlan.Read(state,plan.Data.FenceId).SHA256!=plan.SHA256)throw new InvalidDataException("Private fence intent changed");
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
            var replacement=ReadInTransaction();if(!replacement.FullQuarantineObserved)throw new InvalidDataException("Replacement quarantine differs");return replacement;
            });
            var observed=Observe();if(!observed.FullQuarantineObserved)throw new InvalidDataException("Quarantine commit readback differs");
            Record("QUARANTINE_REINSTATED_READBACK",observed);return observed;
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
        AssertHeld();var layerPresent=false;var layerHealthy=false;
        var layerKey=plan.SubLayer;var layerStatus=WfpNative.FwpmSubLayerGetByKey0(engine,in layerKey,out var pointer);
        if(layerStatus!=WfpNative.SubLayerNotFound)
        {
            try
            {
                WfpNative.Check(layerStatus,"ReadExactSubLayer");if(pointer==IntPtr.Zero)throw new InvalidDataException("Missing sublayer response");
                var layer=Marshal.PtrToStructure<WfpNative.SubLayer>(pointer);
                if(layer.Key!=plan.SubLayer || layer.Provider!=IntPtr.Zero || WfpNative.Name(layer.Display.Name)!=plan.Name(-1) || !WfpNative.BlobMatches(layer.Data,plan.Marker(-1)))
                    throw new InvalidDataException("Foreign or changed sublayer identity refused");
                WfpNative.AssertSecurity(engine,layerKey,WfpNative.FwpmSubLayerGetSecurityInfoByKey0);
                layerPresent=true;layerHealthy=layer.Flags==WfpNative.Persistent && layer.Weight==ushort.MaxValue;
            }
            finally{if(pointer!=IntPtr.Zero)WfpNative.FwpmFreeMemory0(ref pointer);}
        }
        else if(pointer!=IntPtr.Zero){WfpNative.FwpmFreeMemory0(ref pointer);throw new InvalidDataException("Unexpected absent sublayer response");}
        var roles=new List<FenceRoleObservation>();
        for(var role=0;role<6;role++)
        {
            var key=plan.Key(role);var status=WfpNative.FwpmFilterGetByKey0(engine,in key,out var filterPointer);
            if(status==WfpNative.FilterNotFound)
            {
                if(filterPointer!=IntPtr.Zero){WfpNative.FwpmFreeMemory0(ref filterPointer);throw new InvalidDataException("Unexpected absent filter response");}
                roles.Add(new(CompiledFencePolicy.Roles[role],false,false,false,null));continue;
            }
            try
            {
                WfpNative.Check(status,"ReadExactFilter");if(filterPointer==IntPtr.Zero)throw new InvalidDataException("Missing filter response");
                var filter=Marshal.PtrToStructure<WfpNative.Filter>(filterPointer);
                if(!layerPresent || filter.Key!=key || filter.Provider!=IntPtr.Zero || filter.SubLayer!=plan.SubLayer || WfpNative.Name(filter.Display.Name)!=plan.Name(role) ||
                    !WfpNative.BlobMatches(filter.Data,plan.Marker(role)) || !PackageMatches(filter))throw new InvalidDataException("Foreign or changed filter ownership refused");
                WfpNative.AssertSecurity(engine,key,WfpNative.FwpmFilterGetSecurityInfoByKey0);
                roles.Add(new(CompiledFencePolicy.Roles[role],true,(filter.Flags&WfpNative.Persistent)!=0,PolicyMatches(filter,role),filter.Id));
            }
            finally{if(filterPointer!=IntPtr.Zero)WfpNative.FwpmFreeMemory0(ref filterPointer);}
        }
        return new(plan.Data.FenceId,layerPresent,layerHealthy,roles.ToArray(),DateTime.UtcNow.ToString("o"),"INSTALLATION_PACKAGE_SID_ALE_CONNECT_ONLY",false,false,false);
    }
    private IEnumerable<WfpNative.Condition> Conditions(WfpNative.Filter filter)
    {
        if(filter.ConditionCount is <1 or >16 || filter.Conditions==IntPtr.Zero)throw new InvalidDataException("Filter condition array invalid");
        var size=Marshal.SizeOf<WfpNative.Condition>();for(var i=0;i<filter.ConditionCount;i++)yield return Marshal.PtrToStructure<WfpNative.Condition>(filter.Conditions+i*size);
    }
    private bool PackageMatches(WfpNative.Filter filter)
    {
        var count=0;
        foreach(var condition in Conditions(filter))
        {
            if(condition.Field!=WfpNative.PackageId)continue;count++;
            if(condition.Match!=WfpNative.Equal || condition.Value.Type!=WfpNative.Sid || condition.Value.Pointer==IntPtr.Zero || !WfpNative.IsValidSid(condition.Value.Pointer) ||
                new SecurityIdentifier(condition.Value.Pointer).Value!=package.Value)return false;
        }
        return count==1;
    }
    private bool PolicyMatches(WfpNative.Filter filter,int role)
    {
        if(filter.Flags!=WfpNative.Persistent || filter.Layer!=(role is 3 or 5?WfpNative.ConnectV6:WfpNative.ConnectV4) || filter.Action.Type!=WfpNative.Block || filter.Action.Key!=Guid.Empty ||
            filter.Context.Key!=Guid.Empty || filter.Reserved!=IntPtr.Zero || filter.Weight.Type!=WfpNative.UInt64 || filter.Weight.Pointer==IntPtr.Zero ||
            unchecked((ulong)Marshal.ReadInt64(filter.Weight.Pointer))!=ulong.MaxValue || filter.ConditionCount!=(role<3?2u:1u))return false;
        var extra=Conditions(filter).Where(c=>c.Field!=WfpNative.PackageId).ToArray();
        if(role>=3)return extra.Length==0;
        if(extra.Length!=1 || extra[0].Match!=WfpNative.NotEqual)return false;var c=extra[0];
        return role switch {
            0=>c.Field==WfpNative.RemoteAddress && c.Value.Type==WfpNative.UInt32 && c.Value.U32==0x7f000001,
            1=>c.Field==WfpNative.RemotePort && c.Value.Type==WfpNative.UInt16 && c.Value.U16==plan.Data.ProxyPort,
            2=>c.Field==WfpNative.Protocol && c.Value.Type==WfpNative.UInt8 && c.Value.U8==6,
            _=>false
        };
    }
    private void AddSubLayer()
    {
        using var arena=new WfpNative.Arena();using var security=new WfpNative.Descriptor();
        var layer=new WfpNative.SubLayer{Key=plan.SubLayer,Display=new(){Name=arena.Text(plan.Name(-1))},Flags=WfpNative.Persistent,Data=arena.Bytes(plan.Marker(-1)),Weight=ushort.MaxValue};
        WfpNative.Check(WfpNative.FwpmSubLayerAdd0(engine,in layer,security.Pointer),"AddExactPersistentSubLayer");
    }
    private void AddFilter(int role)
    {
        using var arena=new WfpNative.Arena();using var security=new WfpNative.Descriptor();
        var conditions=new List<WfpNative.Condition>{new(){Field=WfpNative.PackageId,Match=WfpNative.Equal,Value=new(){Type=WfpNative.Sid,Pointer=package.Pointer}}};
        if(role==0)conditions.Add(new(){Field=WfpNative.RemoteAddress,Match=WfpNative.NotEqual,Value=new(){Type=WfpNative.UInt32,U32=0x7f000001}});
        else if(role==1)conditions.Add(new(){Field=WfpNative.RemotePort,Match=WfpNative.NotEqual,Value=new(){Type=WfpNative.UInt16,U16=checked((ushort)plan.Data.ProxyPort)}});
        else if(role==2)conditions.Add(new(){Field=WfpNative.Protocol,Match=WfpNative.NotEqual,Value=new(){Type=WfpNative.UInt8,U8=6}});
        var filter=new WfpNative.Filter{Key=plan.Key(role),Display=new(){Name=arena.Text(plan.Name(role))},Flags=WfpNative.Persistent,Data=arena.Bytes(plan.Marker(role)),
            Layer=role is 3 or 5?WfpNative.ConnectV6:WfpNative.ConnectV4,SubLayer=plan.SubLayer,Weight=new(){Type=WfpNative.UInt64,Pointer=arena.Struct(ulong.MaxValue)},
            ConditionCount=checked((uint)conditions.Count),Conditions=arena.Conditions(conditions.ToArray()),Action=new(){Type=WfpNative.Block}};
        WfpNative.Check(WfpNative.FwpmFilterAdd0(engine,in filter,security.Pointer,out _),"AddExactPersistentRole");
    }
    public void Dispose(){lock(gate){if(disposed)return;disposed=true;try{engine.Dispose();}finally{package.Dispose();}}} // Persistent objects remain; close is not cleanup.
}
