using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;

namespace ProtectionLifecycle;

// A real WFP implementation for a fixed installation package SID. It adds or
// reinstates quarantine and opens only the compiled IPv4 proxy endpoint after
// identity qualification. It cannot remove the final barrier for uninstall or
// manufacture lifecycle quiescence.
internal sealed partial class PersistentFence : IDisposable
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
    internal static FenceObservation MigrateRawProxyToSession(ProtectedState state,VerifiedVersion version,string fenceId,RegisteredJobSet jobs)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);jobs.AssertClosedAdmissionsForNetworkMaintenance();
        LifecycleRecovery.AssertNoPending(state,forNetworkMigration:true);
        if(!FencePlan.HasMigration(state,fenceId))
        {
            using var prior=OpenExisting(state,fenceId);
            if(prior.plan.Data.PolicySHA256!=CompiledFencePolicy.SHA256 || prior.plan.Data.ProxyPort!=CompiledFencePolicy.ProxyPort)
                throw WfpNative.Contract("OnlyKnownRawProxyPolicyCanMigrate");
            // Freeze the old channel before writing the durable transition.
            _=prior.ReinstateQuarantine();
        }
        var migration=FencePlan.PrepareMigration(state,version,fenceId);
        using var owner=OpenExisting(state,fenceId);
        _=owner.Mutate("MIGRATE_RAW_PROXY_TO_QUARANTINED_SESSION_GATEWAY",()=>WfpNative.Transaction(owner.engine,false,()=>{
            jobs.AssertClosedAdmissionsForNetworkMaintenance();version.AssertHeld(state);
            var actual=owner.ReadMigrationPlan(migration);
            var action=ClaudeCodeProtection.Security.FenceMigrationSelection.Decide(migration.Prior.SHA256,migration.Next.SHA256,
                owner.plan.SHA256,actual.SHA256,owner.ReadInTransaction(actual).FullQuarantineObserved);
            if(action==ClaudeCodeProtection.Security.FenceMigrationAction.ReplaceKernelThenSelect)
            {
                // Same exact keys and installation SID, full quarantine on both
                // sides, all seven objects replaced in ONE WFP transaction.
                for(var i=0;i<6;i++)WfpNative.Check(WfpNative.FwpmFilterDeleteByKey0(owner.engine,actual.Key(i)),"MigrateExactOwnedFilter");
                WfpNative.Check(WfpNative.FwpmSubLayerDeleteByKey0(owner.engine,actual.SubLayer),"MigrateExactOwnedSubLayer");
                owner.AddSubLayer(migration.Next);for(var i=0;i<6;i++)owner.AddFilter(i,migration.Next);
            }
            var result=owner.ReadInTransaction(migration.Next);
            if(!result.FullQuarantineObserved)throw WfpNative.Contract("MigratedTransactionReadbackMismatch");return result;
        }));
        // Independent committed readback BEFORE selecting the new private image.
        var committed=WfpNative.Transaction(owner.engine,true,()=>owner.ReadInTransaction(migration.Next));
        if(!committed.FullQuarantineObserved)throw WfpNative.Contract("MigratedCommitReadbackMismatch");
        jobs.AssertClosedAdmissionsForNetworkMaintenance();version.AssertHeld(state);
        if(owner.plan.SHA256==migration.Prior.SHA256)
            _=state.ReplacePointer(FencePlan.Leaf(fenceId),migration.Prior.SHA256,migration.NextBytes.Bytes);
        using var selected=OpenExisting(state,fenceId);var final=selected.Observe();
        if(!final.FullQuarantineObserved)throw WfpNative.Contract("MigratedSelectionReadbackMismatch");
        FencePlan.CompleteMigration(state,migration);return final;
    }
    private FencePlan ReadMigrationPlan(FencePlan.Migration migration)
    {
        AssertHeld();var key=migration.Prior.SubLayer;
        var status=WfpNative.FwpmSubLayerGetByKey0(engine,in key,out var pointer);
        try
        {
            WfpNative.Check(status,"ReadMigrationSubLayer");if(pointer==IntPtr.Zero)throw WfpNative.Contract("MigrationSubLayerMissing");
            var layer=Marshal.PtrToStructure<WfpNative.SubLayer>(pointer);
            var actual=LayerIdentityMatches(layer,migration.Prior)?migration.Prior:
                LayerIdentityMatches(layer,migration.Next)?migration.Next:throw WfpNative.Contract("ForeignMigrationSubLayer");
            WfpNative.AssertSecurity(engine,key,WfpNative.FwpmSubLayerGetSecurityInfoByKey0);return actual;
        }
        finally{if(pointer!=IntPtr.Zero)WfpNative.FwpmFreeMemory0(ref pointer);}
    }
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
        return OpenChannel(gateway.AssertReadyToOpen,"OPEN_AUTHENTICATED_SESSION_GATEWAY");
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

    public void Dispose(){lock(gate){if(disposed)return;disposed=true;try{engine.Dispose();}finally{package.Dispose();}}} // Persistent objects remain; close is not cleanup.
}
