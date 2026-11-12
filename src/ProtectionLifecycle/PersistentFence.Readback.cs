using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed partial class PersistentFence
{
    private FenceObservation ReadInTransaction()=>ReadInTransaction(plan);
    private FenceObservation ReadInTransaction(FencePlan plan)
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
}
