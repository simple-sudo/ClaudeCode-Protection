using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed partial class PersistentFence
{
    private void AddSubLayer()=>AddSubLayer(plan);
    private void AddSubLayer(FencePlan plan)
    {
        using var arena=new WfpNative.Arena();using var security=new WfpNative.Descriptor();
        var layer=SubLayerDefinition(plan,arena);
        WfpNative.Check(WfpNative.FwpmSubLayerAdd0(engine,in layer,security.Pointer),"AddExactPersistentSubLayer");
    }
    private void AddFilter(int role)=>AddFilter(role,plan);
    private void AddFilter(int role,FencePlan plan)
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
}
