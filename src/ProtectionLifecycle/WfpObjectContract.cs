using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text.Json;

namespace ProtectionLifecycle;

// Bounded native qualification, separate from read-only diagnostics and the
// installed quarantine path. No installed state, production SID, Job, process
// creation, proxy/network configuration or transaction commit is available.
public static class WfpObjectContract
{
    public static (int ExitCode,string Report) Qualify()
    {
        ProtectedState.RequireAdministrator();
        var folder=WindowsPathSeal.Child(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ClaudeCodeProtection-Qualification-ObjectContract-20261027");
        using var directory=WindowsPathSeal.LockDirectory(folder,PathPolicy.Protected);
        if(!string.Equals(Environment.ProcessPath,WindowsPathSeal.Child(folder,"ProtectionBroker.exe"),StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Assembly.GetEntryAssembly()?.Location,WindowsPathSeal.Child(folder,"ProtectionBroker.dll"),StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(typeof(WfpObjectContract).Assembly.Location,WindowsPathSeal.Child(folder,"ProtectionLifecycle.dll"),StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Fixed protected qualification host required");
        using var package=InstallationPackageSid.ForObjectContractQualification();
        using var engine=WfpNative.Open();
        var layerKey=Guid.NewGuid();var filterKey=Guid.NewGuid();
        object? observation=null;Exception? failure=null;bool aborted=false;bool absent=false;
        WfpNative.Check(WfpNative.FwpmTransactionBegin0(engine,0),"BeginUncommittedObjectQualification");
        try
        {
            using var arena=new WfpNative.Arena();using var descriptor=new WfpNative.Descriptor();
            var layer=new WfpNative.SubLayer{Key=layerKey,Display=new(){Name=arena.Text("CPC object-contract qualification")},Flags=WfpNative.Persistent,Weight=ushort.MaxValue};
            WfpNative.Check(WfpNative.FwpmSubLayerAdd0(engine,in layer,descriptor.Pointer),"AddUncommittedQualificationLayer");
            var conditions=new[]{new WfpNative.Condition{Field=WfpNative.PackageId,Match=WfpNative.Equal,Value=new(){Type=WfpNative.Sid,Pointer=package.Pointer}}};
            var filter=new WfpNative.Filter{Key=filterKey,Display=new(){Name=arena.Text("CPC object-contract qualification")},Flags=WfpNative.Persistent,
                Layer=WfpNative.ConnectV4,SubLayer=layerKey,Weight=new(){Type=WfpNative.UInt64,Pointer=arena.Struct(ulong.MaxValue)},
                ConditionCount=1,Conditions=arena.Conditions(conditions),Action=new(){Type=WfpNative.Block}};
            WfpNative.Check(WfpNative.FwpmFilterAdd0(engine,in filter,descriptor.Pointer,out _),"AddUncommittedQualificationFilter");
            WfpNative.Check(WfpNative.FwpmFilterGetByKey0(engine,in filterKey,out var pointer),"ReadUncommittedQualificationFilter");
            try
            {
                if(pointer==IntPtr.Zero)throw new InvalidDataException("Missing qualification filter response");
                var read=Marshal.PtrToStructure<WfpNative.Filter>(pointer);
                observation=new {LayerSecurity=Security(layerKey,WfpNative.FwpmSubLayerGetSecurityInfoByKey0),FilterSecurity=Security(filterKey,WfpNative.FwpmFilterGetSecurityInfoByKey0),
                    read.Flags,ActionType=read.Action.Type,ActionKey=read.Action.Key,ContextRaw=read.Context.Raw,ContextUnion=read.Context.Key,
                    ReservedPointerIsNull=read.Reserved==IntPtr.Zero,read.ConditionCount,WeightType=read.Weight.Type,
                    Weight=read.Weight.Pointer==IntPtr.Zero?(ulong?)null:unchecked((ulong)Marshal.ReadInt64(read.Weight.Pointer))};
            }
            finally{if(pointer!=IntPtr.Zero)WfpNative.FwpmFreeMemory0(ref pointer);}
        }
        catch(Exception ex){failure=ex;}
        finally
        {
            var status=WfpNative.FwpmTransactionAbort0(engine);aborted=status==0;
            if(!aborted)failure=failure is null?new WfpFailure("AbortObjectQualification",status):new AggregateException(failure,new WfpFailure("AbortObjectQualification",status));
        }
        // Independent post-abort reads. Neither an abort call nor handle close
        // alone is presented as observed absence.
        if(aborted)
        {
            try
            {
                var a=WfpNative.FwpmFilterGetByKey0(engine,in filterKey,out var p);
                try{if(a!=WfpNative.FilterNotFound || p!=IntPtr.Zero)throw new InvalidDataException("Qualification filter absence not observed");}
                finally{if(p!=IntPtr.Zero)WfpNative.FwpmFreeMemory0(ref p);}
                var b=WfpNative.FwpmSubLayerGetByKey0(engine,in layerKey,out p);
                try{if(b!=WfpNative.SubLayerNotFound || p!=IntPtr.Zero)throw new InvalidDataException("Qualification layer absence not observed");}
                finally{if(p!=IntPtr.Zero)WfpNative.FwpmFreeMemory0(ref p);}
                absent=true;
            }
            catch(Exception ex){failure=failure is null?ex:new AggregateException(failure,ex);}
        }
        return(failure is null && absent?0:2,JsonSerializer.Serialize(new {SchemaVersion=1,Scope="UNCOMMITTED_SYNTHETIC_PACKAGE_OBJECT_CONTRACT",Observation=observation,
            Aborted=aborted,ObjectsAbsentAfterAbort=absent,Failures=failure is null?Array.Empty<WfpErrorEvidence>():WfpNative.Describe(failure),
            ProductionStateOpened=false,TransactionCommitted=false,ProtectionQualified=false}));

        object Security(Guid key,WfpNative.ReadSecurity read)
        {
            WfpNative.Check(read(engine,in key,1|4,out _,out _,out _,out _,out var p),"ReadQualificationSecurity");
            try
            {
                if(p==IntPtr.Zero)throw new InvalidDataException("Qualification security missing");
                // ReadSecurity's self-relative descriptor has a bounded length;
                // use the OS length rather than assuming an ACE count/shape.
                var length=GetSecurityDescriptorLength(p);if(length is 0 or >65536)throw new InvalidDataException("Qualification descriptor size refused");
                var bytes=new byte[checked((int)length)];Marshal.Copy(p,bytes,0,bytes.Length);
                var sd=new RawSecurityDescriptor(bytes,0);
                return new {Owner=sd.Owner?.Value,ControlFlags=(int)sd.ControlFlags,Sddl=sd.GetSddlForm(AccessControlSections.Owner|AccessControlSections.Access),AceCount=sd.DiscretionaryAcl?.Count};
            }
            finally{if(p!=IntPtr.Zero)WfpNative.FwpmFreeMemory0(ref p);}
        }
    }
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
}
