using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text.Json;

namespace ProtectionLifecycle;

// Native qualification uses the production six-role definitions/matchers on a
// synthetic plan and separate SID. It cannot commit or open installed state.
public static class WfpObjectContract
{
    public static (int ExitCode,string Report) Qualify()
    {
        ProtectedSession.AssertSystemTestingAllowed();
        ProtectedState.RequireAdministrator();
        var folder=WindowsPathSeal.Child(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ClaudeCodeProtection-Qualification-ObjectContract-20261027-r4");
        using var directory=WindowsPathSeal.LockDirectory(folder,PathPolicy.Protected);
        if(!string.Equals(Environment.ProcessPath,WindowsPathSeal.Child(folder,"ProtectionBroker.exe"),StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Assembly.GetEntryAssembly()?.Location,WindowsPathSeal.Child(folder,"ProtectionBroker.dll"),StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(typeof(WfpObjectContract).Assembly.Location,WindowsPathSeal.Child(folder,"ProtectionLifecycle.dll"),StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Fixed protected qualification host required");
        using var package=InstallationPackageSid.ForObjectContractQualification();
        using var engine=WfpNative.Open();var plan=FencePlan.ForObjectContractQualification();
        object? layerObservation=null;var roles=new List<object>();var accepted=true;
        Exception? failure=null;bool aborted=false;bool absent=false;
        WfpNative.Check(WfpNative.FwpmTransactionBegin0(engine,0),"BeginUncommittedObjectQualification");
        try
        {
            using var arena=new WfpNative.Arena();using var descriptor=new WfpNative.Descriptor();
            var layer=PersistentFence.SubLayerDefinition(plan,arena);
            WfpNative.Check(WfpNative.FwpmSubLayerAdd0(engine,in layer,descriptor.Pointer),"AddUncommittedQualificationLayer");
            var key=plan.SubLayer;
            WfpNative.Check(WfpNative.FwpmSubLayerGetByKey0(engine,in key,out var pointer),"ReadUncommittedQualificationLayer");
            try
            {
                if(pointer==IntPtr.Zero)throw WfpNative.Contract("MissingQualificationLayer");
                var read=Marshal.PtrToStructure<WfpNative.SubLayer>(pointer);
                var identity=PersistentFence.LayerIdentityMatches(read,plan);
                var healthy=PersistentFence.LayerPolicyMatches(read);
                layerObservation=new {read.Flags,read.Weight,IdentityMatches=identity,PolicyMatches=healthy,Security=Security(key,WfpNative.FwpmSubLayerGetSecurityInfoByKey0)};
                accepted&=identity && healthy;
                WfpNative.AssertSecurity(engine,key,WfpNative.FwpmSubLayerGetSecurityInfoByKey0);
            }
            finally{if(pointer!=IntPtr.Zero)WfpNative.FwpmFreeMemory0(ref pointer);}
            for(var role=0;role<6;role++)
            {
                var filter=PersistentFence.FilterDefinition(plan,package,role,arena);key=plan.Key(role);
                WfpNative.Check(WfpNative.FwpmFilterAdd0(engine,in filter,descriptor.Pointer,out _),"AddUncommittedQualificationFilter"+role);
                WfpNative.Check(WfpNative.FwpmFilterGetByKey0(engine,in key,out pointer),"ReadUncommittedQualificationFilter"+role);
                try
                {
                    if(pointer==IntPtr.Zero)throw WfpNative.Contract("MissingQualificationFilter");
                    var read=Marshal.PtrToStructure<WfpNative.Filter>(pointer);
                    var identity=PersistentFence.FilterIdentityMatches(read,plan,role,package.Value);
                    var policy=PersistentFence.PolicyMatches(read,role,CompiledFencePolicy.ProxyPort);
                    var size=Marshal.SizeOf<WfpNative.Condition>();
                    if(read.ConditionCount is <1 or >16 || read.Conditions==IntPtr.Zero)throw WfpNative.Contract("QualificationConditionBounds");
                    var conditions=Enumerable.Range(0,checked((int)read.ConditionCount)).Select(i=>{
                        var c=Marshal.PtrToStructure<WfpNative.Condition>(read.Conditions+i*size);
                        return new {c.Field,c.Match,c.Value.Type,c.Value.U32};
                    }).ToArray();
                    var flagCases=new uint[]{0,1,0x40,0x41,0x21,0x61,0x81,0xc1,0x3,0x43,0x5,0x45,0x9,0x49,0x11,0x51}.Select(flags=>{
                        var candidate=read;candidate.Flags=flags;return new {Flags=flags,Accepted=PersistentFence.PolicyMatches(candidate,role,CompiledFencePolicy.ProxyPort)};
                    }).ToArray();
                    roles.Add(new {Role=CompiledFencePolicy.Roles[role],read.Flags,IdentityMatches=identity,PolicyMatches=policy,Conditions=conditions,
                        Security=Security(key,WfpNative.FwpmFilterGetSecurityInfoByKey0),FlagCases=flagCases});
                    accepted&=identity && policy;
                    WfpNative.AssertSecurity(engine,key,WfpNative.FwpmFilterGetSecurityInfoByKey0);
                }
                finally{if(pointer!=IntPtr.Zero)WfpNative.FwpmFreeMemory0(ref pointer);}
            }
            if(!accepted)throw WfpNative.Contract("QualificationFullProductionPolicyMismatch");
        }
        catch(Exception ex){failure=ex;}
        finally
        {
            var status=WfpNative.FwpmTransactionAbort0(engine);aborted=status==0;
            if(!aborted)failure=Combine(failure,new WfpFailure("AbortObjectQualification",status));
        }
        if(aborted)
        {
            try
            {
                for(var role=0;role<6;role++)
                {
                    var key=plan.Key(role);var status=WfpNative.FwpmFilterGetByKey0(engine,in key,out var p);
                    try{if(status!=WfpNative.FilterNotFound || p!=IntPtr.Zero)throw WfpNative.Contract("QualificationFilterAbsenceNotObserved");}
                    finally{if(p!=IntPtr.Zero)WfpNative.FwpmFreeMemory0(ref p);}
                }
                var layerKey=plan.SubLayer;var code=WfpNative.FwpmSubLayerGetByKey0(engine,in layerKey,out var pointer);
                try{if(code!=WfpNative.SubLayerNotFound || pointer!=IntPtr.Zero)throw WfpNative.Contract("QualificationLayerAbsenceNotObserved");}
                finally{if(pointer!=IntPtr.Zero)WfpNative.FwpmFreeMemory0(ref pointer);}
                absent=true;
            }
            catch(Exception ex){failure=Combine(failure,ex);}
        }
        return(failure is null && absent?0:2,JsonSerializer.Serialize(new {SchemaVersion=2,Scope="UNCOMMITTED_SYNTHETIC_PACKAGE_OBJECT_CONTRACT",
            Layer=layerObservation,Roles=roles,AllProductionRolesMatched=accepted && roles.Count==6,
            Aborted=aborted,ObjectsAbsentAfterAbort=absent,Failures=failure is null?Array.Empty<WfpErrorEvidence>():WfpNative.Describe(failure),
            ProductionStateOpened=false,TransactionCommitted=false,ProtectionQualified=false}));

        object Security(Guid key,WfpNative.ReadSecurity read)
        {
            WfpNative.Check(read(engine,in key,1|4,out _,out _,out _,out _,out var p),"ReadQualificationSecurity");
            try
            {
                if(p==IntPtr.Zero)throw WfpNative.Contract("QualificationSecurityMissing");
                var length=GetSecurityDescriptorLength(p);if(length is 0 or >65536)throw WfpNative.Contract("QualificationDescriptorSizeRefused");
                var bytes=new byte[checked((int)length)];Marshal.Copy(p,bytes,0,bytes.Length);
                var sd=new RawSecurityDescriptor(bytes,0);
                return new {Owner=sd.Owner?.Value,ControlFlags=(int)sd.ControlFlags,Sddl=sd.GetSddlForm(AccessControlSections.Owner|AccessControlSections.Access),AceCount=sd.DiscretionaryAcl?.Count};
            }
            finally{if(p!=IntPtr.Zero)WfpNative.FwpmFreeMemory0(ref p);}
        }
    }
    private static Exception Combine(Exception? a,Exception b)=>a is null?b:new AggregateException(a,b);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
}
