using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;

if(args.Length==1 && args[0]=="--check-machine-egress-policy")
{
    MachineEgressProbeCases.Run();
    return 0;
}
if(args.Length==1 && args[0]=="--read-machine-egress-layers")
    return MachineEgressProbeCases.ReadLayers();
if(args.Length==1 && args[0]=="--check-selection")
{Console.WriteLine(JsonSerializer.Serialize(WfpExistingEvents.SelectionChecks.Run()));return 0;}
if(args.Length!=1 || args[0] is not ("--inspect" or "--read-fixed"))return 125;
if(!OperatingSystem.IsWindows() || !Environment.Is64BitProcess || Marshal.SizeOf<Native.Value>()!=16)
    throw new PlatformNotSupportedException("FixedWfpReadLayoutRequired");
if(args[0]=="--inspect")
{
    Console.WriteLine(JsonSerializer.Serialize(new{Scope="WFP_FIXED_READ_LAYOUT_ONLY",ValueBytes=Marshal.SizeOf<Native.Value>(),
        ValueOffset=Marshal.OffsetOf<Native.Value>(nameof(Native.Value.U32)).ToInt32(),EngineOpened=false,PolicyChanged=false}));return 0;
}
using var identity=WindowsIdentity.GetCurrent();
var administrator=new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
IntPtr engine=IntPtr.Zero;uint? close=null;
var options=new List<object>();string? failure=null;int? failureCode=null;
var opened=Native.FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out var returned);
try
{
    if(opened==0)
    {
        if(returned==IntPtr.Zero)throw new InvalidDataException("WfpReadEngineMissing");
        engine=returned;
        // Only existing collection state and keyword state. No setter,
        // subscription, event enumeration, filter or resource mutation API.
        foreach(uint option in new uint[]{0,1})
        {
            IntPtr value=IntPtr.Zero;
            var status=Native.FwpmEngineGetOption0(engine,option,out value);
            try
            {
                uint? kind=null,scalar=null;
                if(status==0)
                {
                    if(value==IntPtr.Zero)throw new InvalidDataException("WfpReadOptionMissing");
                    var read=Marshal.PtrToStructure<Native.Value>(value);kind=read.Type;
                    if(kind!=3)throw new InvalidDataException("WfpReadOptionNotDword");scalar=read.U32;
                }
                options.Add(new{Option=option,Status=status,ValueType=kind,Value=scalar});
            }
            finally{if(value!=IntPtr.Zero)Native.FwpmFreeMemory0(ref value);}
        }
    }
}
catch(Exception error){failure=error.GetType().Name;failureCode=error.HResult;}
finally{if(engine!=IntPtr.Zero)close=Native.FwpmEngineClose0(engine);}
Console.WriteLine(JsonSerializer.Serialize(new{Scope="READ_ONLY_EXISTING_WFP_COLLECTION_OPTIONS_NO_POLICY_CHANGE",Administrator=administrator,
    EngineOpenStatus=opened,OwnConnectionCloseStatus=close,Options=options,FailureType=failure,FailureCode=failureCode,
    EventEnumerationPerformed=false,CollectionEnabledByThisTool=false,PolicyChanged=false,TraceStarted=false,NetworkAdmission=false}));
return 0; // An OS denial is retained data, never success/collection proof.

internal static class Native
{
    [StructLayout(LayoutKind.Explicit,Size=16)]internal struct Value
    {[FieldOffset(0)]internal uint Type;[FieldOffset(8)]internal uint U32;}
    [DllImport("fwpuclnt.dll",ExactSpelling=true,CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint FwpmEngineOpen0(string? server,uint authentication,IntPtr identity,IntPtr session,out IntPtr engine);
    [DllImport("fwpuclnt.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint FwpmEngineGetOption0(IntPtr engine,uint option,out IntPtr value);
    [DllImport("fwpuclnt.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern void FwpmFreeMemory0(ref IntPtr memory);
    [DllImport("fwpuclnt.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint FwpmEngineClose0(IntPtr engine);
}
