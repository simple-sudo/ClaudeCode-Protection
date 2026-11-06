using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace WfpExistingEvents;

// Internal, read-only diagnostic building block. A separately reviewed fixed
// entry point supplies its compiled plan; no CLI accepts paths, SIDs or times.
internal sealed record Selection(long Start, long End, long CallStart, long CallEnd,
    string UserSid, string PackageSid, string ImageSuffix)
{
    internal void Validate()
    {
        if(Start<=0 || End<=Start || End-Start>TimeSpan.TicksPerSecond*5 ||
            CallStart<Start || CallEnd<CallStart || CallEnd>End ||
            new SecurityIdentifier(UserSid).Value!=UserSid || new SecurityIdentifier(PackageSid).Value!=PackageSid ||
            !PackageSid.StartsWith("S-1-15-2-",StringComparison.Ordinal) ||
            !ImageSuffix.StartsWith('\\') || !ImageSuffix.EndsWith("\\ProtectionBroker.exe",StringComparison.OrdinalIgnoreCase) ||
            ImageSuffix.Contains("..",StringComparison.Ordinal))throw new InvalidDataException("FixedSelectionInvalid");
    }
    internal bool Matches(long timestamp,uint flags,string? user,string? package,string? image) =>
        timestamp>=Start && timestamp<=End && (flags&0x460)==0x460 &&
        user==UserSid && package==PackageSid && image is not null &&
        image.EndsWith(ImageSuffix,StringComparison.OrdinalIgnoreCase);
}

internal sealed class ReadResult
{
    public string Scope {get;}="EXISTING_WFP_HISTORY_READ_ONLY_NOT_PID_BINDING_OR_ADMISSION";
    public uint? OpenStatus {get;set;} public uint? CloseStatus {get;set;}
    public uint? EnumerationCreateStatus {get;set;} public uint? EnumerationDestroyStatus {get;set;}
    public List<object> Options {get;}=new(); public List<uint> PageStatuses {get;}=new();
    public int EntriesExamined {get;set;} public bool EnumerationExhausted {get;set;}
    public bool BoundedStop {get;set;} public string? Failure {get;set;} public int? FailureCode {get;set;}
    public List<object> Selected {get;}=new();
    public bool CollectionEnabledByTool=>false; public bool PolicyChanged=>false;
    public bool ExactActorPidAvailable=>false; public bool HistoricalCompletenessEstablished=>false;
    public bool NetworkAdmission=>false;
}

internal static class Reader
{
    internal const int PageSize=128,MaximumPages=16,MaximumSelected=16;
    internal static ReadResult Read(Selection selection)
    {
        selection.Validate();Native.Layout();var report=new ReadResult();
        IntPtr engine=IntPtr.Zero,enumerator=IntPtr.Zero;var timer=Stopwatch.StartNew();
        try
        {
            report.OpenStatus=Native.FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out var opened);
            if(report.OpenStatus!=0)return report;
            engine=opened;
            if(engine==IntPtr.Zero)throw new InvalidDataException("EngineMissing");
            uint? collection=null;
            foreach(uint option in new uint[]{0,1})
            {
                IntPtr value=IntPtr.Zero;var status=Native.FwpmEngineGetOption0(engine,option,out value);
                try
                {
                    uint? scalar=null;
                    if(status==0){var v=Read<Native.Value>(value);if(v.Type!=3)throw new InvalidDataException("OptionNotDword");scalar=v.U32;}
                    report.Options.Add(new{Option=option,Status=status,Value=scalar});if(option==0 && status==0)collection=scalar;
                }
                finally{Free(ref value);}
            }
            // Never enable collection. Unknown/disabled state stays unknown;
            // absent history is not a negative capability or privacy result.
            if(collection!=1)return report;
            var template=new Native.Template{Start=selection.Start,End=selection.End};
            report.EnumerationCreateStatus=Native.FwpmNetEventCreateEnumHandle0(engine,ref template,out var created);
            if(report.EnumerationCreateStatus!=0)return report;
            enumerator=created;
            if(enumerator==IntPtr.Zero)throw new InvalidDataException("EnumeratorMissing");
            for(int page=0;page<MaximumPages;page++)
            {
                if(timer.ElapsedMilliseconds>=15000){report.BoundedStop=true;break;}
                IntPtr array=IntPtr.Zero;
                var status=Native.FwpmNetEventEnum2(engine,enumerator,PageSize,out array,out var count);
                report.PageStatuses.Add(status);
                try
                {
                    if(status!=0)break;
                    if(count>PageSize || count!=0 && array==IntPtr.Zero)throw new InvalidDataException("EventPageInvalid");
                    for(int index=0;index<count;index++)
                    {
                        var item=Read<Native.Event>(Marshal.ReadIntPtr(array,index*IntPtr.Size));report.EntriesExamined++;
                        if(item.Timestamp<selection.Start || item.Timestamp>selection.End || item.Type is not (3 or 7) || (item.Flags&0x460)!=0x460)continue;
                        var user=Sid(item.User);var package=Sid(item.Package);var image=Image(item.App);
                        if(!selection.Matches(item.Timestamp,item.Flags,user,package,image))continue;
                        if(report.Selected.Count>=MaximumSelected){report.BoundedStop=true;break;}
                        ulong filter;ushort? layer=null;uint? capability=null,direction=null;int loopback;
                        if(item.Type==3){var drop=Read<Native.ClassifyDrop>(item.Data);filter=drop.Filter;layer=drop.Layer;direction=drop.Direction;loopback=drop.Loopback;}
                        else{var drop=Read<Native.CapabilityDrop>(item.Data);filter=drop.Filter;capability=drop.Capability;loopback=drop.Loopback;}
                        if(loopback is not (0 or 1))throw new InvalidDataException("DropLoopbackInvalid");
                        report.Selected.Add(new{item.Timestamp,item.Flags,Type=item.Type,UserSid=user,PackageSid=package,Image=image,
                            WithinOriginalCall=item.Timestamp>=selection.CallStart && item.Timestamp<=selection.CallEnd,
                            Capability=capability,Direction=direction,IsLoopback=loopback==1,FilterId=filter,LayerId=layer,
                            CurrentFilter=Filter(engine,filter),CurrentLayer=layer is null?null:Layer(engine,layer.Value),
                            Binding="PACKAGE_USER_IMAGE_TIME_ONLY_NO_PID_OR_TID"});
                    }
                    if(count<PageSize){report.EnumerationExhausted=true;break;}
                    if(report.BoundedStop)break;
                    if(page==MaximumPages-1)report.BoundedStop=true;
                }
                finally{Free(ref array);} // RPC array owns entries; never free each item.
            }
        }
        catch(Exception error){report.Failure=error.GetType().Name;report.FailureCode=error.HResult;}
        finally
        {
            if(enumerator!=IntPtr.Zero && engine!=IntPtr.Zero)report.EnumerationDestroyStatus=Native.FwpmNetEventDestroyEnumHandle0(engine,enumerator);
            if(engine!=IntPtr.Zero)report.CloseStatus=Native.FwpmEngineClose0(engine);
        }
        return report;
    }
    private static T Read<T>(IntPtr p)where T:struct => p==IntPtr.Zero?throw new InvalidDataException("NativeObjectMissing"):Marshal.PtrToStructure<T>(p);
    private static void Free(ref IntPtr p){if(p!=IntPtr.Zero)Native.FwpmFreeMemory0(ref p);}
    private static string Sid(IntPtr p)
    {if(p==IntPtr.Zero || !Native.IsValidSid(p))throw new InvalidDataException("EventSidInvalid");return new SecurityIdentifier(p).Value;}
    private static string Image(Native.Blob b)
    {
        if(b.Size is <2 or >8192 || b.Size%2!=0 || b.Data==IntPtr.Zero)throw new InvalidDataException("EventImageInvalid");
        var bytes=new byte[b.Size];Marshal.Copy(b.Data,bytes,0,bytes.Length);
        var value=new UnicodeEncoding(false,false,true).GetString(bytes);
        if(value[^1]!='\0' || value[..^1].Contains('\0'))throw new InvalidDataException("EventImageNotTerminated");return value[..^1];
    }
    private static string? Name(IntPtr p)
    {
        if(p==IntPtr.Zero)return null;var text=new StringBuilder();
        for(int i=0;i<256;i++){var c=(char)Marshal.ReadInt16(p,i*2);if(c=='\0')return text.ToString();text.Append(c);}
        return "NAME_EXCEEDS_BOUND";
    }
    private static object Filter(IntPtr engine,ulong id)
    {
        IntPtr p=IntPtr.Zero;var status=Native.FwpmFilterGetById0(engine,id,out p);
        try
        {
            if(status!=0)return new{Status=status,HistoricalIdentityProven=false};var filter=Read<Native.Filter>(p);
            if(filter.Id!=id)throw new InvalidDataException("CurrentFilterIdDiffers");
            Guid? provider=filter.Provider==IntPtr.Zero?null:Read<Guid>(filter.Provider);
            return new{Status=status,filter.Id,filter.Key,Name=Name(filter.Name),filter.Flags,Provider=provider,filter.Layer,filter.SubLayer,
                filter.ActionType,filter.ActionKey,HistoricalIdentityProven=false};
        }
        finally{Free(ref p);}
    }
    private static object Layer(IntPtr engine,ushort id)
    {
        IntPtr p=IntPtr.Zero;var status=Native.FwpmLayerGetById0(engine,id,out p);
        try
        {if(status!=0)return new{Status=status};var layer=Read<Native.Layer>(p);if(layer.Id!=id)throw new InvalidDataException("CurrentLayerIdDiffers");return new{Status=status,layer.Id,layer.Key,Name=Name(layer.Name)};}
        finally{Free(ref p);}
    }
}

internal static class Native
{
    [StructLayout(LayoutKind.Explicit,Size=16)]internal struct Value{[FieldOffset(0)]internal uint Type;[FieldOffset(8)]internal uint U32;}
    [StructLayout(LayoutKind.Sequential)]internal struct Blob{internal uint Size;internal IntPtr Data;}
    [StructLayout(LayoutKind.Explicit,Size=120)]internal struct Event
    {
        [FieldOffset(0)]internal long Timestamp;[FieldOffset(8)]internal uint Flags;
        [FieldOffset(64)]internal Blob App;[FieldOffset(80)]internal IntPtr User;
        [FieldOffset(96)]internal IntPtr Package;[FieldOffset(104)]internal uint Type;[FieldOffset(112)]internal IntPtr Data;
    }
    [StructLayout(LayoutKind.Sequential)]internal struct Template{internal long Start,End;internal uint Count;internal IntPtr Conditions;}
    [StructLayout(LayoutKind.Explicit,Size=56)]internal struct ClassifyDrop
    {[FieldOffset(0)]internal ulong Filter;[FieldOffset(8)]internal ushort Layer;[FieldOffset(24)]internal uint Direction;[FieldOffset(28)]internal int Loopback;}
    [StructLayout(LayoutKind.Explicit,Size=24)]internal struct CapabilityDrop
    {[FieldOffset(0)]internal uint Capability;[FieldOffset(8)]internal ulong Filter;[FieldOffset(16)]internal int Loopback;}
    [StructLayout(LayoutKind.Explicit,Size=200)]internal struct Filter
    {
        [FieldOffset(0)]internal Guid Key;[FieldOffset(16)]internal IntPtr Name;[FieldOffset(32)]internal uint Flags;[FieldOffset(40)]internal IntPtr Provider;
        [FieldOffset(64)]internal Guid Layer;[FieldOffset(80)]internal Guid SubLayer;[FieldOffset(128)]internal uint ActionType;
        [FieldOffset(132)]internal Guid ActionKey;[FieldOffset(176)]internal ulong Id;
    }
    [StructLayout(LayoutKind.Explicit,Size=72)]internal struct Layer
    {[FieldOffset(0)]internal Guid Key;[FieldOffset(16)]internal IntPtr Name;[FieldOffset(64)]internal ushort Id;}
    internal static void Layout()
    {
        if(!OperatingSystem.IsWindows() || !Environment.Is64BitProcess || Marshal.SizeOf<Value>()!=16 || Marshal.SizeOf<Blob>()!=16 ||
            Marshal.OffsetOf<Blob>(nameof(Blob.Data)).ToInt32()!=8 || Marshal.SizeOf<Event>()!=120 || Marshal.SizeOf<Template>()!=32 ||
            Marshal.OffsetOf<Template>(nameof(Template.Conditions)).ToInt32()!=24 || Marshal.SizeOf<ClassifyDrop>()!=56 ||
            Marshal.SizeOf<CapabilityDrop>()!=24 || Marshal.SizeOf<Filter>()!=200 || Marshal.SizeOf<Layer>()!=72)throw new PlatformNotSupportedException("FixedWfpX64LayoutRequired");
    }
    [DllImport("fwpuclnt.dll",ExactSpelling=true,CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]internal static extern uint FwpmEngineOpen0(string? s,uint a,IntPtr i,IntPtr session,out IntPtr engine);
    [DllImport("fwpuclnt.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]internal static extern uint FwpmEngineGetOption0(IntPtr e,uint o,out IntPtr value);
    [DllImport("fwpuclnt.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]internal static extern uint FwpmNetEventCreateEnumHandle0(IntPtr e,ref Template t,out IntPtr handle);
    [DllImport("fwpuclnt.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]internal static extern uint FwpmNetEventEnum2(IntPtr e,IntPtr h,uint count,out IntPtr entries,out uint returned);
    [DllImport("fwpuclnt.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]internal static extern uint FwpmNetEventDestroyEnumHandle0(IntPtr e,IntPtr h);
    [DllImport("fwpuclnt.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]internal static extern uint FwpmFilterGetById0(IntPtr e,ulong id,out IntPtr filter);
    [DllImport("fwpuclnt.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]internal static extern uint FwpmLayerGetById0(IntPtr e,ushort id,out IntPtr layer);
    [DllImport("fwpuclnt.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]internal static extern void FwpmFreeMemory0(ref IntPtr memory);
    [DllImport("fwpuclnt.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]internal static extern uint FwpmEngineClose0(IntPtr e);
    [DllImport("advapi32.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)][return:MarshalAs(UnmanagedType.Bool)]internal static extern bool IsValidSid(IntPtr sid);
}
