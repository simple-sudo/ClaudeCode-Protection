using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed class WfpFailure : IOException
{
    internal uint Status { get; }
    internal string Stage { get; }
    internal WfpFailure(string stage,uint status):base(stage+":0x"+status.ToString("X8")){Stage=stage;Status=status;HResult=unchecked((int)status);}
}
internal sealed record WfpErrorEvidence(string Type,uint Code,string? Stage);
internal sealed class SafeWfpEngine : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeWfpEngine():base(true){}
    protected override bool ReleaseHandle()=>WfpNative.FwpmEngineClose0(handle)==0;
}
internal sealed class InstallationPackageSid : IDisposable
{
    internal IntPtr Pointer { get; private set; }
    internal string Value { get; }
    internal InstallationPackageSid(ProtectedState state)
    {
        state.AssertHeld();var status=DeriveAppContainerSidFromAppContainerName("ClaudeCodeProtection."+Identifiers.Hex32(state.InstallationId),out var pointer);
        if(status!=0){if(pointer!=IntPtr.Zero)FreeSid(pointer);throw new WfpFailure("DeriveFixedInstallationPackageSid",unchecked((uint)status));}
        Pointer=pointer;
        try{if(pointer==IntPtr.Zero || !WfpNative.IsValidSid(pointer))throw new InvalidDataException("Derived package SID invalid");Value=new SecurityIdentifier(pointer).Value;}
        catch{Dispose();throw;}
    }
    public void Dispose(){if(Pointer!=IntPtr.Zero){FreeSid(Pointer);Pointer=IntPtr.Zero;}}
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] private static extern int DeriveAppContainerSidFromAppContainerName(string name,out IntPtr sid);
    [DllImport("advapi32.dll")] private static extern IntPtr FreeSid(IntPtr sid);
}

// x64 Win32 declarations, not a native-layout qualification. The size/offset
// assertions run only if this source is eventually compiled and invoked.
internal static class WfpNative
{
    internal const uint FilterNotFound=0x80320003,SubLayerNotFound=0x80320007;
    internal static readonly Guid ConnectV4=new("c38d57d1-05a7-4c33-904f-7fbceee60e82"),ConnectV6=new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"),
        PackageId=new("71bc78fa-f17c-4997-a602-6abb261f351c"),RemoteAddress=new("b235ae9a-1d64-49b8-a44c-5ff3d9095045"),
        RemotePort=new("c35a604d-d22b-4e1a-91b4-68f674ee674b"),Protocol=new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
    internal const uint Persistent=1,Block=0x1001,UInt8=1,UInt16=2,UInt32=3,UInt64=4,Sid=13,Equal=0,NotEqual=10;
    [StructLayout(LayoutKind.Sequential)] internal struct Display {internal IntPtr Name,Description;}
    [StructLayout(LayoutKind.Sequential)] internal struct Blob {internal uint Size;internal IntPtr Data;}
    [StructLayout(LayoutKind.Explicit,Size=16)] internal struct Value {
        [FieldOffset(0)] internal uint Type;[FieldOffset(8)] internal IntPtr Pointer;
        [FieldOffset(8)] internal uint U32;[FieldOffset(8)] internal ushort U16;[FieldOffset(8)] internal byte U8;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct Condition {internal Guid Field;internal uint Match;internal Value Value;}
    [StructLayout(LayoutKind.Sequential)] internal struct Action {internal uint Type;internal Guid Key;}
    [StructLayout(LayoutKind.Explicit,Size=16)] internal struct Context {[FieldOffset(0)] internal ulong Raw;[FieldOffset(0)] internal Guid Key;}
    [StructLayout(LayoutKind.Sequential)] internal struct SubLayer {
        internal Guid Key;internal Display Display;internal uint Flags;internal IntPtr Provider;internal Blob Data;internal ushort Weight;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct Filter {
        internal Guid Key;internal Display Display;internal uint Flags;internal IntPtr Provider;internal Blob Data;internal Guid Layer,SubLayer;internal Value Weight;
        internal uint ConditionCount;internal IntPtr Conditions;internal Action Action;internal Context Context;internal IntPtr Reserved;internal ulong Id;internal Value EffectiveWeight;
    }
    internal static void AssertLayout()
    {
        if(!OperatingSystem.IsWindows() || !Environment.Is64BitProcess || Marshal.SizeOf<Value>()!=16 || Marshal.SizeOf<Blob>()!=16 || Marshal.SizeOf<Condition>()!=40 ||
            Marshal.SizeOf<Action>()!=20 || Marshal.SizeOf<Context>()!=16 || Marshal.SizeOf<SubLayer>()!=72 || Marshal.SizeOf<Filter>()!=200 ||
            Marshal.OffsetOf<Filter>(nameof(Filter.Context)).ToInt32()!=152 || Marshal.OffsetOf<Filter>(nameof(Filter.Id)).ToInt32()!=176)
            throw new PlatformNotSupportedException("Unqualified WFP interop layout");
    }
    internal static SafeWfpEngine Open()
    {
        AssertLayout();var status=FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out var handle);
        if(status!=0){handle?.Dispose();throw new WfpFailure("OpenLocalNonDynamicWfpEngine",status);}
        if(handle is null || handle.IsInvalid){handle?.Dispose();throw new InvalidDataException("WFP engine returned no usable handle");}return handle;
    }
    internal static void Check(uint status,string stage){if(status!=0)throw new WfpFailure(stage,status);}
    internal static WfpErrorEvidence[] Describe(Exception failure)
    {
        var errors=failure is AggregateException group?group.Flatten().InnerExceptions.AsEnumerable():new[]{failure};
        return errors.Select(ex=>new WfpErrorEvidence(ex.GetType().Name,
            ex is WfpFailure native?native.Status:ex is Win32Exception win32?unchecked((uint)win32.NativeErrorCode):unchecked((uint)ex.HResult),
            ex is WfpFailure failed?failed.Stage:ex.Data["Stage"] as string)).ToArray();
    }
    internal static T Transaction<T>(SafeWfpEngine engine,bool readOnly,Func<T> body)
    {
        Check(FwpmTransactionBegin0(engine,readOnly?1u:0u),"BeginWfpTransaction");
        try{var result=body();Check(FwpmTransactionCommit0(engine),"CommitWfpTransaction");return result;}
        catch(Exception ex){var abort=FwpmTransactionAbort0(engine);if(abort!=0)throw new AggregateException("WFP transaction and abort both failed",ex,new WfpFailure("AbortWfpTransaction",abort));throw;}
    }
    internal static string Name(IntPtr pointer)
    {
        if(pointer==IntPtr.Zero)throw new InvalidDataException("WFP name missing");var chars=new List<char>();
        for(var i=0;i<192;i++){var c=(char)Marshal.ReadInt16(pointer,i*2);if(c=='\0')return new(chars.ToArray());chars.Add(c);}throw new InvalidDataException("WFP name exceeds bound");
    }
    internal static bool BlobMatches(Blob actual,byte[] expected)
    {
        if(actual.Size!=expected.Length || actual.Data==IntPtr.Zero)return false;var bytes=new byte[expected.Length];Marshal.Copy(actual.Data,bytes,0,bytes.Length);return bytes.AsSpan().SequenceEqual(expected);
    }
    internal delegate uint ReadSecurity(SafeWfpEngine engine,in Guid key,uint requested,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    internal static void AssertSecurity(SafeWfpEngine engine,Guid key,ReadSecurity read)
    {
        var status=read(engine,in key,1|4,out _,out _,out var dacl,out _,out var descriptor);
        try
        {
            Check(status,"ReadWfpObjectSecurity");
            if(descriptor==IntPtr.Zero || dacl==IntPtr.Zero)throw new InvalidDataException("WFP object security missing");
            var size=GetSecurityDescriptorLength(descriptor);if(size is 0 or >65536)throw new InvalidDataException("WFP security descriptor too large");
            var bytes=new byte[checked((int)size)];Marshal.Copy(descriptor,bytes,0,bytes.Length);var sd=new RawSecurityDescriptor(bytes,0);
            var trusted=new HashSet<string>(StringComparer.Ordinal){"S-1-5-18","S-1-5-32-544"};
            if(sd.Owner is null || !trusted.Contains(sd.Owner.Value) || sd.DiscretionaryAcl is null || sd.DiscretionaryAcl.Count!=2 ||
                (sd.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0)throw new InvalidDataException("WFP object owner/DACL differs");
            foreach(GenericAce ace in sd.DiscretionaryAcl)
                if(ace is not CommonAce common || common.IsCallback || common.AceFlags!=AceFlags.None || common.AceQualifier!=AceQualifier.AccessAllowed ||
                    common.AccessMask==0 || !trusted.Remove(common.SecurityIdentifier.Value))throw new InvalidDataException("Unreviewed WFP grant");
            if(trusted.Count!=0)throw new InvalidDataException("Required WFP grants missing");
        }
        finally{if(descriptor!=IntPtr.Zero)FwpmFreeMemory0(ref descriptor);}
    }
    internal sealed class Arena : IDisposable
    {
        private readonly List<IntPtr> blocks=new();
        internal IntPtr Struct<T>(T value)where T:struct{var pointer=Allocate(Marshal.SizeOf<T>());Marshal.StructureToPtr(value,pointer,false);return pointer;}
        internal IntPtr Text(string value){var pointer=Marshal.StringToHGlobalUni(value);blocks.Add(pointer);return pointer;}
        internal Blob Bytes(byte[] bytes){var pointer=Allocate(bytes.Length);Marshal.Copy(bytes,0,pointer,bytes.Length);return new(){Size=checked((uint)bytes.Length),Data=pointer};}
        internal IntPtr Conditions(Condition[] values){var size=Marshal.SizeOf<Condition>();var pointer=Allocate(checked(size*values.Length));for(var i=0;i<values.Length;i++)Marshal.StructureToPtr(values[i],pointer+i*size,false);return pointer;}
        private IntPtr Allocate(int size){var p=Marshal.AllocHGlobal(size);blocks.Add(p);return p;}
        public void Dispose(){for(var i=blocks.Count-1;i>=0;i--)Marshal.FreeHGlobal(blocks[i]);blocks.Clear();}
    }
    internal sealed class Descriptor : IDisposable
    {
        internal IntPtr Pointer;
        internal Descriptor(){if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:BAG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)",1,out Pointer,out _))throw new Win32Exception(Marshal.GetLastWin32Error());}
        public void Dispose(){if(Pointer!=IntPtr.Zero){LocalFree(Pointer);Pointer=IntPtr.Zero;}}
    }
    [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] private static extern uint FwpmEngineOpen0(string? server,uint authentication,IntPtr identity,IntPtr session,out SafeWfpEngine engine);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] private static extern uint FwpmTransactionBegin0(SafeWfpEngine engine,uint flags);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] private static extern uint FwpmTransactionCommit0(SafeWfpEngine engine);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] private static extern uint FwpmTransactionAbort0(SafeWfpEngine engine);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern uint FwpmSubLayerAdd0(SafeWfpEngine engine,in SubLayer layer,IntPtr security);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern uint FwpmSubLayerGetByKey0(SafeWfpEngine engine,in Guid key,out IntPtr layer);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern uint FwpmSubLayerDeleteByKey0(SafeWfpEngine engine,in Guid key);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern uint FwpmSubLayerGetSecurityInfoByKey0(SafeWfpEngine engine,in Guid key,uint requested,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern uint FwpmFilterAdd0(SafeWfpEngine engine,in Filter filter,IntPtr security,out ulong id);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern uint FwpmFilterGetByKey0(SafeWfpEngine engine,in Guid key,out IntPtr filter);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern uint FwpmFilterDeleteByKey0(SafeWfpEngine engine,in Guid key);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern uint FwpmFilterGetSecurityInfoByKey0(SafeWfpEngine engine,in Guid key,uint requested,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DllImport("fwpuclnt.dll",ExactSpelling=true)] internal static extern void FwpmFreeMemory0(ref IntPtr memory);
    [DllImport("advapi32.dll")] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool IsValidSid(IntPtr sid);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll",EntryPoint="ConvertStringSecurityDescriptorToSecurityDescriptorW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string value,uint revision,out IntPtr descriptor,out uint length);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}
