using System.Runtime.InteropServices;

namespace AfdObserverProtocol;

// Unmanaged DATA only for compiled manifest event sets. No tracing/native API
// or caller-supplied filter IDs are exposed by this class.
internal sealed class EventIdFilter : IDisposable
{
    [StructLayout(LayoutKind.Sequential)] internal struct EventIds {internal byte FilterIn,Reserved;internal ushort Count,Event;}
    [StructLayout(LayoutKind.Sequential)] internal struct Descriptor {internal ulong Pointer;internal uint Size,Type;}
    [StructLayout(LayoutKind.Sequential)] internal struct Parameters
    {internal uint Version,EnableProperty,ControlFlags;internal Guid Source;internal IntPtr Descriptors;internal uint Count;}
    private IntPtr ids,descriptor;
    internal IntPtr Pointer {get;private set;}
    internal static void AssertLayout()
    {
        if(IntPtr.Size!=8 || Marshal.SizeOf<EventIds>()!=6 || Marshal.SizeOf<Descriptor>()!=16 || Marshal.SizeOf<Parameters>()!=48 ||
            Marshal.OffsetOf<EventIds>(nameof(EventIds.Event)).ToInt32()!=4 || Marshal.OffsetOf<Parameters>(nameof(Parameters.Descriptors)).ToInt32()!=32 ||
            Marshal.OffsetOf<Parameters>(nameof(Parameters.Count)).ToInt32()!=40)throw new PlatformNotSupportedException("FixedEtwEventIdFilterAbiRequired");
    }
    internal EventIdFilter(Guid source):this(source,new ushort[]{1000}){}
    internal static EventIdFilter TcpipCreate(Guid source)=>new(source,new ushort[]{1001,1010,1011,1012,1013,1562});
    private EventIdFilter(Guid source,ushort[] events)
    {
        AssertLayout();
        try
        {
            int size=checked(4+events.Length*2);
            ids=Marshal.AllocHGlobal(size);
            Marshal.WriteByte(ids,0,1);Marshal.WriteByte(ids,1,0);Marshal.WriteInt16(ids,2,checked((short)events.Length));
            for(int i=0;i<events.Length;i++)Marshal.WriteInt16(ids,4+i*2,checked((short)events[i]));
            descriptor=Marshal.AllocHGlobal(16);
            Marshal.StructureToPtr(new Descriptor{Pointer=unchecked((ulong)ids.ToInt64()),Size=checked((uint)size),Type=0x80000200},descriptor,false);
            Pointer=Marshal.AllocHGlobal(48);
            Marshal.StructureToPtr(new Parameters{Version=2,Source=source,Descriptors=descriptor,Count=1},Pointer,false);
        }
        catch{Dispose();throw;}
    }
    public void Dispose()
    {
        if(Pointer!=IntPtr.Zero){Marshal.FreeHGlobal(Pointer);Pointer=IntPtr.Zero;}
        if(descriptor!=IntPtr.Zero){Marshal.FreeHGlobal(descriptor);descriptor=IntPtr.Zero;}
        if(ids!=IntPtr.Zero){Marshal.FreeHGlobal(ids);ids=IntPtr.Zero;}
    }
}
