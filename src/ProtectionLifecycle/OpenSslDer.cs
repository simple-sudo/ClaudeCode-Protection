using System.Runtime.InteropServices;

namespace ProtectionLifecycle;

internal static class OpenSslDer
{
    internal const uint CheckWholeChainRevocation=0x4u|0x8u;
    internal const uint ExactDnsName=0x22; // no wildcard or subject CN fallback

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate IntPtr Decode(IntPtr previous,ref IntPtr cursor,int length);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void Free(IntPtr owner);

    internal static IntPtr Read(byte[] bytes,Decode decode,Free free)
    {
        var held=GCHandle.Alloc(bytes,GCHandleType.Pinned);
        try
        {
            var start=held.AddrOfPinnedObject();
            var cursor=start;
            var result=decode(IntPtr.Zero,ref cursor,bytes.Length);
            if(result==IntPtr.Zero || cursor==start+bytes.Length)return result;
            free(result);
            return IntPtr.Zero;
        }
        finally{held.Free();}
    }
}
