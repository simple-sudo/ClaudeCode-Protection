using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// A descriptor comparison on the creator's attached objects. This does not
// identify the desktop the child ultimately tries to open or mutate either ACL.
internal static class SessionZeroWindowAccess
{
    internal const uint StationRights=0x000f016f,DesktopRights=0x000f01ff;
    private const uint UserObjectFlags=1,Visible=1,DescriptorInformation=7,MaximumAllowed=0x02000000;
    internal readonly record struct ObjectAccess(uint Error,uint CreatorGranted,uint ChildGranted);
    internal readonly record struct Evidence(ObjectAccess Station,ObjectAccess Desktop);

    internal static Evidence Observe(SafeProcessHandle process,SessionZeroCreatorChannel.TokenProof proof,SessionZeroWindowPolicy? privateWindows=null)
    {
        using var identity=WindowsIdentity.GetCurrent(TokenAccessLevels.Query|TokenAccessLevels.Duplicate);
        if(!OpenProcessToken(process,10,out var token))
        {
            var error=LastError();
            token.Dispose();
            return Unavailable(error);
        }
        using(token)
        {
            if(WindowsTokenInformation.ReadPrimaryBinding(token)!=proof.Binding)
                throw WfpNative.Contract("CreatorWindowAccessTokenChanged");
            var result=ObserveTokensCore(identity.AccessToken,token,requireNoninteractive:true,privateWindows);
            if(WindowsTokenInformation.ReadPrimaryBinding(token)!=proof.Binding)
                throw WfpNative.Contract("CreatorWindowAccessTokenChanged");
            return result;
        }
    }

    internal static Evidence ObserveTokens(SafeAccessTokenHandle creator,SafeAccessTokenHandle child,bool requireNoninteractive)
        =>ObserveTokensCore(creator,child,requireNoninteractive,null);

    private static Evidence ObserveTokensCore(SafeAccessTokenHandle creator,SafeAccessTokenHandle child,bool requireNoninteractive,
        SessionZeroWindowPolicy? privateWindows)
    {
        if(!DuplicateTokenEx(creator,8,IntPtr.Zero,1,2,out var creatorQuery))
        {
            var error=LastError();
            creatorQuery.Dispose();
            return Unavailable(error);
        }
        using(creatorQuery)
        {
            if(!DuplicateTokenEx(child,8,IntPtr.Zero,1,2,out var childQuery))
            {
                var error=LastError();
                childQuery.Dispose();
                return Unavailable(error);
            }
            using(childQuery)
            {
                var noninteractiveStation=new Mapping(0x20103,0x2000c,0x20060,StationRights);
                var desktopMapping=new Mapping(0x20041,0x200be,0x20100,DesktopRights);
                if(privateWindows is not null)
                    return new(CheckPolicy(station:true,noninteractiveStation),CheckPolicy(station:false,desktopMapping));
                var station=GetProcessWindowStation();
                if(station==IntPtr.Zero)return Unavailable(LastError());
                if(!GetUserObjectInformation(station,UserObjectFlags,out var flags,12,out var size))
                    return Unavailable(LastError());
                if(size!=12 || requireNoninteractive && (flags.Flags&Visible)!=0)return Unavailable(13);
                var visible=(flags.Flags&Visible)!=0;
                var stationMapping=visible?new Mapping(0x20303,0x2001c,0x20060,0xf037f):noninteractiveStation;
                var stationAccess=ReadAccess(station,creatorQuery,childQuery,stationMapping);
                var desktop=GetThreadDesktop(GetCurrentThreadId());
                var desktopAccess=desktop==IntPtr.Zero?new(LastError(),0,0):
                    ReadAccess(desktop,creatorQuery,childQuery,desktopMapping);
                return new(stationAccess,desktopAccess);

                ObjectAccess CheckPolicy(bool station,Mapping mapping)
                {
                    var policy=privateWindows!.Descriptor(station);
                    var bytes=new byte[policy.BinaryLength];policy.GetBinaryForm(bytes,0);
                    try{return CheckAccess(bytes,creatorQuery,childQuery,mapping);}
                    finally{Array.Clear(bytes);}
                }
            }
        }
    }

    private static ObjectAccess ReadAccess(IntPtr handle,SafeAccessTokenHandle creator,SafeAccessTokenHandle child,Mapping mapping)
    {
        var information=DescriptorInformation;
        if(GetUserObjectSecurity(handle,ref information,null,0,out var needed))return new(13,0,0);
        var error=LastError();
        if(error!=122)return new(error,0,0);
        if(needed is <20 or >65536)return new(13,0,0);
        var descriptor=new byte[checked((int)needed)];
        try
        {
            if(!GetUserObjectSecurity(handle,ref information,descriptor,needed,out var used))return new(LastError(),0,0);
            if(used!=needed)return new(13,0,0);
            return CheckAccess(descriptor,creator,child,mapping);
        }
        finally{Array.Clear(descriptor);}
    }

    private static ObjectAccess CheckAccess(byte[] descriptor,SafeAccessTokenHandle creator,SafeAccessTokenHandle child,Mapping mapping)
    {
        var creatorGrant=Check(creator,out var error);
        if(error!=0)return new(error,0,0);
        var childGrant=Check(child,out error);
        return error==0?new(0,creatorGrant,childGrant):new(error,0,0);

        uint Check(SafeAccessTokenHandle token,out uint status)
        {
            var privileges=new byte[256];uint count=(uint)privileges.Length;
            if(!AccessCheck(descriptor,token,MaximumAllowed,ref mapping,privileges,ref count,out var granted,out var allowed))
            {status=LastError();return 0;}
            status=count>privileges.Length || (granted&~mapping.All)!=0?13u:0;
            return allowed?granted:0;
        }
    }

    private static Evidence Unavailable(uint error)=>new(new(error,0,0),new(error,0,0));
    private static uint LastError()
    {
        var error=unchecked((uint)Marshal.GetLastWin32Error());
        return error==0?13:error;
    }

    [StructLayout(LayoutKind.Sequential)] private record struct Mapping(uint Read,uint Write,uint Execute,uint All);
    [StructLayout(LayoutKind.Sequential)] private struct UserFlags {internal uint Inherit,Reserved,Flags;}
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle process,uint access,out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(SafeAccessTokenHandle token,uint access,IntPtr attributes,int level,int type,out SafeAccessTokenHandle result);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool AccessCheck(byte[] descriptor,SafeAccessTokenHandle token,uint desired,ref Mapping mapping,
        [Out]byte[] privileges,ref uint size,out uint granted,[MarshalAs(UnmanagedType.Bool)]out bool allowed);
    [DllImport("user32.dll",SetLastError=true)] private static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll",SetLastError=true)] private static extern IntPtr GetThreadDesktop(uint threadId);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
    [DllImport("user32.dll",EntryPoint="GetUserObjectInformationW",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetUserObjectInformation(IntPtr handle,uint index,out UserFlags flags,uint bytes,out uint needed);
    [DllImport("user32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetUserObjectSecurity(IntPtr handle,ref uint information,[Out]byte[]? descriptor,uint bytes,out uint needed);
}
