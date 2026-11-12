using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed partial class AtomicChild
{
    private static AdmissionToken ReadToken(SafeProcessHandle process,bool observePackageAccess=true)
        =>ReadTokenSnapshot(process,observePackageAccess,false,out _);

    // The trusted creator can run the native access check against the exact
    // child it holds. Transfer data only; no token or impersonation authority.
    internal static SessionZeroCreatorChannel.TokenProof ObserveCreatorTokenProof(SafeProcessHandle process)
    {
        if(!OpenProcessToken(process,8|2,out var token))throw Error("CreatorOpenHeldChildTokenForAccessCheck");
        using(token)
        {
            var binding=WindowsTokenInformation.ReadPrimaryBinding(token);
            var access=ProbeApplicationPackageAccess(token);
            if(WindowsTokenInformation.ReadPrimaryBinding(token)!=binding)
                throw WfpNative.Contract("CreatorPrimaryTokenChangedDuringAccessCheck");
            return new(binding,access);
        }
    }

    private static SafeAccessTokenHandle OpenCreatorQueryToken(SafeProcessHandle process)
    {
        if(!OpenProcessToken(process,8,out var token))throw Error("CreatorChildTokenQueryOnly");
        return token;
    }

    private static AdmissionToken ReadIndependentOfflineToken(SafeProcessHandle process,SessionZeroCreatorChannel.TokenProof proof,
        out SecurityIdentifier? user)
    {
        using var token=OpenCreatorQueryToken(process);
        AssertCreatorLpacBinding(proof,WindowsTokenInformation.ReadPrimaryBinding(token));
        var snapshot=ReadHeldTokenSnapshot(token,false,true,out user);
        AssertCreatorLpacBinding(proof,WindowsTokenInformation.ReadPrimaryBinding(token));
        return snapshot with {LpacAccessCheckObserved=snapshot.IsAppContainer,ApplicationPackageAccessMask=proof.PackageAccess};
    }

    private static void AssertCreatorLpacBinding(SessionZeroCreatorChannel.TokenProof proof,WindowsTokenInformation.PrimaryBinding observed)
    {
        if(proof.PackageAccess!=2 || proof.Binding!=observed)
            throw WfpNative.Contract("CreatorLpacAccessCheckNotBoundToPrimaryToken");
    }

    private static AdmissionToken ReadTokenSnapshot(SafeProcessHandle process,bool observePackageAccess,bool captureUser,out SecurityIdentifier? user)
    {
        if(!OpenProcessToken(process,observePackageAccess?8u|2u:8u,out var token))throw Error("AtomicOpenCreatedToken");
        using(token)return ReadHeldTokenSnapshot(token,observePackageAccess,captureUser,out user);
    }

    private static AdmissionToken ReadHeldTokenSnapshot(SafeAccessTokenHandle token,bool observePackageAccess,bool captureUser,out SecurityIdentifier? user)
    {
        user=captureUser?Read(1,p=>{var sid=Marshal.ReadIntPtr(p);return sid==IntPtr.Zero?
            throw WfpNative.Contract("OfflineConsoleSuspendedTokenUserMissing"):new SecurityIdentifier(sid);}):null;
        var container=WindowsTokenInformation.Read(token,WindowsTokenInformation.Dword.IsAppContainer,"AtomicReadTokenInformation")!=0;
        var sid=Read(31,p=>{var s=Marshal.ReadIntPtr(p);return s==IntPtr.Zero?null:new SecurityIdentifier(s).Value;});
        // Read actual capability SIDs/attributes within the bounded native
        // buffer. Count alone must not become a future singleton-profile
        // identity check. Existing consumers still reject all nonzero sets.
        var capabilities=TokenCapabilitySnapshot.Read(token.DangerousGetHandle());
        var integrity=Read(25,p=>new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value);
        // Class46's zero-buffer query returned ERROR_INVALID_PARAMETER in
        // the preserved own-token qualification. Do not infer false or a
        // positive permit from that failure. Check the actual access
        // semantic using documented AccessCheck + a query-only duplicate.
        var packageAccess=observePackageAccess?ProbeApplicationPackageAccess(token):0u; // 0 = NOT_OBSERVED, never a grant.
        return new(container,sid,capabilities.Count,integrity,container && packageAccess==2,packageAccess){Capabilities=capabilities};
        T Read<T>(int type,Func<IntPtr,T> consume)
        {
            _=GetTokenInformation(token,type,IntPtr.Zero,0,out var size);
            if(size is <4 or >65536)throw Error("AtomicTokenBufferSize");var p=Marshal.AllocHGlobal(size);
            try{if(!GetTokenInformation(token,type,p,size,out _))throw Error("AtomicReadTokenInformation");return consume(p);}
            finally{Marshal.FreeHGlobal(p);}
        }
    }
    private static uint ProbeApplicationPackageAccess(SafeAccessTokenHandle token)
    {
        // Pattern also exercised by Chromium's CheckLpacToken. These two bits
        // have meaning ONLY for this synthetic descriptor; no host resource,
        // package profile or process is created or granted additional access.
        // The World ACE satisfies the ordinary-user half of the access check.
        var descriptor=new RawSecurityDescriptor("O:SYG:SYD:P(A;;0x3;;;WD)(A;;0x1;;;S-1-15-2-1)(A;;0x2;;;S-1-15-2-2)");
        var bytes=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(bytes,0);
        if(!DuplicateTokenEx(token,8,IntPtr.Zero,1,2,out var query))throw Error("DuplicateTokenForLpacAccessCheck");
        using(query)
        {
            var mapping=new GenericMapping();var privileges=new byte[64];uint size=(uint)privileges.Length;
            if(!AccessCheck(bytes,query,0x02000000,ref mapping,privileges,ref size,out var granted,out var allowed))throw Error("ReadLpacAccessCheck");
            if(size>privileges.Length || !allowed || granted is <1 or >3)throw WfpNative.Contract("LpacAccessCheckResultNotQualified");
            return granted;
        }
    }
    internal static EtwTokenAccessCheck ObserveTokenRegisterAccess(SafeProcessHandle process,string descriptor)
    {
        var security=new RawSecurityDescriptor(descriptor);var bytes=new byte[security.BinaryLength];security.GetBinaryForm(bytes,0);
        var hash=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));
        if(!OpenProcessToken(process,8|2,out var token))throw Error("EtwComparisonOpenHeldToolToken");
        using(token)
        {
            if(!DuplicateTokenEx(token,8,IntPtr.Zero,1,2,out var query))throw Error("EtwComparisonDuplicateQueryOnlyToken");
            using(query)
            {
                var mapping=new GenericMapping();var privileges=new byte[64];uint size=(uint)privileges.Length;
                var succeeded=AccessCheck(bytes,query,SessionEtwProviderAccess.RegisterRight,ref mapping,privileges,ref size,out var granted,out var allowed);
                var error=succeeded?(int?)null:Marshal.GetLastWin32Error();
                if(size>privileges.Length)return new(hash,false,null,null,error??122);
                return new(hash,succeeded,succeeded?allowed:null,succeeded?granted:null,error);
            }
        }
    }
}
