using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Optional, reviewed candidate for the exact suspended gateway child.
// It does not authorize admission or alter the host object's ACLs.
internal sealed partial class AtomicChild
{
    internal string? DefaultDaclPreparationSHA256 {get;private set;}

    internal void PrepareOwnDefaultDaclBeforeResume()
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);
        if(sessionPreparation is null || !sessionPreparation.IsGatewayQualification ||
            !job.AtomicAdmissionReserved || ResumeAttempted || DefaultDaclPreparationSHA256 is not null)
            throw WfpNative.Contract("DefaultDaclRequiresOriginalSuspendedGatewayChild");
        sessionPreparation.AssertCurrent();AssertSuspendedIdentity();
        KernelJobSeal.SessionObjectDescriptor.AssertSeal(process);KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread);
        var before=ReadToken(process);
        if(!before.IsAppContainer || !before.LpacAccessCheckObserved || before.ApplicationPackageAccessMask!=2 ||
            before.PackageSid!=packageSid || before.CapabilityCount!=0 || before.IntegritySid!="S-1-16-4096")
            throw WfpNative.Contract("DefaultDaclRequiresExactLpacIdentity");
        if(!OpenProcessToken(process,0x88,out var token))throw Error("OpenOwnChildDefaultDaclToken");
        using(token)
        using(var human=WindowsIdentity.GetCurrent(TokenAccessLevels.Query))
        {
            var user=ReadDefaultDaclTokenData(token,1,(pointer,length)=>
            {
                if(length<IntPtr.Size)throw WfpNative.Contract("DefaultDaclUserPointerBounds");
                var sid=Marshal.ReadIntPtr(pointer);var offset=sid.ToInt64()-pointer.ToInt64();
                if(offset<0 || offset>length-8 || Marshal.ReadByte(sid)!=1 || Marshal.ReadByte(sid,1)>15 ||
                    8+4*Marshal.ReadByte(sid,1)>length-offset)throw WfpNative.Contract("DefaultDaclUserSidBounds");
                return new SecurityIdentifier(sid).Value;
            });
            if(user!=human.User?.Value)throw WfpNative.Contract("DefaultDaclActualOwnerUserMismatch");
            var original=ReadOwnDefaultDacl(token);
            var prepared=OwnedObjectDefaultDaclPolicy.AddExactOwnerAce(original,user,packageSid);
            var intent=state.WriteNew("atomic-default-dacl-intent-"+job.JobId+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,state.InstallationId,SessionId=sessionPreparation.SessionId,job.JobId,Pid,
                CreatedFileTime=ExpectedCreatedFileTime,version.Package.Release,version.Package.ManifestHash,UserSid=user,PackageSid=packageSid,
                OriginalAcl=Convert.ToBase64String(original),PreparedAcl=Convert.ToBase64String(prepared),
                Scope="ONE_HELD_SUSPENDED_LPAC_CHILD_FUTURE_OBJECTS_ONLY",HostObjectAclModified=false,PrivilegesOrCapabilitiesModified=false
            }));
            var acl=Marshal.AllocHGlobal(prepared.Length);var information=IntPtr.Zero;
            try
            {
                Marshal.Copy(prepared,0,acl,prepared.Length);information=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(information,acl);
                if(!SetTokenInformation(token,6,information,(uint)IntPtr.Size))throw Error("SetOwnSuspendedChildDefaultDacl");
            }
            finally{if(information!=IntPtr.Zero)Marshal.FreeHGlobal(information);Marshal.FreeHGlobal(acl);}
            if(!OwnedObjectDefaultDaclPolicy.IsExactOwnerAddition(ReadOwnDefaultDacl(token),original,user,packageSid) || ReadToken(process)!=before)
                throw WfpNative.Contract("DefaultDaclReadbackOrLpacIdentityChanged");
            AssertSuspendedIdentity();KernelJobSeal.SessionObjectDescriptor.AssertSeal(process);KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread);
            DefaultDaclPreparationSHA256=state.WriteNew("atomic-default-dacl-prepared-"+job.JobId+".json",JsonSerializer.SerializeToUtf8Bytes(new {
                SchemaVersion=1,state.InstallationId,SessionId=sessionPreparation.SessionId,job.JobId,Pid,IntentSHA256=intent,
                BeforeSHA256=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(original)),
                AfterSHA256=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(prepared)),
                LpacIdentityUnchanged=true,ExistingProcessAndThreadSealsUnchanged=true,FutureObjectsOnly=true
            }));
        }
    }
    private static byte[] ReadOwnDefaultDacl(SafeAccessTokenHandle token)=>ReadDefaultDaclTokenData(token,6,(pointer,length)=>
    {
        if(length<IntPtr.Size)throw WfpNative.Contract("DefaultDaclPointerBounds");
        var acl=Marshal.ReadIntPtr(pointer);var offset=acl.ToInt64()-pointer.ToInt64();
        if(offset<0 || offset>length-8)throw WfpNative.Contract("DefaultDaclBufferBounds");
        var size=unchecked((ushort)Marshal.ReadInt16(acl,2));
        if(size is <8 or >2048 || size>length-offset)throw WfpNative.Contract("DefaultDaclAclBounds");
        var bytes=new byte[size];Marshal.Copy(acl,bytes,0,size);return bytes;
    });
    private static T ReadDefaultDaclTokenData<T>(SafeAccessTokenHandle token,int kind,Func<IntPtr,int,T> consume)
    {
        if(GetTokenInformation(token,kind,IntPtr.Zero,0,out var length) || Marshal.GetLastWin32Error()!=122 || length is <4 or >65536)
            throw WfpNative.Contract("DefaultDaclTokenSizeUnavailable");
        var pointer=Marshal.AllocHGlobal(length);
        try
        {
            if(!GetTokenInformation(token,kind,pointer,length,out var used))throw Error("ReadOwnDefaultDaclTokenData");
            if(used<4 || used>length)throw WfpNative.Contract("DefaultDaclTokenReadBounds");
            return consume(pointer,used);
        }
        finally{Marshal.FreeHGlobal(pointer);}
    }
}
