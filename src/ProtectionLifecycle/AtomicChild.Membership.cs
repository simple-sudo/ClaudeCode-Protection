using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Exact process/Job membership observations. Temporary process handles are
// held through the complete observation callback and closed by this method.
internal sealed partial class AtomicChild
{
    internal static void AssertIndependentSessionUser(SecurityIdentifier? actual,SecurityIdentifier? host)
    {
        // A different account on the same host can still disclose its machine
        // account domain. This creation route currently qualifies LocalService only.
        if(actual is null || host is null || actual.Equals(host) || !actual.IsWellKnown(WellKnownSidType.LocalServiceSid))
            throw WfpNative.Contract("FormalSessionRequiresIndependentLocalServiceUser");
    }
    internal static void AssertIndependentOfflineHandoffToken(SafeProcessHandle process,SessionZeroCreatorChannel.TokenProof proof,string expectedPackageSid)
    {
        var token=ReadIndependentOfflineToken(process,proof,out var actualUser);
        using var host=WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        AssertIndependentSessionUser(actualUser,host.User);
        if(!token.IsAppContainer || !token.LpacAccessCheckObserved || token.ApplicationPackageAccessMask!=2 ||
            token.PackageSid!=expectedPackageSid || token.IntegritySid!="S-1-16-4096" || !LpacCapabilityProfile.None.Matches(token.CapabilityCount,token.Capabilities))
            throw WfpNative.Contract("IndependentOfflineHandoffTokenMismatch");
        AssertNoChildCreation(process);
    }
    internal static SafeProcessHandle HoldSessionPeer(OwnedKernelJob job,string sid,int sourcePort,LpacCapabilityProfile? capabilities=null)
    {
        var process=OpenProcess(0x101000,false,ProxyChannelLease.SessionPeerOwner(sourcePort));
        try
        {
            if(process.IsInvalid)throw Error("OpenSessionGatewayPeer");
            AssertSessionPeer(job,process,sid,sourcePort,capabilities);return process;
        }
        catch{process.Dispose();throw;}
    }
    internal static void AssertSessionPeer(OwnedKernelJob job,SafeProcessHandle process,string sid,int sourcePort,LpacCapabilityProfile? capabilities=null)
    {
        if(process.IsClosed || process.IsInvalid || WaitForSingleObject(process,0)!=0x102 || !job.ContainsProcess(process) ||
            ProxyChannelLease.SessionPeerOwner(sourcePort)!=GetProcessId(process))throw WfpNative.Contract("SessionGatewayPeerJobOrLifetimeMismatch");
        var token=ReadToken(process);
        if(!token.IsAppContainer || !token.LpacAccessCheckObserved || token.PackageSid!=sid || !(capabilities??LpacCapabilityProfile.None).Matches(token.CapabilityCount,token.Capabilities) || token.IntegritySid!="S-1-16-4096")
            throw WfpNative.Contract("SessionGatewayPeerTokenMismatch");
    }
    internal static (uint Pid,long CreatedFileTime) SessionPeerIdentity(SafeProcessHandle process)
    {
        var pid=GetProcessId(process);
        if(pid==0 || !GetProcessTimes(process,out var created,out _,out _,out _))throw Error("SessionGatewayPeerIdentity");
        return(pid,created);
    }
    internal static void InspectMembers(OwnedKernelJob job,JobSnapshot snapshot,Action<OwnedMemberInspection[]> whileHeld)
    {
        if(snapshot.JobId!=job.JobId || snapshot.ProcessIds.Length>64)throw WfpNative.Contract("BoundedExactJobInspectionRequired");
        // Keep every successfully opened process object alive through the
        // caller's second Job snapshot and decision. A recycled numeric PID
        // must not stand in for an inspected member between those operations.
        var held=new List<SafeProcessHandle>();
        try
        {
        var members=snapshot.ProcessIds.Select(pid=>
        {
            long? created=null;string? image=null;AdmissionToken? token=null;bool member=false;Exception? failure=null;
            try
            {
                var process=OpenProcess(0x101000,false,pid);held.Add(process);if(process.IsInvalid)throw Error("InspectOwnedMemberOpen");
                member=job.ContainsProcess(process);if(!member)throw WfpNative.Contract("InspectedProcessNotInExactJob");
                if(WaitForSingleObject(process,0)!=0x102)throw WfpNative.Contract("InspectedMemberNotRunning");
                if(!GetProcessTimes(process,out var at,out _,out _,out _))throw Error("InspectOwnedMemberCreation");created=at;
                var path=new StringBuilder(32768);uint length=(uint)path.Capacity;if(!QueryFullProcessImageName(process,0,path,ref length))throw Error("InspectOwnedMemberImage");image=path.ToString();
                token=ReadToken(process);
            }
            catch(Exception ex){failure=ex;}
            return new OwnedMemberInspection(pid,member,created,image,token,failure is null?Array.Empty<WfpErrorEvidence>():WfpNative.Describe(failure));
        }).ToArray();
        whileHeld(members);
        }
        finally{foreach(var handle in held)handle.Dispose();}
    }
}
