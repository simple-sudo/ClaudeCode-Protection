using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

// Qualification-only member policy: a console host can be created by Windows
// after the canary's suspended admission. Reject arbitrary extra executables,
// foreign tokens, unstable snapshots and missing/uncertain member evidence.
// This is NOT a general Claude child-process admission policy.
internal static class WatchdogMemberPolicy
{
    internal static void Verify(JobSnapshot before,OwnedMemberInspection[] inspected,JobSnapshot after,
        uint primaryPid,long primaryCreatedFileTime,string packageSid,string primaryImage,string consoleHostImage,bool requireLpac=false)
        =>VerifyWithCapabilities(before,inspected,after,primaryPid,primaryCreatedFileTime,packageSid,primaryImage,consoleHostImage,requireLpac,LpacCapabilityProfile.None);
    internal static void VerifyWithCapabilities(JobSnapshot before,OwnedMemberInspection[] inspected,JobSnapshot after,
        uint primaryPid,long primaryCreatedFileTime,string packageSid,string primaryImage,string consoleHostImage,bool requireLpac,LpacCapabilityProfile capabilities)
    {
        ArgumentNullException.ThrowIfNull(capabilities);
        if(capabilities.IsInternetClientQualification && !requireLpac)throw WfpNative.Contract("NetworkQualificationRequiresLpacMemberChecks");
        if(before.JobId!=after.JobId || !before.ExpectedLimits || !after.ExpectedLimits ||
            before.ActiveBefore!=before.ActiveAfter || after.ActiveBefore!=after.ActiveAfter ||
            before.ActiveBefore is <1 or >2 || after.ActiveBefore!=before.ActiveBefore || primaryPid==0 || primaryCreatedFileTime<=0 ||
            before.ProcessIds.Length!=checked((int)before.ActiveBefore) || after.ProcessIds.Length!=checked((int)after.ActiveBefore) ||
            before.ProcessIds.Distinct().Count()!=before.ProcessIds.Length ||
            after.ProcessIds.Distinct().Count()!=after.ProcessIds.Length ||
            !before.ProcessIds.Contains(primaryPid) || inspected.Length!=before.ProcessIds.Length ||
            !before.ProcessIds.SequenceEqual(inspected.Select(m=>m.Pid)) ||
            !before.ProcessIds.OrderBy(p=>p).SequenceEqual(after.ProcessIds.OrderBy(p=>p)))
            throw WfpNative.Contract("WatchdogMemberSnapshotUnstableOrUnexpected");

        var expectedPrimary=WindowsPathSeal.Canonical(primaryImage);
        var expectedConsole=WindowsPathSeal.Canonical(consoleHostImage);
        foreach(var member in inspected)
        {
            var token=member.Token;
            if(!member.MembershipConfirmed || member.CreatedFileTime is null or <=0 ||
                (member.Pid==primaryPid && member.CreatedFileTime!=primaryCreatedFileTime) ||
                (member.Pid!=primaryPid && member.CreatedFileTime<primaryCreatedFileTime) ||
                member.Failures is null || member.Failures.Length!=0 ||
                token is null || !token.IsAppContainer || requireLpac && (!token.LpacAccessCheckObserved || token.ApplicationPackageAccessMask!=2) || token.PackageSid!=packageSid ||
                !capabilities.Matches(token.CapabilityCount,token.Capabilities) || token.IntegritySid!="S-1-16-4096" ||
                string.IsNullOrWhiteSpace(member.ImagePath))
                throw WfpNative.Contract("WatchdogMemberIdentityNotQualified");

            var observedImage=WindowsPathSeal.Canonical(member.ImagePath);
            var expectedImage=member.Pid==primaryPid?expectedPrimary:expectedConsole;
            if(!string.Equals(observedImage,expectedImage,StringComparison.OrdinalIgnoreCase))
                throw WfpNative.Contract("WatchdogUnexpectedMemberImage");
        }
    }
}
