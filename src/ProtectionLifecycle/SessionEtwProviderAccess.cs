using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32;

namespace ProtectionLifecycle;

internal sealed record EtwAccessIntent(int SchemaVersion,string InstallationId,string SessionId,string JobId,string Release,
    string ManifestSHA256,string PackageSid,string OriginalSecurity);
internal sealed record EtwAccessGrant(int SchemaVersion,string InstallationId,string SessionId,string IntentSHA256,
    string GrantedSecurity,string StoredValueSHA256);
internal sealed record EtwTokenAccessCheck(string DescriptorSHA256,bool ApiSucceeded,bool? AccessAllowed,uint? GrantedMask,int? ApiError);

// Legacy register-only trial journals still require exact inspection/recovery.
// That trial restored exactly but did not repair the installed EventRegister5.
// No new permission grant is exposed here. Never alter logging or AMSI.
internal static class SessionEtwProviderAccess
{
    internal const string ProviderId="f90714a8-5509-434a-bf6d-b1624c8a19a2";
    internal const uint RegisterRight=0x800;
    internal const string ObservedDefault="O:BAG:BAD:(A;;0x1800;;;WD)(A;;0x120fff;;;SY)(A;;0x120fff;;;LS)(A;;0x120fff;;;NS)(A;;0x120fff;;;BA)(A;;0xee5;;;LU)(A;;LC;;;MU)(A;;0x1800;;;AC)(A;;0x1800;;;S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)";
    private const string Prefix=ProtectedState.EtwAccessIntentPrefix,GrantPrefix="etw-access-grant-",ClosedPrefix="etw-access-closed-";

    internal static string AddRegisterAce(string original,string packageSid)
    {
        var sid=Package(packageSid);if(original!=ObservedDefault)throw WfpNative.Contract("EtwUnreviewedDefaultSecurity");
        var descriptor=new RawSecurityDescriptor(original);var acl=descriptor.DiscretionaryAcl??throw WfpNative.Contract("EtwDefaultDaclMissing");
        if(acl.Cast<GenericAce>().OfType<KnownAce>().Any(a=>a.SecurityIdentifier==sid))throw WfpNative.Contract("EtwPackageAlreadyPresent");
        var expanded=new RawAcl(acl.Revision,acl.Count+1);for(var index=0;index<acl.Count;index++)expanded.InsertAce(index,acl[index]);
        expanded.InsertAce(acl.Count,new CommonAce(AceFlags.None,AceQualifier.AccessAllowed,(int)RegisterRight,sid,false,null));
        descriptor.DiscretionaryAcl=expanded;return Canonical(descriptor);
    }
    internal static bool IsExactGrant(string observed,string original,string packageSid)
    {
        _=AddRegisterAce(original,packageSid);var sid=Package(packageSid);
        if(observed.Length is <1 or >4096)throw WfpNative.Contract("EtwSecurityBounds");
        var descriptor=new RawSecurityDescriptor(observed);var acl=descriptor.DiscretionaryAcl;
        if(acl is null)return false;var matches=0;var remaining=new RawAcl(acl.Revision,acl.Count);var index=0;
        foreach(GenericAce ace in acl)
        {
            if(ace is KnownAce known && known.SecurityIdentifier==sid)
            {
                if(ace is not CommonAce common || common.IsCallback || common.AceQualifier!=AceQualifier.AccessAllowed ||
                    common.AceFlags!=AceFlags.None || common.AccessMask!=RegisterRight)return false;
                matches++;
            }
            else remaining.InsertAce(index++,ace);
        }
        descriptor.DiscretionaryAcl=remaining;return matches==1 && Canonical(descriptor)==original;
    }
    internal static string RestoreDecision(string observed,string? storedHash,string original,string packageSid,EtwAccessGrant? granted)
    {
        _=AddRegisterAce(original,packageSid);
        if(observed==original && storedHash is null)return "ALREADY_ORIGINAL_DEFAULT";
        if(storedHash is not null && IsExactGrant(observed,original,packageSid) &&
            (granted is null || granted.GrantedSecurity==observed && granted.StoredValueSHA256==storedHash))return "REMOVE_ONLY_OWN_NEW_OVERRIDE";
        throw WfpNative.Contract("EtwSecurityDriftRequiresHumanResolution");
    }
    private static SecurityIdentifier Package(string value)
    {
        var sid=new SecurityIdentifier(value);
        if(!sid.Value.StartsWith("S-1-15-2-",StringComparison.Ordinal) || sid.Value is "S-1-15-2-1" or "S-1-15-2-2")
            throw WfpNative.Contract("EtwExactPackageSidRequired");
        return sid;
    }
    private static string Canonical(RawSecurityDescriptor descriptor)=>descriptor.GetSddlForm(AccessControlSections.All);
    private static IReadOnlyList<(EtwAccessIntent Intent,string Hash)> Pending(ProtectedState state)
    {
        state.AssertHeld();using var package=new InstallationPackageSid(state);var result=new List<(EtwAccessIntent,string)>();
        foreach(var leaf in state.ListLeaves(Prefix))
        {
            var raw=state.Read(leaf,16384);using var doc=JsonDocument.Parse(raw.Bytes);
            StrictJson.Fields(doc.RootElement,"SchemaVersion","InstallationId","SessionId","JobId","Release","ManifestSHA256","PackageSid","OriginalSecurity");
            var value=JsonSerializer.Deserialize<EtwAccessIntent>(raw.Bytes)??throw WfpNative.Contract("EtwAccessIntentMissing");
            if(value.SchemaVersion!=1 || value.InstallationId!=state.InstallationId || leaf!=Prefix+Identifiers.Hex32(value.SessionId)+".json" || value.PackageSid!=package.Value)
                throw WfpNative.Contract("EtwAccessIntentOwnershipDiffers");
            _=Identifiers.Hex32(value.JobId);_=Identifiers.Hex32(value.Release);_=Identifiers.Hash(value.ManifestSHA256);_=AddRegisterAce(value.OriginalSecurity,value.PackageSid);
            _=ReadGrant(state,value,raw.SHA256);
            var closed=state.ReadOptional(ClosedPrefix+value.SessionId+".json");
            if(closed is null){result.Add((value,raw.SHA256));continue;}
            using var completion=JsonDocument.Parse(closed.Bytes);var c=completion.RootElement;
            StrictJson.Fields(c,"SchemaVersion","InstallationId","SessionId","JobId","IntentSHA256","Status");
            if(c.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(c,"InstallationId")!=state.InstallationId || StrictJson.Text(c,"SessionId")!=value.SessionId ||
                StrictJson.Text(c,"JobId")!=value.JobId || StrictJson.Text(c,"IntentSHA256")!=raw.SHA256 || StrictJson.Text(c,"Status")!="EXACT_ORIGINAL_DEFAULT_AND_VALUE_ABSENCE_AFTER_CLOSED_JOB")
                throw WfpNative.Contract("EtwAccessClosedReceiptDiffers");
        }
        return result;
    }
    private static EtwAccessGrant? ReadGrant(ProtectedState state,EtwAccessIntent intent,string hash)
    {
        var raw=state.ReadOptional(GrantPrefix+intent.SessionId+".json");if(raw is null)return null;
        using var doc=JsonDocument.Parse(raw.Bytes);StrictJson.Fields(doc.RootElement,"SchemaVersion","InstallationId","SessionId","IntentSHA256","GrantedSecurity","StoredValueSHA256");
        var grant=JsonSerializer.Deserialize<EtwAccessGrant>(raw.Bytes)??throw WfpNative.Contract("EtwAccessGrantMissing");
        if(grant.SchemaVersion!=1 || grant.InstallationId!=state.InstallationId || grant.SessionId!=intent.SessionId || grant.IntentSHA256!=hash ||
            !IsExactGrant(grant.GrantedSecurity,intent.OriginalSecurity,intent.PackageSid))throw WfpNative.Contract("EtwAccessGrantBindingDiffers");
        _=Identifiers.Hash(grant.StoredValueSHA256);return grant;
    }
    internal static void AssertNoPending(ProtectedState state)
    {if(Pending(state).Count!=0)throw WfpNative.Contract("EtwAccessRequiresExplicitRecovery");}
    internal static (int ExitCode,string Report) Inspect(ProtectedState state)
    {
        var pending=Pending(state);var security=ReadSecurity();var stored=StoredValueHash();
        return(pending.Count==0?0:2,JsonSerializer.Serialize(new{SchemaVersion=1,Status=pending.Count==0?"NO_PENDING_ETW_PROVIDER_ACCESS":"ETW_PROVIDER_RECOVERY_DECISION_REQUIRED",
            ProviderId,EffectiveSecurity=security,ExplicitValuePresent=stored is not null,StoredValueSHA256=stored,Pending=pending.Select(p=>new{p.Intent.SessionId,p.Intent.JobId}),
            StateModified=false,EtwModified=false,EventDataRead=false}));
    }
    internal static (int ExitCode,string Report) Recover(ProtectedState state)
    {
        state.AssertHeld();InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var job in OwnedJobIntent.ReadAll(state))if(!SessionZeroCreatorRecovery.IsAdmissionResolved(state,job))throw WfpNative.Contract("EtwRecoveryNeedsAllAdmissionsClosed");
        var plans=FencePlan.ReadAll(state);if(plans.Count==0)throw WfpNative.Contract("EtwRecoveryNeedsQuarantine");
        foreach(var plan in plans){using var fence=PersistentFence.OpenExisting(state,plan.Data.FenceId);if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("EtwRecoveryNeedsQuarantine");}
        var pending=Pending(state);foreach(var item in pending)Restore(state,item.Intent,item.Hash);AssertNoPending(state);
        return(0,JsonSerializer.Serialize(new{SchemaVersion=1,Status="EXACT_ETW_PROVIDER_ACCESS_RECOVERED",Count=pending.Count,ProviderId,
            JobCreated=false,ProcessCreated=false,ProfileStorageModified=false,NetworkPolicyModified=false}));
    }
    private static void Restore(ProtectedState state,EtwAccessIntent intent,string hash)
    {
        state.AssertHeld();var job=OwnedJobIntent.ReadAll(state).SingleOrDefault(j=>j.JobId==intent.JobId)??throw WfpNative.Contract("EtwRestoreJobMissing");
        if(job.Release!=intent.Release || job.ManifestSHA256!=intent.ManifestSHA256 || AtomicJobCompletion.ReadClosed(state,job) is null)
            throw WfpNative.Contract("EtwRestoreNeedsDurableClosedJobZero");
        var granted=ReadGrant(state,intent,hash);var security=ReadSecurity();var stored=StoredValueHash();
        if(RestoreDecision(security,stored,intent.OriginalSecurity,intent.PackageSid,granted)=="REMOVE_ONLY_OWN_NEW_OVERRIDE")
        {
            if(ReadSecurity()!=security || StoredValueHash()!=stored)throw WfpNative.Contract("EtwSecurityChangedBeforeRestore");
            var provider=new Guid(ProviderId);var status=EventAccessRemove(ref provider);if(status!=0)throw Native("RemoveOnlyOwnedEtwOverride",status);
        }
        if(ReadSecurity()!=intent.OriginalSecurity || StoredValueHash() is not null)throw WfpNative.Contract("EtwOriginalDefaultOrAbsenceNotRestored");
        state.WriteNew(ClosedPrefix+intent.SessionId+".json",JsonSerializer.SerializeToUtf8Bytes(new{SchemaVersion=1,state.InstallationId,intent.SessionId,
            intent.JobId,IntentSHA256=hash,Status="EXACT_ORIGINAL_DEFAULT_AND_VALUE_ABSENCE_AFTER_CLOSED_JOB"}));
    }
    internal static uint RestrictedQueryCode(){var provider=new Guid(ProviderId);uint size=0;return EventAccessQuery(ref provider,null,ref size);}
    internal static (string Readback,string InMemoryPackageAce) RegistrationCheckDescriptors(string packageSid)
    {
        // Readback is a WMI/registry observation, NOT the live ETW entry's SD.
        // The second descriptor exists only in managed memory; never install it.
        var security=ReadSecurity();
        if(security!=ObservedDefault || StoredValueHash() is not null)throw WfpNative.Contract("EtwTokenComparisonRequiresObservedDefaultAndAbsence");
        return(security,AddRegisterAce(security,packageSid));
    }
    private static string ReadSecurity()
    {
        var provider=new Guid(ProviderId);uint size=0;var status=EventAccessQuery(ref provider,null,ref size);
        if(status is not (0 or 122 or 234) || size is <20 or >65536)throw Native("SizeFixedEtwSecurity",status);
        var bytes=new byte[size];status=EventAccessQuery(ref provider,bytes,ref size);
        if(status!=0 || size>bytes.Length)throw Native("ReadFixedEtwSecurity",status);
        return Canonical(new RawSecurityDescriptor(bytes,0));
    }
    private static string? StoredValueHash()
    {
        using var root=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64);
        using var key=root.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\WMI\Security",false)
            ??throw WfpNative.Contract("EtwSecurityStorageParentMissing");
        // No enumeration of other providers. Refuse any existing representation
        // of THIS GUID, rather than assuming one registry name convention.
        string? observed=null;
        foreach(var format in new[]{"B","D","N","P"})
        {
            var name=new Guid(ProviderId).ToString(format);
            var value=key.GetValue(name,null,RegistryValueOptions.DoNotExpandEnvironmentNames);if(value is null)continue;
            if(observed is not null || value is not byte[] bytes || bytes.Length is <20 or >65536 || key.GetValueKind(name)!=RegistryValueKind.Binary)
                throw WfpNative.Contract("EtwStoredSecurityValueShapeUntrusted");
            var prefix=System.Text.Encoding.ASCII.GetBytes(name+"\0");
            observed=Convert.ToHexString(SHA256.HashData(prefix.Concat(bytes).ToArray()));
        }
        return observed;
    }
    private static Win32Exception Native(string stage,uint code){var error=new Win32Exception(unchecked((int)code));error.Data["Stage"]=stage;return error;}
    [DllImport("advapi32.dll",ExactSpelling=true)] private static extern uint EventAccessQuery(ref Guid provider,[Out] byte[]? buffer,ref uint length);
    [DllImport("advapi32.dll",ExactSpelling=true)] private static extern uint EventAccessRemove(ref Guid provider);
}
