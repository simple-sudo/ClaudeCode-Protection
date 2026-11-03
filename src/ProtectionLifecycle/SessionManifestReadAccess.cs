using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed record ManifestReadIntent(int SchemaVersion,string InstallationId,string SessionId,string JobId,
    string Release,string ManifestSHA256,string PackageSid,string OriginalSecurity,string GrantedSecurity);

// Windows CreateProcess reads PreferExternalManifest using KEY_READ. LPAC
// denies the OS's AAP/registryRead ACEs. Authorize this ONE dependency for this
// package, without an inheritable ACE, a capability, or a caller-selected key.
// The original resource-session owner journals before mutation and restores
// only after the exact one-shot Job has a durable closed/zero receipt.
internal sealed class SessionManifestReadAccess : IDisposable
{
    internal const string KeyPath=@"SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide";
    private const string Prefix="manifest-access-intent-",ClosedPrefix="manifest-access-closed-";
    private const int ReadKey=0x20019;
    private readonly ProtectedState state;
    private readonly SafeRegistryHandle key;
    private readonly ManifestReadIntent intent;
    private readonly string intentHash;
    private bool restored,disposed;

    private SessionManifestReadAccess(ProtectedState state,SafeRegistryHandle key,ManifestReadIntent intent,string hash)
    {this.state=state;this.key=key;this.intent=intent;intentHash=hash;}

    internal static SessionManifestReadAccess Create(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,string sessionId)
    {
        state.AssertHeld();version.AssertHeld(state);AssertNoPending(state);
        if(!job.AtomicAdmissionReserved)throw WfpNative.Contract("ManifestAccessRequiresOriginalAtomicJob");
        using var package=new InstallationPackageSid(state);
        var key=OpenFixed();
        try
        {
            var original=ReadSecurity(key);var granted=AddReadAce(original,package.Value);
            var intent=new ManifestReadIntent(1,state.InstallationId,Identifiers.Hex32(sessionId),job.JobId,
                version.Package.Release,version.Package.ManifestHash,package.Value,original,granted);
            var hash=state.WriteNew(Prefix+sessionId+".json",JsonSerializer.SerializeToUtf8Bytes(intent));
            // Failures after this point intentionally leave the protected intent.
            // No rollback while a child could be alive, and no automatic retry.
            if(ReadSecurity(key)!=original)throw WfpNative.Contract("ManifestSecurityChangedBeforeGrant");
            WriteSecurity(key,granted);
            if(ReadSecurity(key)!=granted)throw WfpNative.Contract("ManifestReadGrantNotObserved");
            return new(state,key,intent,hash);
        }
        catch{key.Dispose();throw;}
    }

    internal void AssertHeld()
    {
        state.AssertHeld();
        if(disposed || restored || key.IsClosed || key.IsInvalid || ReadSecurity(key)!=intent.GrantedSecurity)
            throw WfpNative.Contract("ManifestReadResourceLeaseChanged");
    }

    internal void RestoreAfterClosedJob(JobSnapshot snapshot)
    {
        state.AssertHeld();
        if(disposed || restored || snapshot.JobId!=intent.JobId || !snapshot.ExpectedLimits || !snapshot.ObservedZero)
            throw WfpNative.Contract("ManifestRestoreNeedsExactClosedJobZero");
        Restore(state,key,intent,intentHash);restored=true;
    }

    public void Dispose()
    {
        if(disposed)return;disposed=true;key.Dispose();
        if(!restored)throw WfpNative.Contract("ManifestReadAccessRequiresExplicitRecovery");
    }

    // Pure descriptor policy, also used to validate every protected recovery
    // record. Existing permissions/order remain exact; only one non-inherited
    // KEY_READ ACE is added. Never grant registryRead or AAP/ARP access.
    internal static string AddReadAce(string original,string packageSid)
    {
        var sid=new SecurityIdentifier(packageSid);
        if(!sid.Value.StartsWith("S-1-15-2-",StringComparison.Ordinal) || sid.Value is "S-1-15-2-1" or "S-1-15-2-2")
            throw WfpNative.Contract("ManifestExactPackageSidRequired");
        var descriptor=ParseSecurity(original);
        if(descriptor.Owner?.Value is not ("S-1-5-18" or "S-1-5-32-544") || descriptor.DiscretionaryAcl is null ||
            (descriptor.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0)
            throw WfpNative.Contract("ManifestSystemKeySecurityUntrusted");
        var dacl=descriptor.DiscretionaryAcl;
        foreach(GenericAce ace in dacl)
        {
            if(ace is not CommonAce common || common.IsCallback || common.SecurityIdentifier==sid)
                throw WfpNative.Contract("ManifestExistingOrUnsupportedPackageAce");
            // An ordinary principal must not be able to replace the policy.
            if(common.AceQualifier==AceQualifier.AccessAllowed && (common.AceFlags&AceFlags.InheritOnly)==0 &&
                (common.AccessMask&0x500d0026)!=0 && common.SecurityIdentifier.Value is not ("S-1-5-18" or "S-1-5-32-544"))
                throw WfpNative.Contract("ManifestUntrustedKeyWriter");
        }
        var expanded=new RawAcl(dacl.Revision,dacl.Count+1);var index=0;var added=false;
        foreach(GenericAce ace in dacl)
        {
            if(!added && (ace.AceFlags&AceFlags.Inherited)!=0)
            {expanded.InsertAce(index++,new CommonAce(AceFlags.None,AceQualifier.AccessAllowed,ReadKey,sid,false,null));added=true;}
            expanded.InsertAce(index++,ace);
        }
        if(!added)expanded.InsertAce(index,new CommonAce(AceFlags.None,AceQualifier.AccessAllowed,ReadKey,sid,false,null));
        descriptor.DiscretionaryAcl=expanded;
        return Canonical(descriptor);
    }

    internal static string RestoreDecision(string observed,string original,string granted)
    {
        // Descriptor drift is never repaired/merged. Before/no-write and exact
        // own grant are the only recoverable states; no foreign ACE is erased.
        if(observed==original)return "ALREADY_ORIGINAL";
        if(observed==granted)return "REMOVE_EXACT_OWN_READ_GRANT";
        throw WfpNative.Contract("ManifestSecurityDriftRequiresHumanResolution");
    }

    private static RawSecurityDescriptor ParseSecurity(string value)
    {
        if(value.Length is <1 or >4096)throw WfpNative.Contract("ManifestSecurityBounds");
        var result=new RawSecurityDescriptor(value);
        if(Canonical(result)!=value)throw WfpNative.Contract("ManifestSecurityNotCanonical");
        return result;
    }
    private static string Canonical(RawSecurityDescriptor value)=>value.GetSddlForm(AccessControlSections.Owner|AccessControlSections.Access);

    private static IReadOnlyList<(ManifestReadIntent Intent,string Hash)> Pending(ProtectedState state)
    {
        state.AssertHeld();var results=new List<(ManifestReadIntent,string)>();
        using var package=new InstallationPackageSid(state);
        foreach(var leaf in state.ListLeaves(Prefix))
        {
            if(leaf.Length!=Prefix.Length+37 || !leaf.EndsWith(".json",StringComparison.Ordinal))throw WfpNative.Contract("ManifestIntentLeafRefused");
            var raw=state.Read(leaf,16384);using var doc=JsonDocument.Parse(raw.Bytes);
            StrictJson.Fields(doc.RootElement,"SchemaVersion","InstallationId","SessionId","JobId","Release","ManifestSHA256","PackageSid","OriginalSecurity","GrantedSecurity");
            var record=JsonSerializer.Deserialize<ManifestReadIntent>(raw.Bytes)??throw WfpNative.Contract("ManifestIntentMissing");
            if(record.SchemaVersion!=1 || record.InstallationId!=state.InstallationId || leaf!=Prefix+Identifiers.Hex32(record.SessionId)+".json" ||
                record.PackageSid!=package.Value || AddReadAce(record.OriginalSecurity,record.PackageSid)!=record.GrantedSecurity)
                throw WfpNative.Contract("ManifestIntentIdentityOrGrantMismatch");
            _=Identifiers.Hex32(record.JobId);_=Identifiers.Hex32(record.Release);_=Identifiers.Hash(record.ManifestSHA256);
            var closed=state.ReadOptional(ClosedPrefix+record.SessionId+".json");
            if(closed is not null)
            {
                using var completion=JsonDocument.Parse(closed.Bytes);var c=completion.RootElement;
                StrictJson.Fields(c,"SchemaVersion","InstallationId","SessionId","JobId","IntentSHA256","Status");
                if(c.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(c,"InstallationId")!=state.InstallationId ||
                    StrictJson.Text(c,"SessionId")!=record.SessionId || StrictJson.Text(c,"JobId")!=record.JobId ||
                    StrictJson.Text(c,"IntentSHA256")!=raw.SHA256 || StrictJson.Text(c,"Status")!="EXACT_ORIGINAL_DACL_OBSERVED_AFTER_CLOSED_JOB")
                    throw WfpNative.Contract("ManifestRestorationReceiptMismatch");
            }
            else results.Add((record,raw.SHA256));
        }
        if(results.Count>1)throw WfpNative.Contract("ManifestAccessOverlappingIntentsRefused");
        return results;
    }
    internal static void AssertNoPending(ProtectedState state)
    {if(Pending(state).Count!=0)throw WfpNative.Contract("ManifestReadAccessRequiresExplicitRecovery");}

    internal static (int ExitCode,string Report) Inspect(ProtectedState state)
    {
        var pending=Pending(state);
        return(pending.Count==0?0:2,JsonSerializer.Serialize(new {SchemaVersion=1,Status=pending.Count==0?"NO_PENDING_MANIFEST_READ_ACCESS":"MANIFEST_READ_RECOVERY_DECISION_REQUIRED",
            Pending=pending.Select(p=>new{p.Intent.SessionId,p.Intent.JobId}),FixedKey=KeyPath,StateModified=false,RegistryModified=false}));
    }
    internal static (int ExitCode,string Report) Recover(ProtectedState state)
    {
        state.AssertHeld();InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var job in OwnedJobIntent.ReadAll(state))
            if(AtomicJobCompletion.ReadClosed(state,job) is null)throw WfpNative.Contract("ManifestRecoveryNeedsAllAdmissionsClosed");
        var plans=FencePlan.ReadAll(state);if(plans.Count==0)throw WfpNative.Contract("ManifestRecoveryNeedsQuarantine");
        foreach(var plan in plans){using var fence=PersistentFence.OpenExisting(state,plan.Data.FenceId);if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("ManifestRecoveryNeedsQuarantine");}
        var pending=Pending(state);
        foreach(var item in pending){using var key=OpenFixed();Restore(state,key,item.Intent,item.Hash);}
        AssertNoPending(state);
        return(0,JsonSerializer.Serialize(new {SchemaVersion=1,Status="EXACT_MANIFEST_READ_ACCESS_RECOVERED",Count=pending.Count,FixedKey=KeyPath,
            JobCreated=false,ProcessCreated=false,ProfileStorageModified=false,NetworkPolicyModified=false}));
    }
    private static void Restore(ProtectedState state,SafeRegistryHandle key,ManifestReadIntent intent,string hash)
    {
        state.AssertHeld();
        var job=OwnedJobIntent.ReadAll(state).SingleOrDefault(j=>j.JobId==intent.JobId)??throw WfpNative.Contract("ManifestRestoreJobMissing");
        if(job.Release!=intent.Release || job.ManifestSHA256!=intent.ManifestSHA256 || AtomicJobCompletion.ReadClosed(state,job) is null)
            throw WfpNative.Contract("ManifestRestoreNeedsDurableClosedJobZero");
        if(RestoreDecision(ReadSecurity(key),intent.OriginalSecurity,intent.GrantedSecurity)=="REMOVE_EXACT_OWN_READ_GRANT")
            WriteSecurity(key,intent.OriginalSecurity);
        if(ReadSecurity(key)!=intent.OriginalSecurity)throw WfpNative.Contract("ManifestOriginalSecurityNotRestored");
        state.WriteNew(ClosedPrefix+intent.SessionId+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,
            intent.SessionId,intent.JobId,IntentSHA256=hash,Status="EXACT_ORIGINAL_DACL_OBSERVED_AFTER_CLOSED_JOB"}));
    }

    private static SafeRegistryHandle OpenFixed()=>OpenReviewedKey(KeyPath,true);
    // Shared object primitive for fixed registry resource owners; no Broker path input.
    internal static SafeRegistryHandle OpenReviewedKey(string keyPath,bool writeSecurity)
    {
        // Open the fixed 64-bit key object itself, not a registry symbolic-link
        // target. A link, deleted key, unsupported DACL or drift always refuses.
        var status=RegOpenKeyEx((IntPtr)unchecked((int)0x80000002),keyPath,8,ReadKey|(writeSecurity?0x40000:0)|0x100,out var handle);
        if(status!=0){handle?.Dispose();throw new Win32Exception(status);}
        try
        {
            uint type=0,size=0;status=RegQueryValueEx(handle,"SymbolicLinkValue",IntPtr.Zero,out type,IntPtr.Zero,ref size);
            if(status!=2)throw WfpNative.Contract("ManifestRegistryLinkOrUnexpectedValueRefused");
            _=ReadSecurity(handle);return handle;
        }
        catch{handle.Dispose();throw;}
    }
    internal static string ReadSecurity(SafeRegistryHandle handle)
    {
        // Read the registry OBJECT security, including its actual protection
        // control bits. The preserved RegGetKeySecurity observation on this
        // host synthesized an unprotected ACL and an extra owner ACE, unlike
        // the independent Windows security provider. Never normalize that
        // discrepancy away or use the synthesized ACL as restoration bytes.
        var status=GetSecurityInfo(handle,4,5,out _,out _,out var dacl,out _,out var descriptor); // SE_REGISTRY_KEY.
        if(status!=0)throw new Win32Exception(checked((int)status));
        try
        {
            if(descriptor==IntPtr.Zero || dacl==IntPtr.Zero)throw WfpNative.Contract("ManifestKeySecurityMissing");
            var size=GetSecurityDescriptorLength(descriptor);
            if(size is <20 or >4096)throw WfpNative.Contract("ManifestKeySecuritySizeRefused");
            var bytes=new byte[checked((int)size)];Marshal.Copy(descriptor,bytes,0,bytes.Length);
            return Canonical(new RawSecurityDescriptor(bytes,0));
        }
        finally{if(descriptor!=IntPtr.Zero)LocalFree(descriptor);}
    }
    internal static void WriteSecurity(SafeRegistryHandle handle,string value,bool protect=true)
    {
        ProtectedState.RequireAdministrator();
        var descriptor=ParseSecurity(value);var bytes=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(bytes,0);
        var status=RegSetKeySecurity(handle,protect?0x80000004u:4u,bytes);if(status!=0)throw new Win32Exception(status);
    }
    [DllImport("advapi32.dll",EntryPoint="RegOpenKeyExW",CharSet=CharSet.Unicode)] private static extern int RegOpenKeyEx(IntPtr root,string path,uint options,int access,out SafeRegistryHandle key);
    [DllImport("advapi32.dll",EntryPoint="RegQueryValueExW",CharSet=CharSet.Unicode)] private static extern int RegQueryValueEx(SafeRegistryHandle key,string name,IntPtr reserved,out uint type,IntPtr data,ref uint size);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityInfo(SafeRegistryHandle key,int type,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("advapi32.dll")] private static extern int RegSetKeySecurity(SafeRegistryHandle key,uint information,byte[] descriptor);
}
