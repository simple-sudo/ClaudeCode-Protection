using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
namespace ProtectionLifecycle;
internal sealed record TimeZoneReadTarget(string Role,string OriginalSecurity,string GrantedSecurity);
internal sealed record TimeZoneReadIntent(int SchemaVersion,string InstallationId,string SessionId,string JobId,string Release,
    string ManifestSHA256,string PackageSid,string TimeZoneId,TimeZoneReadTarget[] Targets);

// Specialized owner in the existing registry-resource lease chain. No caller
// path, value writer, capability, parent-hive grant or inheritable ACE.
internal sealed class SessionTimeZoneReadAccess : IDisposable
{
    internal const string Hive=@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones";
    private const string Prefix="timezone-access-intent-",ClosedPrefix="timezone-access-closed-";
    private const int ReadKey=0x20019,MaxSecurityCharacters=4096,MaxIntentBytes=16384;
    private static readonly string Installer=((SecurityIdentifier)new NTAccount("NT SERVICE","TrustedInstaller").Translate(typeof(SecurityIdentifier))).Value;
    private readonly ProtectedState state;
    private readonly TimeZoneReadIntent intent;
    private readonly SafeRegistryHandle[] keys;
    internal string IntentSHA256 {get;}
    private bool applied,restored,disposed;
    private SessionTimeZoneReadAccess(ProtectedState state,TimeZoneReadIntent intent,SafeRegistryHandle[] keys,string hash)
    {this.state=state;this.intent=intent;this.keys=keys;IntentSHA256=hash;}
    internal int KeyCount=>keys.Length;
    internal bool Restored=>restored;
    internal static string PathFor(string zone,string role)
    {
        if(zone.Length is <1 or >96 || zone.Trim()!=zone || zone.Contains("..") ||
            zone.Any(c=>!char.IsAsciiLetterOrDigit(c) && !" .-_()+".Contains(c)))throw WfpNative.Contract("TimeZoneDefinitionNameRefused");
        return Hive+"\\"+zone+(role switch {"ZONE_DEFINITION"=>"","DYNAMIC_DST"=>@"\Dynamic DST",
            _=>throw WfpNative.Contract("TimeZoneDefinitionRoleRefused")});
    }
    private static string Canonical(RawSecurityDescriptor sd)=>sd.GetSddlForm(AccessControlSections.Owner|AccessControlSections.Access);
    internal static string AddReadAce(string original,string packageSid)
    {
        if(original.Length is <1 or >MaxSecurityCharacters)throw WfpNative.Contract("TimeZoneSecurityBounds");
        var sid=new SecurityIdentifier(packageSid);
        if(!sid.Value.StartsWith("S-1-15-2-",StringComparison.Ordinal) || sid.Value is "S-1-15-2-1" or "S-1-15-2-2")
            throw WfpNative.Contract("TimeZoneExactPackageRequired");
        var sd=new RawSecurityDescriptor(original);var dacl=sd.DiscretionaryAcl;
        if(Canonical(sd)!=original || dacl is null || sd.Owner is null ||
            (sd.Owner.Value is not ("S-1-5-18" or "S-1-5-32-544") && sd.Owner.Value!=Installer))
            throw WfpNative.Contract("TimeZoneSystemOwnerOrDescriptorRefused");
        foreach(GenericAce ace in dacl)
        {
            if(ace is not CommonAce c || c.IsCallback || c.SecurityIdentifier==sid)throw WfpNative.Contract("TimeZoneExistingOrUnsupportedPackageAce");
            if(c.AceQualifier==AceQualifier.AccessAllowed && (c.AceFlags&AceFlags.InheritOnly)==0 &&
                (c.AccessMask&0x500d0026)!=0 && c.SecurityIdentifier.Value is not ("S-1-5-18" or "S-1-5-32-544") &&
                c.SecurityIdentifier.Value!=Installer)throw WfpNative.Contract("TimeZoneUntrustedWriter");
        }
        var next=new RawAcl(dacl.Revision,dacl.Count+1);var index=0;var added=false;
        foreach(GenericAce ace in dacl)
        {
            if(!added && (ace.AceFlags&AceFlags.Inherited)!=0)
            {next.InsertAce(index++,new CommonAce(AceFlags.None,AceQualifier.AccessAllowed,ReadKey,sid,false,null));added=true;}
            next.InsertAce(index++,ace);
        }
        if(!added)next.InsertAce(index,new CommonAce(AceFlags.None,AceQualifier.AccessAllowed,ReadKey,sid,false,null));
        sd.DiscretionaryAcl=next;return Canonical(sd);
    }
    private static SafeRegistryHandle Open(string zone,string role,bool write)
    {
        var path=PathFor(zone,role);var key=SessionManifestReadAccess.OpenReviewedKey(path,write);
        try{AssertName(key,path);return key;}catch{key.Dispose();throw;}
    }
    private static void AssertName(SafeRegistryHandle key,string path)
    {
        uint length=0;var status=NtQueryKey(key,3,IntPtr.Zero,0,out length);
        if(status!=unchecked((int)0xC0000023) && status!=unchecked((int)0x80000005))throw WfpNative.Contract("TimeZoneRegistryIdentitySizeRefused");
        if(length is <6 or >2048)throw WfpNative.Contract("TimeZoneRegistryIdentityBounds");
        var data=Marshal.AllocHGlobal(checked((int)length));
        try
        {
            if(NtQueryKey(key,3,data,length,out var used)!=0 || used>length)throw WfpNative.Contract("TimeZoneRegistryIdentityUnavailable");
            var bytes=Marshal.ReadInt32(data);
            if(bytes<2 || (bytes&1)!=0 || bytes>length-4)throw WfpNative.Contract("TimeZoneRegistryIdentityShape");
            if(!string.Equals(Marshal.PtrToStringUni(data+4,bytes/2),@"\REGISTRY\MACHINE\"+path,StringComparison.OrdinalIgnoreCase))
                throw WfpNative.Contract("TimeZoneRegistryIdentityChanged");
        }
        finally{Marshal.FreeHGlobal(data);}
    }
    internal static string InspectCurrentMetadata()
    {
        var zone=TimeZoneInfo.Local.Id;var rows=new List<object>();
        foreach(var role in new[]{"ZONE_DEFINITION","DYNAMIC_DST"})
        {
            try
            {
                using var key=Open(zone,role,false);var original=SessionManifestReadAccess.ReadSecurity(key);
                _=AddReadAce(original,"S-1-15-2-1-2-3-4-5-6-7");
                rows.Add(new{Role=role,SecuritySHA256=Digest(original),Present=true});
            }
            catch(Win32Exception ex)when(role=="DYNAMIC_DST" && ex.NativeErrorCode==2)
            {rows.Add(new{Role=role,SecuritySHA256=(string?)null,Present=false});}
        }
        return JsonSerializer.Serialize(new{Scope="PUBLIC_CURRENT_TIMEZONE_KEY_METADATA_ONLY",TimeZoneId=zone,Keys=rows,
            RegistryModified=false,StateRead=false,StateModified=false});
    }
    internal static SessionTimeZoneReadAccess Prepare(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,string sessionId)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);AssertNoPending(state);
        if(!job.AtomicAdmissionReserved)throw WfpNative.Contract("TimeZoneGrantRequiresOriginalAtomicJob");
        using var package=new InstallationPackageSid(state);var zone=TimeZoneInfo.Local.Id;
        var handles=new List<SafeRegistryHandle>();var targets=new List<TimeZoneReadTarget>();
        try
        {
            foreach(var role in new[]{"ZONE_DEFINITION","DYNAMIC_DST"})
            {
                SafeRegistryHandle key;
                try{key=Open(zone,role,true);}catch(Win32Exception ex)when(role=="DYNAMIC_DST" && ex.NativeErrorCode==2){continue;}
                handles.Add(key);var original=SessionManifestReadAccess.ReadSecurity(key);
                var granted=AddReadAce(original,package.Value);
                if(granted.Length>MaxSecurityCharacters ||
                    new RawSecurityDescriptor(granted).BinaryLength>SessionManifestReadAccess.MaxSecurityDescriptorBytes)
                    throw WfpNative.Contract("TimeZoneGrantedSecurityBounds");
                targets.Add(new(role,original,granted));
            }
            var record=new TimeZoneReadIntent(1,state.InstallationId,Identifiers.Hex32(sessionId),job.JobId,version.Package.Release,
                version.Package.ManifestHash,package.Value,zone,targets.ToArray());
            var bytes=JsonSerializer.SerializeToUtf8Bytes(record);
            // Never persist an intent that the health and recovery paths cannot read.
            if(bytes.Length>MaxIntentBytes)throw WfpNative.Contract("TimeZoneIntentBounds");
            var hash=state.WriteNew(Prefix+sessionId+".json",bytes);
            return new(state,record,handles.ToArray(),hash);
        }
        catch{foreach(var key in handles)key.Dispose();throw;}
    }
    internal void Apply()
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();
        if(disposed || applied || restored)throw WfpNative.Contract("TimeZoneGrantAlreadyConsumed");
        for(var i=0;i<keys.Length;i++)if(Read(i)!=intent.Targets[i].OriginalSecurity)throw WfpNative.Contract("TimeZoneSecurityChangedBeforeGrant");
        // Owner already holds this object. Partial application is recoverable
        // only after the original Job has a durable closed/zero receipt.
        for(var i=0;i<keys.Length;i++)
        {
            // A prior key write can take time. Recheck this key immediately
            // before its own write so detected drift is never overwritten.
            if(Read(i)!=intent.Targets[i].OriginalSecurity)throw WfpNative.Contract("TimeZoneSecurityChangedBeforeGrant");
            Write(keys[i],intent.Targets[i].GrantedSecurity);
            if(Read(i)!=intent.Targets[i].GrantedSecurity)throw WfpNative.Contract("TimeZoneGrantNotObserved");
        }
        applied=true;
    }
    private string Read(int i){AssertName(keys[i],PathFor(intent.TimeZoneId,intent.Targets[i].Role));return SessionManifestReadAccess.ReadSecurity(keys[i]);}
    private static void Write(SafeRegistryHandle key,string value)
    {SessionManifestReadAccess.WriteSecurity(key,value,(new RawSecurityDescriptor(value).ControlFlags&ControlFlags.DiscretionaryAclProtected)!=0);}
    internal void AssertHeld()
    {
        state.AssertHeld();
        if(disposed || restored || !applied || state.Read(Prefix+intent.SessionId+".json",MaxIntentBytes).SHA256!=IntentSHA256)throw WfpNative.Contract("TimeZoneLeaseNotCurrent");
        for(var i=0;i<keys.Length;i++)if(Read(i)!=intent.Targets[i].GrantedSecurity)throw WfpNative.Contract("TimeZoneLeaseSecurityDrift");
    }
    internal void RestoreAfterClosedJob(JobSnapshot snapshot)
    {
        if(disposed || restored || snapshot.JobId!=intent.JobId || !snapshot.ExpectedLimits || !snapshot.ObservedZero)throw WfpNative.Contract("TimeZoneRestoreRequiresOriginalJobZero");
        Restore(state,intent,IntentSHA256,keys);restored=true;
    }
    private static void Restore(ProtectedState state,TimeZoneReadIntent r,string hash,SafeRegistryHandle[] keys)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();
        var job=OwnedJobIntent.ReadAll(state).SingleOrDefault(j=>j.JobId==r.JobId)??throw WfpNative.Contract("TimeZoneOriginalJobMissing");
        if(job.Release!=r.Release || job.ManifestSHA256!=r.ManifestSHA256 || AtomicJobCompletion.ReadClosed(state,job) is null)
            throw WfpNative.Contract("TimeZoneRestoreRequiresDurableClosedJob");
        string ReadTarget(int i)
        {
            AssertName(keys[i],PathFor(r.TimeZoneId,r.Targets[i].Role));
            return SessionManifestReadAccess.ReadSecurity(keys[i]);
        }
        for(var i=0;i<keys.Length;i++)
            _=SessionManifestReadAccess.RestoreDecision(ReadTarget(i),r.Targets[i].OriginalSecurity,r.Targets[i].GrantedSecurity);
        for(var i=0;i<keys.Length;i++)
        {
            var t=r.Targets[i];
            if(SessionManifestReadAccess.RestoreDecision(ReadTarget(i),t.OriginalSecurity,t.GrantedSecurity)=="REMOVE_EXACT_OWN_READ_GRANT")
                Write(keys[i],t.OriginalSecurity);
        }
        // Read back every key after the last write before sealing the receipt.
        for(var i=0;i<keys.Length;i++)
            if(ReadTarget(i)!=r.Targets[i].OriginalSecurity)throw WfpNative.Contract("TimeZoneOriginalSecurityNotRestored");
        state.WriteNew(ClosedPrefix+r.SessionId+".json",JsonSerializer.SerializeToUtf8Bytes(new{SchemaVersion=1,state.InstallationId,r.SessionId,r.JobId,
            IntentSHA256=hash,Status="EXACT_ORIGINAL_TIMEZONE_DACLS_AFTER_CLOSED_JOB"}));
    }
    private static IReadOnlyList<(TimeZoneReadIntent Record,string Hash)> Pending(ProtectedState state)
    {
        state.AssertHeld();using var package=new InstallationPackageSid(state);var pending=new List<(TimeZoneReadIntent,string)>();
        foreach(var leaf in state.ListLeaves(Prefix))
        {
            if(leaf.Length!=Prefix.Length+37 || !leaf.EndsWith(".json",StringComparison.Ordinal))throw WfpNative.Contract("TimeZoneIntentLeafRefused");
            var raw=state.Read(leaf,MaxIntentBytes);using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=5});
            StrictJson.Fields(doc.RootElement,"SchemaVersion","InstallationId","SessionId","JobId","Release","ManifestSHA256","PackageSid","TimeZoneId","Targets");
            foreach(var t in doc.RootElement.GetProperty("Targets").EnumerateArray())StrictJson.Fields(t,"Role","OriginalSecurity","GrantedSecurity");
            var r=JsonSerializer.Deserialize<TimeZoneReadIntent>(raw.Bytes)??throw WfpNative.Contract("TimeZoneIntentMissing");
            if(r.SchemaVersion!=1 || r.InstallationId!=state.InstallationId || r.PackageSid!=package.Value || leaf!=Prefix+Identifiers.Hex32(r.SessionId)+".json" ||
                r.Targets is null || r.Targets.Length is <1 or >2 || r.Targets[0].Role!="ZONE_DEFINITION" || r.Targets.Length==2 && r.Targets[1].Role!="DYNAMIC_DST")
                throw WfpNative.Contract("TimeZoneIntentScopeMismatch");
            _=Identifiers.Hex32(r.JobId);_=Identifiers.Hex32(r.Release);_=Identifiers.Hash(r.ManifestSHA256);
            foreach(var t in r.Targets){_=PathFor(r.TimeZoneId,t.Role);if(AddReadAce(t.OriginalSecurity,r.PackageSid)!=t.GrantedSecurity)throw WfpNative.Contract("TimeZoneIntentGrantMismatch");}
            var closed=state.ReadOptional(ClosedPrefix+r.SessionId+".json");
            if(closed is null)pending.Add((r,raw.SHA256));
            else
            {
                using var c=JsonDocument.Parse(closed.Bytes);var e=c.RootElement;
                StrictJson.Fields(e,"SchemaVersion","InstallationId","SessionId","JobId","IntentSHA256","Status");
                if(e.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(e,"InstallationId")!=state.InstallationId ||
                    StrictJson.Text(e,"SessionId")!=r.SessionId || StrictJson.Text(e,"JobId")!=r.JobId || StrictJson.Text(e,"IntentSHA256")!=raw.SHA256 ||
                    StrictJson.Text(e,"Status")!="EXACT_ORIGINAL_TIMEZONE_DACLS_AFTER_CLOSED_JOB")throw WfpNative.Contract("TimeZoneRestorationReceiptMismatch");
            }
        }
        if(pending.Count>1)throw WfpNative.Contract("TimeZoneOverlappingIntentsRefused");return pending;
    }
    internal static void AssertNoPending(ProtectedState state)
    {if(Pending(state).Count!=0)throw WfpNative.Contract("TimeZoneAccessRequiresExplicitRecovery");}
    internal static (int ExitCode,string Report) Inspect(ProtectedState state)
    {
        var pending=Pending(state);
        return(pending.Count==0?0:2,JsonSerializer.Serialize(new{SchemaVersion=1,Status=pending.Count==0?"NO_PENDING_TIMEZONE_READ_ACCESS":"TIMEZONE_READ_RECOVERY_DECISION_REQUIRED",
            Pending=pending.Select(p=>new{p.Record.SessionId,p.Record.JobId,KeyCount=p.Record.Targets.Length}),StateModified=false,RegistryModified=false}));
    }
    internal static (int ExitCode,string Report) Recover(ProtectedState state)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var job in OwnedJobIntent.ReadAll(state))if(AtomicJobCompletion.ReadClosed(state,job) is null)throw WfpNative.Contract("TimeZoneRecoveryRequiresAllAdmissionsClosed");
        var plans=FencePlan.ReadAll(state);if(plans.Count==0)throw WfpNative.Contract("TimeZoneRecoveryRequiresQuarantine");
        foreach(var p in plans){using var f=PersistentFence.OpenExisting(state,p.Data.FenceId);if(!f.Observe().FullQuarantineObserved)throw WfpNative.Contract("TimeZoneRecoveryRequiresQuarantine");}
        var pending=Pending(state);
        foreach(var item in pending)
        {
            var opened=new List<SafeRegistryHandle>();
            try{foreach(var t in item.Record.Targets)opened.Add(Open(item.Record.TimeZoneId,t.Role,true));Restore(state,item.Record,item.Hash,opened.ToArray());}
            finally{foreach(var key in opened)key.Dispose();}
        }
        AssertNoPending(state);
        return(0,JsonSerializer.Serialize(new{SchemaVersion=1,Status="EXACT_TIMEZONE_READ_ACCESS_RECOVERED",Count=pending.Count,JobCreated=false,ProcessCreated=false,NetworkPolicyModified=false}));
    }
    private static string Digest(string text)=>Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text)));
    public void Dispose()
    {
        if(disposed)return;disposed=true;foreach(var key in keys)key.Dispose();
        if(!restored)throw WfpNative.Contract("TimeZoneAccessRequiresExplicitRecovery");
    }
    [DllImport("ntdll.dll",ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int NtQueryKey(SafeRegistryHandle key,int information,IntPtr buffer,uint size,out uint resultLength);
}
