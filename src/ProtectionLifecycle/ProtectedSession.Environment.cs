using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Security;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal sealed partial class ProtectedSession
{
    private sealed record EnvironmentEvidence(string Id,string Status,string Reason,long ObservedMs,long ValidForMs);

    private (EnvironmentExpectations?,string?,string) ReadExpectations()
    {
        try
        {
            var raw=state.ReadOptional("session-environment-policy.json");
            return raw is null?(null,null,"EXPLICIT_ENVIRONMENT_EXPECTATIONS_MISSING"):
                (EnvironmentExpectations.Parse(raw.Bytes,state.InstallationId,SessionProxy.PolicySHA256),raw.SHA256,"EXPLICIT_PROTECTED_ENVIRONMENT_EXPECTATIONS");
        }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or JsonException or ArgumentException or
            InvalidOperationException or FormatException or OverflowException or System.ComponentModel.Win32Exception)
        {return(null,null,"PROTECTED_ENVIRONMENT_INTENT_INVALID_OR_UNREADABLE");}
    }
    private IReadOnlyList<EnvironmentEvidence> MissingEnvironment()=>Array.AsReadOnly(StrictEnvironmentRequirements.Required.Select(def=>new EnvironmentEvidence(
        def.Id,"UNKNOWN",SystemTestingBlocked?"NOT_RUN_SYSTEM_VALIDATION_BLOCKED":"CURRENT_BROKER_COLLECTOR_MISSING",clock.ElapsedMilliseconds,10000)).ToArray());
    private void RefreshEnvironment(bool force=false)
    {
        if(SystemTestingBlocked)return;
        var now=clock.ElapsedMilliseconds;
        if(!force && lastCollectionMs>=0 && now-lastCollectionMs<10000)return;
        var observed=MissingEnvironment().ToDictionary(e=>e.Id,StringComparer.Ordinal);
        void Set(string name,string status,string reason)=>observed[name]=new(name,status,reason,clock.ElapsedMilliseconds,10000);
        try
        {
            if(expectations is null)
            {Set("host-timezone","UNKNOWN",expectationsReason);Set("host-locale","UNKNOWN",expectationsReason);}
            else
            {
                if(state.ReadOptional("session-environment-policy.json")?.SHA256!=expectationsSHA256)
                    throw new InvalidDataException("EnvironmentIntentChanged");
                using var identity=WindowsIdentity.GetCurrent();
                if(identity.User?.Value!=expectations.OwnerSid)throw new InvalidDataException("EnvironmentIntentOwnerMismatch");
                try
                {
                // This cache belongs to this Broker process. Do not change the
                // host setting; do not retain Local across a cache refresh.
                TimeZoneInfo.ClearCachedData();
                var zone=TimeZoneInfo.Local.Id;
                _=TimeZoneInfo.FindSystemTimeZoneById(expectations.TimeZoneId);
                Set("host-timezone",zone==expectations.TimeZoneId?"PASS":"FAIL",zone==expectations.TimeZoneId?
                    "CURRENT_OS_TIMEZONE_MATCHES_EXPLICIT_INTENT_NOT_ISOLATION_PROOF":"CURRENT_OS_TIMEZONE_MISMATCH");
                }
                catch(Exception ex) when(ex is TimeZoneNotFoundException or InvalidTimeZoneException or System.Security.SecurityException or ArgumentException or InvalidOperationException)
                {Set("host-timezone","UNKNOWN","CURRENT_TIMEZONE_READ_NOT_CONFIRMED");}
                try
                {
                var user=new StringBuilder(85);var system=new StringBuilder(85);
                var userCount=GetUserDefaultLocaleName(user,user.Capacity);var systemCount=GetSystemDefaultLocaleName(system,system.Capacity);
                if(userCount is <2 or >85 || systemCount is <2 or >85 || user.Length!=userCount-1 || system.Length!=systemCount-1)
                    throw new InvalidDataException("CurrentLocaleReadUnavailable");
                var matches=user.ToString()==expectations.UserLocale && system.ToString()==expectations.SystemLocale;
                Set("host-locale",matches?"PASS":"FAIL",matches?
                    "CURRENT_OWNER_USER_AND_SYSTEM_LOCALE_MATCH_EXPLICIT_INTENT_NOT_ISOLATION_PROOF":"CURRENT_LOCALE_MISMATCH");
                }
                catch(Exception ex) when(ex is IOException or System.ComponentModel.Win32Exception or InvalidOperationException)
                {Set("host-locale","UNKNOWN","CURRENT_LOCALE_READ_NOT_CONFIRMED");}
            }
        }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or
            TimeZoneNotFoundException or InvalidTimeZoneException or ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {Set("host-timezone","UNKNOWN","CURRENT_ENVIRONMENT_INTENT_OR_OS_READ_NOT_CONFIRMED");Set("host-locale","UNKNOWN","CURRENT_ENVIRONMENT_INTENT_OR_OS_READ_NOT_CONFIRMED");}
        if(job is not null && gateway is not null && fences.Count>0)
        {
            try
            {
                gateway.AssertHealthy();
                var expected=admission is null?fences.All(f=>f.IsSessionChannel && f.Observe().FullQuarantineObserved):
                    fences.All(f=>f.IsSessionChannel && f.Observe().IPv4ProxyOnlyObserved);
                Set("owned-routing-policy",expected?"PASS":"FAIL",expected?
                    "CURRENT_SESSION_KERNEL_OBJECTS_MATCH_EXPECTED_STAGE_FUNCTIONAL_QUALIFICATION_SEPARATE":"CURRENT_SESSION_RULE_DRIFT");
                // Exact ownership alone is not end-to-end transport availability.
                Set("proxy-core","UNKNOWN","CURRENT_PROXY_IDENTITY_HELD_TRANSPORT_QUALIFICATION_MISSING");
                if(runtime?.StartupGuardObserved==true)Set("session-watchdog","PASS",
                    "CURRENT_BROKER_STARTUP_GUARD_BOUND_TO_JOB_FAULT_QUALIFICATION_SEPARATE");
            }
            catch(Exception){Set("owned-routing-policy","UNKNOWN","CURRENT_SESSION_KERNEL_READ_NOT_CONFIRMED");}
        }
        environment=Array.AsReadOnly(StrictEnvironmentRequirements.Required.Select(def=>observed[def.Id]).ToArray());
        lastCollectionMs=clock.ElapsedMilliseconds;
    }

    private bool CurrentWorkloadEvidenceEligible()=>IsGatewayQualification?
        clock.ElapsedMilliseconds>=0 && clock.ElapsedMilliseconds<GatewayQualificationLimitMs:
        !SystemTestingBlocked && EnvironmentEligible() && SystemSecurityEligible();
    private void AssertQualificationBinding(bool quarantine)
    {
        state.AssertHeld();version.AssertHeld(state);
        if(!IsGatewayQualification || !CurrentWorkloadEvidenceEligible() || resources is not null ||
            state.Read("current.json",4096).SHA256!=pointerSHA256 || job is null || gateway is null || sid is null ||
            gateway.SessionId!=id || fences.Count==0 || fences.Any(f=>!f.IsSessionChannel || quarantine && !f.Observe().FullQuarantineObserved))
            throw WfpNative.Contract("FixedGatewayQualificationExpiredOrBindingDrift");
        if(preparation?.RootPid is not null)
            (preparation.PublicTimeZone??throw WfpNative.Contract("TimeZoneResourceNotPrepared")).AssertCurrent();
        if(UsesFixedOpenSslHead)
        {
            FixedOpenSslHeadTrust.RequireCurrent(DateTimeOffset.UtcNow);
            FixedResolverTrust.RequireCurrent(DateTimeOffset.UtcNow);
        }
        winsockAccess?.AssertHeld();
        gateway.AssertHealthy();
    }
    private bool PreparationEnvironmentEligible()=>expectations is not null && environment.Where(e=>e.Id is "host-timezone" or "host-locale")
        .Count(e=>e.Status=="PASS" && clock.ElapsedMilliseconds-e.ObservedMs<e.ValidForMs)==2;
    private bool EnvironmentEligible()=>environment.Count==StrictEnvironmentRequirements.Required.Count &&
        environment.Select(e=>e.Id).Distinct(StringComparer.Ordinal).Count()==environment.Count &&
        StrictEnvironmentRequirements.Required.All(def=>environment.Any(e=>e.Id==def.Id)) &&
        environment.All(e=>e.Status=="PASS" && e.ValidForMs is >0 and <=120000 &&
            clock.ElapsedMilliseconds>=e.ObservedMs && clock.ElapsedMilliseconds-e.ObservedMs<e.ValidForMs);
    private bool SystemSecurityEligible()=>systemSafety.Select(e=>e.Id).SequenceEqual(SystemRequirements) &&
        systemSafety.All(e=>e.Status=="PASS" && e.ValidForMs is >0 and <=120000 &&
            clock.ElapsedMilliseconds>=e.ObservedMs && clock.ElapsedMilliseconds-e.ObservedMs<e.ValidForMs);
    private void AssertCurrent()
    {
        if(IsGatewayQualification){AssertQualificationBinding(quarantine:false);return;}
        RefreshEnvironment();
        if(SystemTestingBlocked || !EnvironmentEligible() || !SystemSecurityEligible())throw WfpNative.Contract("SessionEvidenceExpiredUnknownOrBlocked");
        state.AssertHeld();version.AssertHeld(state);
        if(state.Read("current.json",4096).SHA256!=pointerSHA256 || job is null || gateway is null || sid is null ||
            state.ReadOptional("session-environment-policy.json")?.SHA256!=expectationsSHA256 ||
            gateway.SessionId!=id || fences.Count==0 || fences.Any(f=>!f.IsSessionChannel))
            throw WfpNative.Contract("SessionInstallationPolicyOrResourceBindingDrift");
        gateway.AssertHealthy();
    }
    private void AssertPreparedCurrent(bool force=false)
    {
        if(IsGatewayQualification){AssertQualificationBinding(quarantine:true);return;}
        AssertSystemTestingAllowed();RefreshEnvironment(force);
        state.AssertHeld();version.AssertHeld(state);
        if(!PreparationEnvironmentEligible() || state.Read("current.json",4096).SHA256!=pointerSHA256 ||
            state.ReadOptional("session-environment-policy.json")?.SHA256!=expectationsSHA256 ||
            job is null || gateway is null || sid is null || gateway.SessionId!=id || fences.Count==0 ||
            fences.Any(f=>!f.IsSessionChannel || !f.Observe().FullQuarantineObserved))
            throw WfpNative.Contract("SuspendedSessionPreparationBindingOrQuarantineDrift");
        gateway.AssertHealthy();
    }

    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] private static extern int GetUserDefaultLocaleName(StringBuilder name,int capacity);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] private static extern int GetSystemDefaultLocaleName(StringBuilder name,int capacity);
}
