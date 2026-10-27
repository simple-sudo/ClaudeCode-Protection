using System.Globalization;

namespace ClaudeProtection;

// Read-only diagnostics are NOT an admission credential. A real launch
// decision belongs to the installed Broker with fresh, bound kernel evidence.
internal sealed record StrictPreflightCheck(
    string Id,string Status,string[] ObservedSources,string FailureReason,
    string RepairHint,string Applicability,bool RequiredForStrictMode,
    bool TrustedForLaunchAdmission);

internal sealed record StrictPreflightReport(
    int SchemaVersion,string Scope,string EvidenceAtUtc,bool EvidenceFresh,
    bool SourceNamesUnique,StrictPreflightCheck[] Checks,bool AllStrictChecksPass,
    bool BrokerSecurityAdmissionPresent,bool LaunchAuthorized);

// Never infer a new PASS from an existing summary. Each explicitly listed
// observation can support only that bounded diagnostic condition; UNKNOWN
// remains UNKNOWN for unimplemented collectors, regardless of other PASSes.
internal static class StrictPreflight
{
    private sealed record Definition(string Id,string[] Sources,string RepairHint);
    private static readonly Definition[] Required =
    {
        new("proxy-core",new[]{"proxy-listener","proxy-owner-path","system-proxy-baseline","user-proxy-settings"},"Verify the exact running proxy, listener ownership and approved settings"),
        new("tun-interface",new[]{"flclash-tun"},"Inspect whether the current policy requires TUN and verify the relevant interface"),
        new("egress-public-ip",Array.Empty<string>(),"Add a bounded proxy-side public-IP observation; never use the host IP as the expected exit"),
        new("egress-ip-consistency",Array.Empty<string>(),"Compare independently scoped, time-bound authorized egress observations"),
        new("host-timezone",new[]{"host-timezone"},"Review the selected timezone and read the current OS setting"),
        new("host-locale",new[]{"host-locale"},"Review the selected locale and read current user/system settings"),
        new("protected-ipv6",new[]{"ipv6-functional"},"Require negative IPv6 evidence bound to the protected SID and current WFP rules"),
        new("resolver-dns",new[]{"dns-isolation"},"Prove raw and service-mediated DNS traffic ownership and enforcement"),
        new("webrtc-stun",new[]{"stun-webrtc"},"Evaluate only applicable components and deny unauthorized UDP/STUN paths"),
        new("session-watchdog",Array.Empty<string>(),"Provide a live, authenticated Watchdog/Job owner observation"),
        new("owned-routing-policy",Array.Empty<string>(),"Provide a verified current installation, WFP, proxy and Job binding"),
        new("client-language",Array.Empty<string>(),"Observe component language against an explicitly selected policy"),
        new("egress-asn",Array.Empty<string>(),"Observe the authorized exit ASN without exposing sensitive address details"),
        new("claude-service-reachability",new[]{"claude-api-transport"},"Perform an explicitly authorized proxy-only TLS/HTTP reachability check")
    };

    internal static StrictPreflightReport Evaluate(Audit audit,DateTimeOffset now)
    {
        var samples=audit.Checks??new List<Check>();
        var unique=samples.All(c=>c is not null && !string.IsNullOrWhiteSpace(c.Name)) &&
            samples.Select(c=>c.Name).Distinct(StringComparer.Ordinal).Count()==samples.Count;
        var fresh=DateTimeOffset.TryParse(audit.AtUtc,CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind,out var observed) &&
            now-observed>=TimeSpan.FromSeconds(-30) && now-observed<=TimeSpan.FromMinutes(2);
        var checks=Required.Select(def=>
        {
            var present=def.Sources.Where(name=>samples.Any(c=>c.Name==name)).ToArray();
            var selected=samples.Where(c=>def.Sources.Contains(c.Name,StringComparer.Ordinal)).ToArray();
            var complete=def.Sources.Length>0 && present.Length==def.Sources.Length;
            var invalid=selected.Any(c=>c.Status is not ("PASS" or "FAIL" or "UNKNOWN"));
            var status=selected.Any(c=>c.Status=="FAIL")?"FAIL":
                !unique || !fresh || invalid || !complete || selected.Any(c=>c.Status!="PASS")?"UNKNOWN":"PASS";
            var reason=status=="PASS"?"READ_ONLY_OBSERVATION_ONLY":
                selected.Any(c=>c.Status=="FAIL")?"ONE_OR_MORE_OBSERVATIONS_FAILED":
                !unique?"DUPLICATE_OR_INVALID_AUDIT_CHECK":
                !fresh?"AUDIT_EVIDENCE_STALE_OR_INVALID":
                !complete?"REQUIRED_COLLECTOR_MISSING":"OBSERVATION_UNKNOWN_OR_INVALID";
            return new StrictPreflightCheck(def.Id,status,present,reason,def.RepairHint,
                "STRICT_CLAUDE_CODE_POLICY",true,false);
        }).ToArray();
        if(checks.Length!=14 || checks.Select(c=>c.Id).Distinct(StringComparer.Ordinal).Count()!=14)
            throw new InvalidOperationException("Fourteen unique strict checks required");
        // Even fourteen observational PASS results could never grant runtime
        // admission: there is no trusted Broker-issued token, active session
        // binding, or authoritative real-time WFP/Job proof in this daily CLI.
        return new StrictPreflightReport(1,"DAILY_READ_ONLY_DIAGNOSTIC_NOT_BROKER_ADMISSION",
            audit.AtUtc,fresh,unique,checks,checks.All(c=>c.Status=="PASS"),
            BrokerSecurityAdmissionPresent:false,LaunchAuthorized:false);
    }
}
