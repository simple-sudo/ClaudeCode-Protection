using ClaudeCodeProtection.Security;
using System.Globalization;

namespace ClaudeProtection;

// Read-only diagnostics are NOT an admission credential. A real launch
// decision belongs to the installed Broker with fresh, bound kernel evidence.
internal sealed record StrictPreflightCheck(
    string Id,string Status,string[] ObservedSources,string EvidenceAtUtc,string EvidenceScope,
    string FailureReason,string RepairHint,string Applicability,bool RequiredForStrictMode,
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

    internal static StrictPreflightReport Evaluate(Audit audit,DateTimeOffset now)
    {
        var samples=audit.Checks??new List<Check>();
        var unique=samples.All(c=>c is not null && !string.IsNullOrWhiteSpace(c.Name)) &&
            samples.Where(c=>c is not null).Select(c=>c.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count()==samples.Count && audit.SchemaVersion==1;
        var fresh=DateTimeOffset.TryParseExact(audit.AtUtc,new[]{"O","yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'"},CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal,out var observed) &&
            now>=observed && now-observed<=TimeSpan.FromMinutes(2);
        var checks=StrictEnvironmentRequirements.Required.Select(def=>
        {
            var present=def.Sources.Where(name=>samples.Any(c=>c is not null && c.Name==name)).ToArray();
            var selected=samples.Where(c=>c is not null && def.Sources.Contains(c.Name,StringComparer.Ordinal)).ToArray();
            var complete=def.Sources.Length>0 && present.Length==def.Sources.Length;
            var invalid=selected.Any(c=>c.Status is not ("PASS" or "FAIL" or "UNKNOWN"));
            var status=selected.Any(c=>c.Status=="FAIL")?"FAIL":
                !unique || !fresh || invalid || !complete || selected.Any(c=>c.Status!="PASS")?"UNKNOWN":"PASS";
            var reason=status=="PASS"?"READ_ONLY_OBSERVATION_ONLY":
                selected.Any(c=>c.Status=="FAIL")?"ONE_OR_MORE_OBSERVATIONS_FAILED":
                !unique?"DUPLICATE_OR_INVALID_AUDIT_CHECK":
                !fresh?"AUDIT_EVIDENCE_STALE_OR_INVALID":
                !complete?"REQUIRED_COLLECTOR_MISSING":"OBSERVATION_UNKNOWN_OR_INVALID";
            return new StrictPreflightCheck(def.Id,status,present,audit.AtUtc,"DAILY_AUDIT_NONAUTHORITATIVE",
                reason,def.RepairHint,
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
