using ClaudeProtection;

static void Require(bool truth,string reason)
{
    if(!truth)throw new InvalidOperationException("PolicySmoke: "+reason);
}
static StrictPreflightCheck Find(StrictPreflightReport report,string name)=>
    report.Checks.Single(c=>c.Id==name);
const now=DateTimeOffset.UtcNow;
const sample=new List<Check>();
foreach(var name in new[]{
    "proxy-listener","proxy-owner-path","system-proxy-baseline","user-proxy-settings",
    "flclash-tun","host-timezone","host-locale","ipv6-functional","dns-isolation",
    "stun-webrtc","claude-api-transport"})
    sample.Add(new Check(name,"PASS","SYNTHETIC_TEST_ONLY",false));
// Required=false from any untrusted daily snapshot is ignored by strict mode.
var audit=new Audit(1,now.ToString("o"),sample);
var baseline=StrictPreflight.Evaluate(audit,now);
Require(baseline.Checks.Length==14,"exactly 14 checks");
Require(baseline.Checks.All(c=>c.RequiredForStrictMode && !c.TrustedForLaunchAdmission),"no downgrade of strict requirement");
Require(Find(baseline,"proxy-core").Status=="PASS","observational proxy composition");
Require(Find(baseline,"egress-public-ip").Status=="UNKNOWN","country or proxy cannot prove public IP");
Require(Find(baseline,"session-watchdog").Status=="UNKNOWN","no fabricated live watchdog PASS");
Require(!baseline.AllStrictChecksPass && !baseline.BrokerSecurityAdmissionPresent && !baseline.LaunchAuthorized,
    "no trusted launch despite observational PASS");

var stale=StrictPreflight.Evaluate(audit,now.AddHours(1));
Require(!stale.EvidenceFresh && Find(stale,"proxy-core").Status=="UNKNOWN","reject expired positive observations");
var invalidSchema=StrictPreflight.Evaluate(audit with {SchemaVersion=9},now);
Require(!invalidSchema.SourceNamesUnique && Find(invalidSchema,"proxy-core").Status=="UNKNOWN","unknown audit schema");
var future=StrictPreflight.Evaluate(audit,now.AddMinutes(-3));
Require(!future.EvidenceFresh && Find(future,"proxy-core").Status=="UNKNOWN","future-dated audit rejected");
var duplicate=StrictPreflight.Evaluate(audit with {Checks=sample.Append(sample[0]).ToList()},now);
Require(!duplicate.SourceNamesUnique && Find(duplicate,"proxy-core").Status=="UNKNOWN","duplicate-source rejection");
var missing=StrictPreflight.Evaluate(audit with {Checks=sample.Where(c=>c.Name!="proxy-owner-path").ToList()},now);
Require(Find(missing,"proxy-core").Status=="UNKNOWN","missing proxy owner source");
var bad=StrictPreflight.Evaluate(audit with {Checks=sample.Select(c=>c.Name=="proxy-listener"?c with {Status="FAIL"}:c).ToList()},now);
Require(Find(bad,"proxy-core").Status=="FAIL","preserve hard failure");
var offline=StrictPreflight.Evaluate(audit with {Checks=sample.Select(c=>c.Name=="claude-api-transport"?c with {Status="UNKNOWN"}:c).ToList()},now);
Require(Find(offline,"claude-service-reachability").Status=="UNKNOWN","offline transport not a PASS");
Require(!DiagnosticNetworkTargetPolicy.DestinationRequiresRestriction("www.microsoft.com"),"public DNS name only a candidate");
foreach(var host in new[]{"localhost","127.0.0.1","10.10.1.1","172.16.0.1","192.168.1.4",
    "169.254.169.254","100.64.1.1","198.18.0.5","::1","fc00::1","2001:db8::1",
    "::ffff:127.0.0.1","metadata.google.internal","router.local","wpad.private"})
    Require(DiagnosticNetworkTargetPolicy.DestinationRequiresRestriction(host),"host restricted: "+host);
Require(DiagnosticNetworkTargetPolicy.IsApprovedDiagnostic("https://api.anthropic.com/v1/models","http://127.0.0.1:7890"),
    "fixed Claude transport");
Require(DiagnosticNetworkTargetPolicy.IsApprovedDiagnostic("https://www.cloudflare.com/cdn-cgi/trace","http://127.0.0.1:7890"),
    "fixed trace transport");
foreach(var target in new[]{"http://api.anthropic.com/v1/models","https://127.0.0.1/",
    "https://10.0.0.1/","https://api.anthropic.com.evil.example/v1/models",
    "https://api.anthropic.com:444/v1/models","https://api.anthropic.com/v1/models?address=1",
    "https://user:pass@api.anthropic.com/v1/models","https://api.anthropic.com/v1/models#fragment"})
    Require(!DiagnosticNetworkTargetPolicy.IsApprovedDiagnostic(target,"http://127.0.0.1:7890"),
        "diagnostic target rejected: "+target);
Require(!DiagnosticNetworkTargetPolicy.IsApprovedDiagnostic("https://api.anthropic.com/v1/models",
    "http://127.0.0.1:9090"),"management port is not an approved proxy");
Console.WriteLine("PolicySmoke: bounded pure policy cases passed. No product or native code executed.");
