using ClaudeProtection;
using ClaudeCodeProtection.Security;
using System.Net;

static void Require(bool truth,string reason)
{
    if(!truth)throw new InvalidOperationException("PolicySmoke: "+reason);
}
static StrictPreflightCheck Find(StrictPreflightReport report,string name)=>
    report.Checks.Single(c=>c.Id==name);
var now=DateTimeOffset.UtcNow;
var sample=new List<Check>();
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

static IPAddress IP(string value)=>IPAddress.Parse(value);
Require(ProxyDestinationPolicy.IsPublicHostnameCandidate("api.anthropic.com"),"reviewed HTTPS host name syntax");
Require(!ProxyDestinationPolicy.IsPublicHostnameCandidate("127.1"),"shortened numeric IPv4 blocked");
Require(!ProxyDestinationPolicy.IsPublicHostnameCandidate("0x7f000001"),"hex numeric alias blocked");
Require(!ProxyDestinationPolicy.IsPublicHostnameCandidate("intranet"),"single-label alias blocked");
Require(!ProxyDestinationPolicy.IsPublicHostnameCandidate("metadata.google.internal"),"metadata name blocked");
Require(!ProxyDestinationPolicy.IsPublicHostnameCandidate("router.local"),"mDNS name blocked");
Require(!ProxyDestinationPolicy.IsPublicHostnameCandidate("dns.home.arpa"),"special-use ARPA name blocked");
Require(!ProxyDestinationPolicy.IsPublicHostnameCandidate("api.anthropic.com."),"trailing dot rejected");
Require(!ProxyDestinationPolicy.IsPublicHostnameCandidate("api.anthropic.com\\bad"),"backslash authority rejected");
Require(!ProxyDestinationPolicy.IsPublicHostnameCandidate("éxample.com"),"ambiguous Unicode name rejected");
foreach(var denied in new[]{"0.0.0.0","10.0.0.1","100.64.0.1","127.1.2.3","169.254.169.254",
 "172.16.0.1","192.0.0.2","192.0.2.1","192.88.99.1","192.168.1.1",
 "198.18.0.1","198.19.2.3","198.51.100.2","203.0.113.2","224.0.0.1","255.255.255.255",
 "::","::1","::ffff:8.8.8.8","fe80::1","fc00::1","ff02::1","2001:db8::1","2002::1","2001::1"})
    Require(!ProxyDestinationPolicy.IsPublicAddressCandidate(IP(denied)),"special address denied "+denied);
foreach(var accepted in new[]{"1.1.1.1","8.8.8.8","93.184.216.34","2606:4700:4700::1111"})
    Require(ProxyDestinationPolicy.IsPublicAddressCandidate(IP(accepted)),"public candidate "+accepted);
var selectedHost="api.anthropic.com";var good=IP("1.1.1.1");var other=IP("8.8.8.8");var internalIp=IP("127.0.0.1");
Require(ProxyDestinationPolicy.AuthorizePinnedHttps(selectedHost,443,new[]{good},good).Allowed,"known public literal candidate");
Require(!ProxyDestinationPolicy.AuthorizePinnedHttps(selectedHost,443,new[]{good,internalIp},good).Allowed,
    "mixed public/private DNS answers fail closed");
Require(!ProxyDestinationPolicy.AuthorizePinnedHttps(selectedHost,443,new[]{good},internalIp).Allowed,
    "selected private address not in verified answer");
Require(!ProxyDestinationPolicy.AuthorizePinnedHttps(selectedHost,443,new[]{good},other).Allowed,
    "selected address not in response rejected");
Require(!ProxyDestinationPolicy.AuthorizePinnedHttps(selectedHost,443,Array.Empty<IPAddress>(),good).Allowed,
    "missing DNS resolution refused");
Require(!ProxyDestinationPolicy.AuthorizePinnedHttps(selectedHost,80,new[]{good},good).Allowed,
    "non-HTTPS port refused");
Require(!ProxyDestinationPolicy.AuthorizePinnedHttps("api.anthropic.com.evil.internal",443,new[]{good},good).Allowed,
    "internal-looking name refused even with public answer");
// A policy decision is only a candidate; the trusted forwarder must actually
// tunnel the selected IP literal, without allowing fallback to direct 7890.

Console.WriteLine("PolicySmoke: bounded pure policy cases passed. No product or native code executed.");
