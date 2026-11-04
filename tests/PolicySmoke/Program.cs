using ClaudeProtection;
using ClaudeCodeProtection.Security;
using System.Net;

static void Require(bool truth,string reason)
{
    if(!truth)throw new InvalidOperationException("PolicySmoke: "+reason);
}
static StrictPreflightCheck Find(StrictPreflightReport report,string name)=>
    report.Checks.Single(c=>c.Id==name);
if(args.Length==1 && args[0]=="gateway-destination-guard"){GatewayDestinationGuardCases.Run();return;}
if(args.Length==1 && args[0]=="session-tunnel"){await SessionTunnelCases.RunAsync();Console.WriteLine("PASS session tunnel fixtures");return;}
var now=DateTimeOffset.UtcNow;
if(args.Length==1 && args[0]=="directory-name-pages")
{
    ProtectionLifecycle.DirectoryNamePageCases.Run();return;
}
ProtectionLifecycle.DirectoryNamePageCases.Run();
LoopbackTcpTableCases.Run();
ProtectionLifecycle.ProfileRecoveryCases.Run();
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
Require(!StrictPreflight.Evaluate(audit,now.AddTicks(-1)).EvidenceFresh,"even small future offsets refused");
Require(StrictPreflight.Evaluate(audit with {AtUtc=now.UtcDateTime.ToString("O")},now).EvidenceFresh,"worker UTC roundtrip format");
Require(!StrictPreflight.Evaluate(audit with {AtUtc="2026-10-27"},now).EvidenceFresh,"date-only evidence refused");
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
 "::","::1","::ffff:8.8.8.8","fe80::1","fc00::1","ff02::1","2001:db8::1","2002::1","2001::1",
 "2001:2::1","2001:10::1","2001:20::1","3fff::1","2606:4700:4700::1111%12"})
    Require(!ProxyDestinationPolicy.IsPublicAddressCandidate(IP(denied)),"special address denied "+denied);
foreach(var accepted in new[]{"1.1.1.1","8.8.8.8","93.184.216.34","2606:4700:4700::1111","3ffe::1","3fff:1000::1"})
    Require(ProxyDestinationPolicy.IsPublicAddressCandidate(IP(accepted)),"public candidate "+accepted);
var selectedHost="api.anthropic.com";var good=IP("1.1.1.1");var other=IP("8.8.8.8");var internalIp=IP("127.0.0.1");
Require(ProxyDestinationPolicy.AuthorizePinnedHttps(selectedHost,443,new[]{good},good).Allowed,"known public literal candidate");
Require(!ProxyDestinationPolicy.AuthorizePinnedHttps(selectedHost,443,new[]{good,internalIp},good).Allowed,
    "mixed public/private DNS answers fail closed");
Require(!ProxyDestinationPolicy.AuthorizePinnedHttps(selectedHost,443,new[]{good},internalIp).Allowed,
    "selected private address not in verified answer");
Require(!ProxyDestinationPolicy.AuthorizePinnedHttps(selectedHost,443,new[]{good},other).Allowed,
    "selected address not in response rejected");
Require(!ProxyDestinationPolicy.AuthorizePinnedHttps("8.8.8.8",443,new[]{good},good).Allowed,"literal host cannot borrow a different address");
Require(!ProxyDestinationPolicy.AuthorizePinnedHttps(selectedHost,443,new IPAddress[]{null!},good).Allowed,"null DNS answer refused");
Require(!ProxyDestinationPolicy.AuthorizePinnedHttps(selectedHost,443,Array.Empty<IPAddress>(),good).Allowed,
    "missing DNS resolution refused");
Require(!ProxyDestinationPolicy.AuthorizePinnedHttps(selectedHost,80,new[]{good},good).Allowed,
    "non-HTTPS port refused");
Require(!ProxyDestinationPolicy.AuthorizePinnedHttps("api.anthropic.com.evil.internal",443,new[]{good},good).Allowed,
    "internal-looking name refused even with public answer");
// A policy decision is only a candidate; the trusted forwarder must actually
// tunnel the selected IP literal, without allowing fallback to direct 7890.

// Exercise the actual GUI formatter without starting WPF or a backend process.
static string Display(StrictPreflightReport report,DateTimeOffset at)=>
    ProtectionCenter.PreflightDisplay.Render(System.Text.Json.JsonSerializer.Serialize(report),at);
var rendered=Display(baseline,now);
Require(rendered.Contains("14. Claude 服务可达性") && rendered.Contains("不是启动许可"),"all fourteen items visible without launch authority");
Require(rendered.Contains("已观察到合格条件"),"fresh bounded observations are visible");
Require(!Display(baseline,now.AddMinutes(3)).Contains("已观察到合格条件"),"GUI independently expires old positive results");
Require(!Display(baseline,now.AddTicks(-1)).Contains("已观察到合格条件"),"GUI refuses future evidence");
Require(Display(bad,now.AddMinutes(3)).Contains("代理内核：失败"),"expired display preserves failures");
Require(!Display(baseline with {SourceNamesUnique=false},now).Contains("已观察到合格条件"),"GUI cannot present duplicated source positives");
foreach(var forged in new[]{
    baseline with {LaunchAuthorized=true},
    baseline with {BrokerSecurityAdmissionPresent=true},
    baseline with {AllStrictChecksPass=true},
    baseline with {Checks=baseline.Checks.Append(baseline.Checks[0]).ToArray()},
    baseline with {Checks=baseline.Checks.Skip(1).ToArray()},
    baseline with {Checks=baseline.Checks.Select((check,index)=>index==0?check with {RequiredForStrictMode=false}:check).ToArray()},
    baseline with {Checks=baseline.Checks.Select((check,index)=>index==0?check with {TrustedForLaunchAdmission=true}:check).ToArray()},
    baseline with {Checks=baseline.Checks.Select((check,index)=>index==0?check with {Status="CACHED_PASS"}:check).ToArray()},
    baseline with {Checks=baseline.Checks.Select((check,index)=>index==0?check with {EvidenceAtUtc=now.AddHours(-1).ToString("O")}:check).ToArray()}
}) Require(Display(forged,now).Contains("报告无法核验"),"GUI refuses malformed or authoritative-looking reports as a whole");
var duplicateProperty=System.Text.Json.JsonSerializer.Serialize(baseline).Replace("\"SchemaVersion\":1","\"SchemaVersion\":1,\"SchemaVersion\":1");
Require(ProtectionCenter.PreflightDisplay.Render(duplicateProperty,now).Contains("报告无法核验"),"duplicate JSON properties refused");
Require(ProtectionCenter.PreflightDisplay.Render("{}",now).Contains("报告无法核验"),"missing payload fields refused");
Require(ProtectionCenter.PreflightDisplay.Render(new string(' ',262145),now).Contains("报告无法核验"),"oversized report refused");

// These are the exact parsers consumed by SessionProxy before any forwarding.
static void Refuse(Action action,string reason)
{
    var refused=false;
    try{action();}catch(Exception error) when(error is System.IO.InvalidDataException or System.Text.Json.JsonException or
        InvalidOperationException or KeyNotFoundException or FormatException or OverflowException){refused=true;}
    Require(refused,reason);
}
var connect="CONNECT www.microsoft.com:443 HTTP/1.1\r\nHost: www.microsoft.com:443\r\nProxy-Authorization: Basic ZmFrZTpmYWtl\r\n\r\n";
Require(ProxyDestinationPolicy.ParseConnect(connect).Host=="www.microsoft.com","canonical CONNECT parsed before transport authorization");
Require(ProxyDestinationPolicy.ParseConnect(connect.Replace("Host:","host:")).Host=="www.microsoft.com","header names case insensitive");
foreach(var malformed in new[]{connect.Replace("CONNECT ","GET "),connect.Replace(":443",":7890"),
    connect.Replace("www.microsoft.com","127.0.0.1"),connect.Replace("www.microsoft.com","metadata.google.internal"),
    connect.Replace("Host: www.microsoft.com:443","Host: evil.invalid:443"),
    connect.Replace("\r\n\r\n","\r\nContent-Length: 12\r\n\r\n"),
    connect.Replace("\r\n\r\n","\r\nTransfer-Encoding: chunked\r\n\r\n"),
    connect.Replace("\r\n\r\n","\r\nHost: www.microsoft.com:443\r\n\r\n"),
    connect.Replace("\r\n","\n"),connect.Replace("HTTP/1.1","HTTP/2"),connect.Replace("Host:"," Host:"),connect[..^2]})
    Refuse(()=>ProxyDestinationPolicy.ParseConnect(malformed),"ambiguous or unauthorized CONNECT syntax refused");
static byte[] DnsBytes(string json)=>System.Text.Encoding.UTF8.GetBytes(json);
var doh="{\"Status\":0,\"TC\":false,\"Question\":[{\"name\":\"www.microsoft.com.\",\"type\":1}],\"Answer\":[{\"name\":\"www.microsoft.com.\",\"type\":1,\"TTL\":30,\"data\":\"1.1.1.1\"}]}";
Require(ProxyDestinationPolicy.ParseResolution("www.microsoft.com",DnsBytes(doh)).Single().Equals(IP("1.1.1.1")),"bounded matching public A answer");
foreach(var invalidDns in new[]{doh.Replace("\"Status\":0","\"Status\":3"),doh.Replace("\"TC\":false","\"TC\":true"),
    doh.Replace("\"TTL\":30","\"TTL\":0"),doh.Replace("\"1.1.1.1\"","\"127.0.0.1\""),
    doh.Replace("\"1.1.1.1\"","\"192.168.1.1\""),doh.Replace("\"1.1.1.1\"","\"::ffff:1.1.1.1\""),
    doh.Replace("\"Status\":0","\"Status\":0,\"Status\":0"),doh.Replace("\"name\":\"www.microsoft.com.\",\"type\":1,\"TTL\"","\"name\":\"unrelated.com.\",\"type\":1,\"TTL\""),
    doh.Replace("\"Question\":[","\"Question\":[{\"name\":\"extra.com.\",\"type\":1},")})
    Refuse(()=>ProxyDestinationPolicy.ParseResolution("www.microsoft.com",DnsBytes(invalidDns)),"unsafe or unrelated DoH answer refused");
var cname=doh.Replace("\"Answer\":[","\"Answer\":[{\"name\":\"www.microsoft.com.\",\"type\":5,\"TTL\":30,\"data\":\"cdn.microsoft.com.\"},")
    .Replace("\"name\":\"www.microsoft.com.\",\"type\":1,\"TTL\"","\"name\":\"cdn.microsoft.com.\",\"type\":1,\"TTL\"");
Require(ProxyDestinationPolicy.ParseResolution("www.microsoft.com",DnsBytes(cname)).Length==1,"CNAME chain bound to the matching question");
Refuse(()=>ProxyDestinationPolicy.ParseResolution("www.microsoft.com",DnsBytes(cname.Replace("cdn.microsoft.com.","router.local."))),"private CNAME refused");

// Only configuration intent is parsed here. It must never accept observations,
// status values, a different installation/policy or an implicit machine default.
var policyInstallation=new string('a',32);var networkPolicy=new string('A',64);
var expectationsJson=System.Text.Json.JsonSerializer.Serialize(new {SchemaVersion=1,InstallationId=policyInstallation,
    NetworkPolicySHA256=networkPolicy,OwnerSid="S-1-5-21-1-2-3-1001",TimeZoneId="Eastern Standard Time",UserLocale="en-US",SystemLocale="en-US"});
var expectations=EnvironmentExpectations.Parse(DnsBytes(expectationsJson),policyInstallation,networkPolicy);
Require(EnvironmentExpectations.ReadForMaintenance(DnsBytes(expectationsJson.Replace(networkPolicy,new string('B',64))),policyInstallation).NetworkPolicySHA256==new string('B',64),
    "historical intent remains inspectable without becoming current launch evidence");
Require(expectations.TimeZoneId=="Eastern Standard Time" && expectations.UserLocale=="en-US" && expectations.SHA256.Length==64,
    "explicit expectation values retained without reading host defaults");
foreach(var badIntent in new[]{expectationsJson.Replace("\"SchemaVersion\":1","\"SchemaVersion\":2"),
    expectationsJson.Replace("\"SchemaVersion\":1","\"SchemaVersion\":1,\"SchemaVersion\":1"),
    expectationsJson.Replace("\"SchemaVersion\":1","\"SchemaVersion\":1,\"LaunchAuthorized\":true"),
    expectationsJson.Replace("\"SchemaVersion\":1","\"SchemaVersion\":1,\"Status\":\"PASS\""),
    expectationsJson.Replace(policyInstallation,new string('b',32)),expectationsJson.Replace(networkPolicy,new string('B',64)),
    expectationsJson.Replace("S-1-5-21-1-2-3-1001","S-1-5-18"),expectationsJson.Replace("S-1-5-21-1-2-3-1001","S-1-5-21-01-2-3-1001"),
    expectationsJson.Replace("Eastern Standard Time",""),expectationsJson.Replace("en-US",""),expectationsJson.Replace("en-US","en-us")})
    Refuse(()=>EnvironmentExpectations.Parse(DnsBytes(badIntent),policyInstallation,networkPolicy),"malformed, implicit or authoritative-looking environment intent refused");

// Exercise the actual owner's crash-phase decision without WFP, disk or Job.
var priorImage=new string('A',64);var nextImage=new string('B',64);var foreignImage=new string('C',64);
Require(FenceMigrationSelection.Decide(priorImage,nextImage,priorImage,priorImage,true)==FenceMigrationAction.ReplaceKernelThenSelect,
    "before transaction selects exact replacement");
Require(FenceMigrationSelection.Decide(priorImage,nextImage,priorImage,nextImage,true)==FenceMigrationAction.SelectCommittedKernel,
    "commit before metadata resumes selection without deleting the new kernel objects");
Require(FenceMigrationSelection.Decide(priorImage,nextImage,nextImage,nextImage,true)==FenceMigrationAction.VerifySelectedKernel,
    "selection before completion only verifies the committed image");
foreach(var selectedImage in new[]{priorImage,nextImage,foreignImage})
foreach(var kernelImage in new[]{priorImage,nextImage,foreignImage})
{
    Refuse(()=>FenceMigrationSelection.Decide(priorImage,nextImage,selectedImage,kernelImage,false),"all non-quarantined migration states refused");
    if(selectedImage==foreignImage || kernelImage==foreignImage || selectedImage==nextImage && kernelImage==priorImage)
        Refuse(()=>FenceMigrationSelection.Decide(priorImage,nextImage,selectedImage,kernelImage,true),"foreign or reverse-order migration refused");
}
Refuse(()=>FenceMigrationSelection.Decide(priorImage,priorImage,priorImage,priorImage,true),"identical transition images refused");
Refuse(()=>FenceMigrationSelection.Decide(priorImage,nextImage,"invalid",nextImage,true),"malformed selection refused");

await SessionTunnelCases.RunAsync();
await TlsClientHelloCases.RunAsync();
Console.WriteLine("PolicySmoke: bounded policy, journal-reader and in-memory duplex cases passed. No product entry point, native mutation or network request was executed; profile-reader cases inspect the current Windows identity.");
