namespace ClaudeCodeProtection.Security;

// Shared identifiers and diagnostic mapping only; this catalog issues no authority.
internal static class StrictEnvironmentRequirements
{
    internal sealed record Definition(string Id,string[] Sources,string RepairHint);
    internal static readonly IReadOnlyList<Definition> Required = Array.AsReadOnly(new Definition[]
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
    });

}
