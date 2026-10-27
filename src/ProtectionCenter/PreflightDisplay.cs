using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Security;

namespace ProtectionCenter;

// Presentation only. Validate the complete report before showing any positive
// item. A backend report can never grant launch permission.
internal static class PreflightDisplay
{
    internal static string Render(string output, DateTimeOffset now)
    {
        const string refused = "十四项检查报告无法核验。不能据此认定任何项目合格；保护仍未激活。请同时核对原始诊断记录的保存结果。";
        if (string.IsNullOrWhiteSpace(output) || output.Length > 262144) return refused;
        try
        {
            using var document = JsonDocument.Parse(output, new JsonDocumentOptions { MaxDepth = 16 });
            var root = document.RootElement;
            AssertUniqueProperties(root);
            if (root.GetProperty("SchemaVersion").GetInt32() != 1 ||
                root.GetProperty("Scope").GetString() != "DAILY_READ_ONLY_DIAGNOSTIC_NOT_BROKER_ADMISSION" ||
                root.GetProperty("BrokerSecurityAdmissionPresent").GetBoolean() ||
                root.GetProperty("LaunchAuthorized").GetBoolean()) return refused;
            var evidenceText = root.GetProperty("EvidenceAtUtc").GetString();
            if (!DateTimeOffset.TryParseExact(evidenceText, new[] { "O", "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'" },
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var observed)) return refused;
            var samples = root.GetProperty("Checks").EnumerateArray().ToArray();
            var definitions = StrictEnvironmentRequirements.Required;
            if (samples.Length != definitions.Count || Wording.Count != definitions.Count ||
                definitions.Any(def => !Wording.ContainsKey(def.Id))) return refused;
            foreach (var item in samples) AssertUniqueProperties(item);
            var ids = samples.Select(item => item.GetProperty("Id").GetString()).ToArray();
            if (ids.Distinct(StringComparer.Ordinal).Count() != definitions.Count ||
                ids.Any(id => !definitions.Any(def => def.Id == id))) return refused;
            if (samples.Any(item => !item.GetProperty("RequiredForStrictMode").GetBoolean() ||
                item.GetProperty("TrustedForLaunchAdmission").GetBoolean() ||
                item.GetProperty("EvidenceScope").GetString() != "DAILY_AUDIT_NONAUTHORITATIVE" ||
                item.GetProperty("EvidenceAtUtc").GetString() != evidenceText ||
                item.GetProperty("Status").GetString() is not ("PASS" or "FAIL" or "UNKNOWN"))) return refused;

            var fresh = root.GetProperty("EvidenceFresh").GetBoolean() && now >= observed &&
                now - observed <= TimeSpan.FromMinutes(2);
            var unique = root.GetProperty("SourceNamesUnique").GetBoolean();
            if (root.GetProperty("AllStrictChecksPass").GetBoolean() !=
                samples.All(item => item.GetProperty("Status").GetString() == "PASS")) return refused;
            var text = new StringBuilder("十四项只读检查（不是启动许可）\r\n保护未激活；真实 Claude 会话仍按要求延期。\r\n");
            text.Append("证据时间：").Append(observed.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture)).AppendLine();
            if (!fresh) text.AppendLine("证据过期、来自未来或未通过时效核验：正向结果一律显示为未知，请重新检查。");
            if (!unique) text.AppendLine("原始来源存在重复或格式异常：正向结果一律显示为未知。");
            for (var index = 0; index < definitions.Count; index++)
            {
                var definition = definitions[index];
                var item = samples.Single(sample => sample.GetProperty("Id").GetString() == definition.Id);
                var status = item.GetProperty("Status").GetString();
                if ((!fresh || !unique) && status == "PASS") status = "UNKNOWN";
                var label = status switch { "PASS" => "已观察到合格条件", "FAIL" => "失败", _ => "未知 / 尚未验证" };
                var wording = Wording[definition.Id];
                text.AppendLine().Append(index + 1).Append(". ").Append(wording.Label).Append("：").AppendLine(label);
                text.Append("   ").AppendLine(wording.Guidance);
            }
            text.AppendLine().Append("独立安全门禁：可信安装、当前会话身份 / Job / WFP、受限转发及子进程和宿主资源隔离仍须由 Broker 核验。此报告不提供授权。");
            return text.ToString();
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or InvalidDataException or KeyNotFoundException or FormatException or OverflowException)
        { return refused; }
    }

    private static void AssertUniqueProperties(JsonElement value)
    {
        var names = value.EnumerateObject().Select(property => property.Name).ToArray();
        if (names.Distinct(StringComparer.Ordinal).Count() != names.Length) throw new InvalidDataException("Duplicate report property");
    }

    private static readonly Dictionary<string, (string Label, string Guidance)> Wording = new(StringComparer.Ordinal) {
        ["proxy-core"] = ("代理内核", "需要核对实际监听、代理进程身份和配置；进程名称不构成保护证明。"),
        ["tun-interface"] = ("TUN 网卡", "由当前策略确定是否依赖 TUN；检查不会修改日常网卡。"),
        ["egress-public-ip"] = ("出口公网 IP", "需要通过授权通道取得当前出口观测；不能使用宿主地址作为预期出口。"),
        ["egress-ip-consistency"] = ("出口 IP 一致性", "需要比较同一策略和有效时间内的独立出口观测。"),
        ["host-timezone"] = ("时区", "需要明确选择预期时区；不会根据出口位置自动修改系统。"),
        ["host-locale"] = ("地区与 Locale", "需要明确选择地区与语言策略；这些设置不代替网络隔离。"),
        ["protected-ipv6"] = ("受保护进程 IPv6", "需要绑定当前受保护身份和规则的 IPv6 负向证据。"),
        ["resolver-dns"] = ("DNS 隔离", "需要分别验证原始 DNS 与系统服务代发的解析路径。"),
        ["webrtc-stun"] = ("WebRTC / STUN", "需要按实际组件验证 UDP / STUN；超时不能证明安全。"),
        ["session-watchdog"] = ("本会话守护进程", "需要本会话守护进程存活、归属和故障处理证据。"),
        ["owned-routing-policy"] = ("实际路由规则", "需要当前安装、WFP、Job 与代理路径一致；配置文件存在不够。"),
        ["client-language"] = ("客户端语言", "需要按用户明确选择的策略核对当前组件语言。"),
        ["egress-asn"] = ("出口 ASN", "需要当前授权出口及 ASN 证据；ASN 类别本身不证明安全。"),
        ["claude-service-reachability"] = ("Claude 服务可达性", "仅验证授权通道的 TLS / HTTP 可达性；401 / 403 不证明账号权限。")
    };
}
