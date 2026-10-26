# Claude Code Protection

Windows Claude Code网络保护工具，当前开发中，未提供可执行交付。真实Claude登录、推理和正式启动按用户要求延期；独立保护工具及探针的功能、故障和安装生命周期仍须完成。

当前状态以[开发状态](docs/STATUS.md)为准；历史证据与范围保留在[验收账本](docs/PROJECT-ACCEPTANCE.md)。[工作规则](AGENTS.md)落实2026-10-26的自主开发要求：本地小范围提交，用户不作为日常阶段审批节点，不配置远程或推送。

## 当前已落实

- 已建立本地Git基线，状态、日志、PID、备份、凭据与构建产物不入库；原始资料未清理。
- 日常CLI、GUI、工程后端、生命周期库四个C#项目完成无产物语义检查，0错误/0警告；不是BUILD或运行通过。
- 实际CLI/GUI维护调用点共用当前用户私有目录，备份与报告不再写安装目录；旧项目备份不自动迁移。
- [四个上游的固定源码复用审查](docs/UPSTREAM-REUSE-20261026.md)已完成，不引入Go/Python/WDK整包依赖。

## 安全与交付边界

卡巴斯基曾在旧综合selftest期间报告PDM:Trojan.Win32.Generic。用户报告清除完成、未重启且当前显示正常；原因和整机影响仍未鉴定。原二进制已删除，不恢复或重跑，不通过排除、改名、重包装或关闭防护绕过。

原构建/运行停止条件保持，当前无批准包。FlClash Global、系统代理、TUN/BFE不停止或重设。IPv6只实现阻断和必要负向测试。当前Job/WFP/lifecycle源码尚未贯通完整生产宿主，不能称为保护已启用、即时断网或跨重启验收成功。

## 开发检查

在已有PowerShell7.4+、SDK8.0.422和引用包8.0.28的环境中：

```powershell
pwsh -NoProfile -File scripts/Check-SourceTypes.ps1
```

该检查仅读取源码与SDK元数据，不运行MSBuild/restore/分析器/生成器，不Emit或加载项目程序集，不调用产品/原生API。它是当前简单项目声明的有界语义检查，不是通用MSBuild替代器；真实构建和运行仍受安全许可约束。

日常后端显式编译7份文件（含与GUI共享的用户目录策略）；工程后端11份，保留独立输出位置，旧SelfTests.cs不进入任何编译清单。生命周期库19份源码尚未接入完整宿主；不继续以新增外围协议替代集成。

## 专项资料

- [安全事件](docs/INCIDENT-20261025-KASPERSKY.md)、[本机验证计划](docs/LOCAL-VALIDATION-PLAN.md)、[日常网络基线](docs/LOCAL-OPERATING-BASELINE.md)、[网络范围](docs/NETWORK-SCOPE.md)。
- [生命周期源码](docs/SECURE-LIFECYCLE-SOURCE.md)、[恢复](docs/LIFECYCLE-RECOVERY-SOURCE.md)、[精确卸载](docs/EXACT-UNINSTALL-SOURCE.md)、[Job成员](docs/OWNED-JOB-SOURCE.md)、[WFP屏障](docs/PERSISTENT-FENCE-SOURCE.md)。
- 这些专项文档包含按时间追加的SOURCE记录；较早的源码数量/未完成项不替代当前STATUS，也不授予运行资格。
