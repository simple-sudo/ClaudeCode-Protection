# Claude Code Protection — 开发中，未提供可执行交付

2026-10-25 卡巴斯基曾对 `ClaudeProtection.exe selftest` 报出 `PDM:Trojan.Win32.Generic`。用户最新反馈：“已经清除了，但是我没有重启，目前卡巴斯基显示正常”，并选择后续继续在本机验证。这是用户观察；没有厂商误报结论、告警原因结论或整机安全鉴定。生成二进制已删除，不恢复原文件、不重复运行原综合 selftest。

本轮继续静态源码改造，未编译、启动项目程序、安装或进行网络实验。`Protection.cmd`、`Inspect.cmd` 和构建/实验停止条件仍保留。源码拆分不代表安全软件兼容性已解决，不得通过排除、改名、重打包或关闭防护重试。

## 目标与范围

完成本机 IPv4 强制代理、受保护父/子进程 IPv4/IPv6 未授权外联阻断、持久 WFP、防直连、Kill-Switch、Watchdog、配置漂移处理、安全安装/更新/恢复/卸载及功能和故障验收。不影响日常 FlClash Global、系统代理与 TUN。IPv6 仅保留阻断与必要负向测试，不开发 IPv6 转发或出口选择。

真实 Claude 登录、推理与正式启动为 `DEFERRED_BY_USER`，不计通过。真实 Claude 两条现有防火墙规则保持禁用。已有项目管理员操作授权沿用；UAC 由本人确认，不建立长期任意管理员执行入口。

## 源码边界

| 组成 | 当前职责 | 限制 |
|---|---|---|
| 日常后端 `src/ClaudeProtection` | 代理/环境审计、身份、配置维护；明确列出 6 份编译源文件 | 不编译 Job、AppContainer、工程 workers 或故障注入；launch 直接返回 125 |
| 工程后端 `src/ClaudeProtection.Engineering` | 独立项目与编译清单；探针和监测器；未来输出至 `bin/engineering` | 日常构建与 GUI 不调用；无真实 Claude 启动或旧综合 selftest 入口 |
| 历史 `SelfTests.cs` | 保留原测试源码 | 两个后端均不编译，不能原样重跑 |
| GUI `src/ProtectionCenter` | 环境检查、Claude 代理配置维护两个按钮；后端命令白名单 | 未运行/视觉验收，无二进制；无工程测试按钮 |
| 原生 WFP 工程后端 | schema 2 GUID 记录、四角色语义检查、事务内清理 | 未编译/运行；用户可写代码/状态目录仍不是正式管理员信任边界 |

构建脚本仍停止，不构成安装器或运行建议。工程项目保持相同程序集文件名以沿用 staging 协议，输出位置独立；本轮未生成任何版本。Job 的普通进程创建路径也已在源码中拒绝，保留专用 sandbox 调用边界。

## 文档与剩余工作

- [完整验收账本](docs/PROJECT-ACCEPTANCE.md)：历史失败、UNKNOWN、工件身份和范围；项目未完成。
- [安全事件](docs/INCIDENT-20261025-KASPERSKY.md)、[静态源码审查](docs/SECURITY-SOURCE-REVIEW.md)。
- [WFP 恢复协议](docs/WFP-RECOVERY-PROTOCOL.md)、[本机分阶段验证计划](docs/LOCAL-VALIDATION-PLAN.md)。
- [日常网络基线](docs/LOCAL-OPERATING-BASELINE.md)、[网络范围](docs/NETWORK-SCOPE.md)、[浏览器故障记录](docs/INCIDENT-20261025-PROXY.md)。

新增检查仅为不访问 WFP 的纯协议测试和语法解析，不证明实际阻断、重启持久性或 AV 兼容性。旧探针 PASS 不覆盖新源码。

仍须完成可信管理员代码/状态边界、安全生命周期、Watchdog/漂移闭环、配置路径身份绑定、DNS/UDP 归属及本机故障验收。现有探针不能授予真实 CLI 或任意工具链部署资格。当前不注册服务、计划任务或自启，不修改 FlClash、TUN、全局代理、系统区域或杀毒策略。

保留 [固定上游审查](docs/UPSTREAM-REVIEW.md)。WFP 协议依据微软 [对象管理与事务](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)、[过滤器结构](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0) 和 [按 key 读取](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltergetbykey0)；API 语义依据不替代本机验收。

## 管理员生命周期源码接续

新增独立 `src/ProtectionLifecycle` Library，包含固定包/路径协议、句柄及 ACL 核验、受保护状态、版本暂存和生命周期账本；默认无批准包，没有可执行或提升入口。10组嵌入协议数据检查只覆盖 JSON 图/管理表面，不是安装运行验收。完整 bootstrap、生产 broker/owner、恢复与生命周期 handlers 尚未完成。见 [源码内核及边界](docs/SECURE-LIFECYCLE-SOURCE.md)。

版本安装/更新/回滚的未激活切换与中断恢复现已补入具体源码，包含重新核验文件、精确指针快照和原账本保留；仍未编译/运行。完整卸载及真实管理员owner/可信引导等仍待完成，见 [版本与恢复边界](docs/LIFECYCLE-RECOVERY-SOURCE.md)。

精确卸载与中断续接已补入源码，按保存的角色/对象ID/哈希逐项删除，保留原配置和证据；仍未编译或执行。资源owner、可信引导与创建身份窗口等仍须完成，见 [卸载源码边界](docs/EXACT-UNINSTALL-SOURCE.md)。

创建身份与初始化修复已继续补入源码；目录清理采用schema 2归属记录，读取异常与真实缺失分开处理。尚无运行验收，截断payload清理及实际运行期边界仍待完成，见 [创建身份源码边界](docs/CREATION-IDENTITY-SOURCE.md)。

2026-10-26续接：部分写入消费方已补入源码，卸载快照升为schema 3，区分预期字节和已证明归属的未发布写入；完成/发布后漂移仍拒绝，不回填旧清单。未编译、未执行清理或验收，实际运行期owner和损坏账本恢复等仍待完成，见 [部分写入清理源码边界](docs/PENDING-WRITE-CLEANUP-SOURCE.md)。

完成回执恢复与状态暂存后发布继续补入源码：原始损坏回执先保留，新回执明确记录本次完整字节观察，不复原旧PASS、不发布版本或推进阶段。未编译或运行，其他坏账本恢复及实际运行期组件仍待完成，见 [完成回执恢复源码边界](docs/COMPLETION-RECOVERY-SOURCE.md)。

Job进程成员控制现有独立具体源码：私有namespace、内核owner/DACL与归属标记核对、实际句柄停止/零成员回读及登记集合。它尚未组成完整runtime lease；进程创建/原子绑定、启动准入、崩溃后全范围核验及网络owner仍缺失，未编译或执行，见 [Job成员控制源码边界](docs/OWNED-JOB-SOURCE.md)。
安装身份WFP屏障已有独立具体源码：私有GUID/计划摘要绑定、六角色初始双栈隔离、事务内归属核对/重建和独立语义回读；不关联未经实际服务绑定的provider。尚不能开放代理通路或移除最终屏障供卸载使用，未编译或调用API，不授予启动/跨重启/完整断网资格，见 [WFP隔离屏障源码边界](docs/PERSISTENT-FENCE-SOURCE.md)。