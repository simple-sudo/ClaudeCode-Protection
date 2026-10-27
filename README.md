# Claude Code Protection

Windows Claude网络保护与环境管理工具，正在开发。已完成本机首次未激活安装及普通用户GUI离线检查；持续网络保护、故障恢复和安全卸载尚未交付。真实Claude登录、推理和正式会话按用户要求延期。

2026-10-27已将修正更新到正式未激活版本，固定隔离入口实际提交并回读6条安装专属持久WFP规则；自有有限canary在创建时原子绑定专属身份和Job，核验完整隔离后恢复执行，结束后封闭准入并核对清零，后续维护也成功消费完成回执。canary没有网络操作，代理开放、实际防泄漏和崩溃恢复仍未验收。原失败及版本历史均保留，具体当前安装见开发状态。

当前事实见[开发状态](docs/STATUS.md)，历史逐项证据见[验收账本](docs/PROJECT-ACCEPTANCE.md)，产品原则见[完整指导落实](docs/PRODUCT-DIRECTION-20261026.md)。现有[GitHub私有仓库](https://github.com/simple-sudo/ClaudeCode-Protection)及origin保持；本地小范围提交，不代用户推送。

## 当前可用切片

- CLI、WPF界面、broker及生命周期库完成当前离线构建，0错误/0警告；独立bootstrap嵌入14文件批准清单并单独构建。六项目源码类型检查通过，工程后端本轮未构建/运行。
- 本机经人类UAC完成首次安装：受保护代码与私有状态、版本整包核验、INACTIVE指针及完成账本。14文件摘要与权限已回读，普通用户不能改写、不能读取私有指针。没有服务、自启动或启用保护策略。
- 已安装GUI的“检查环境”实际调用已安装CLI并保存当前用户报告。此次结果9 PASS/3 FAIL/8 UNKNOWN；代理API不一致、禁用规则和其他未知项如实展示，不代表网络保护通过。
- 用户配置维护已构建并接入GUI：当前用户私有备份、独占锁、先行中断记录和摘要冲突拒绝；修复、撤销及故障分支尚未实测。在线按钮尚未运行。
- 固定quarantine及只读安装观察已实际运行；原子准入仅通过自有无网络canary，真实网络行为、代理失效及崩溃恢复尚未验收。

本机界面位于`C:\Program Files\ClaudeCodeProtection\versions\806b2b6997c84e0da4db46c9d267d7a0\bin\center\ProtectionCenter.exe`，用普通权限打开。当前实测入口为“检查环境”；界面明确显示保护尚未启用。文件布局与本次批准包专属于当前机器/发布，尚非通用安装发行版。

## 下一开发主线

复用现有Job/WFP和生命周期，实现原子进程准入、代理通道审核与精确身份网络限制，使用自有合成进程验证失效/崩溃/恢复，再接Watchdog、更新及安全卸载。Claude Code子进程、独立组件、Desktop和网页逐步纳入，不能粗暴阻断共享浏览器或按名称判定可信进程。

[上游复用审查](docs/UPSTREAM-REUSE-20261026.md)已补充claude-switcher的383f927→870c4ca共18提交。借鉴运行中规则回读及检查/修复体验；不复制Direct成功标签、盲目回滚、全局关闭或按名终止，不引入Go/Python/驱动整包依赖。

## 安全与证据边界

卡巴斯基曾报告PDM:Trojan.Win32.Generic，原因及整机影响仍未鉴定。不恢复退休二进制、不跑旧聚合selftest、不添加排除/关闭防护/规避检测；新告警即停。当前有限窗口未观察到新Application AV事件，完整厂商告警覆盖UNKNOWN。

用户已批准原阻塞部分继续推进；每个新构建/运行仍核验具体输入与作用范围，不反复申请相同许可。原Build/Assert/cmd停止保留防误用。FlClash Global、系统代理及TUN/BFE保持日常状态，UAC由本人确认。时区、全机IPv6、DNS等允许设计为用户明确选择、必要性/影响可说明且可安全恢复的高级能力，本轮未实施全机修改。

## 源码检查

已有PowerShell7.4+、SDK8.0.422与引用8.0.28时：

```powershell
pwsh -NoProfile -File scripts/Check-SourceTypes.ps1
```

检查器只读源码/SDK元数据；不MSBuild、restore、Emit或加载项目程序集，不运行分析器/生成器或产品原生API。按真实WPF默认集合处理隐式引用，使用内存CompilationReference支持直接本地库叶引用，不支持的工程声明拒绝。SOURCE不替代BUILD或功能验收。

状态、日志、PID、备份、凭据、原始报告和构建产物不入Git；旧失败及UNKNOWN保留。专项资料见[安全事件](docs/INCIDENT-20261025-KASPERSKY.md)、[网络范围](docs/NETWORK-SCOPE.md)、[生命周期](docs/SECURE-LIFECYCLE-SOURCE.md)、[Job](docs/OWNED-JOB-SOURCE.md)及[WFP](docs/PERSISTENT-FENCE-SOURCE.md)。较早文档的未完成状态按时间保留，由STATUS说明当前进展。
