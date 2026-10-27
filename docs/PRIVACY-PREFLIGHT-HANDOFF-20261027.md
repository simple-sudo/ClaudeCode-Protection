# ChatGPT GitHub handoff — 网络隐私边界与十四项只读门禁

基线：`main@8e5b4ee15d9ff250e2858dbea3d3cee8e00bbe32`
分支：`dev/chatgpt-privacy-preflight-20261027`
证据：**SOURCE ONLY**。本轮通过 GitHub 读写源码，未在用户电脑执行、编译、安装、提权或开启任何 Windows 原生实验。

## 这批代码已经接入哪里

- `ClaudeProtection preflight` 和 `preflight --online`：复用原有日常审计，额外输出十四项逐项诊断对象，并始终以非零退出码表示**不授予启动权**。未改动现有 `launch` 的拒绝行为。
- `StrictPreflight.cs`：覆盖代理内核、TUN、出口公网 IP、IP 一致性、时区、Locale、IPv6、DNS、WebRTC/STUN、Watchdog、路由规则、客户端语言、出口 ASN、Claude 生态可达性十四项。全部为严格模式必需项；不允许原始 `Required=false` 降级。缺测、未知、过期、异常状态、重复/无效来源均不得自动变成 PASS。
- `Read-Environment.ps1`：补充独立的只读时区与区域设置观察；不做全局设置修改。
- `DiagnosticNetworkTargetPolicy.cs`：收紧**本项目自己的 HTTP 诊断客户端**，只允许精确的 Claude API 与 Cloudflare trace HTTPS 请求通过固定 `127.0.0.1:7890`，拒绝其他 URL、代理地址、端口及 URL 凭据；提供不依赖网络的非公网地址/本地后缀分类，用于判定部分明显的危险输入。`EnvironmentAudit.Transport` 已调用该策略；不修改用户 FlClash。
- `tests/PolicySmoke`：纯 .NET、无第三方包的源码链接测试，不执行项目 native 代码、WFP、Job、CUDA 或代理请求。

## 重要的安全边界

**此 PR 不代表宿主机敏感资源隔离已经完成。**

- 仅对诊断客户端过滤 URL，**不能约束 Claude、PowerShell、Python、MCP 等其他进程通过 FlClash 发起的请求**。当前 WFP 允许到本地代理的连接；要阻止通过代理转发到 `127.0.0.1`、`192.168/16`、`169.254.169.254`、控制器端口或内部管理接口，仍需可信代理/网关端按最终解析出的 IP 与连接目标执行限制，并防 DNS 重绑定。对一般域名的静态检查无法证明它解析到公网。
- 禁止直连只能控制出站路径；子进程本身仍可能读取网络接口地址、路由表、环境变量、位置服务或其他敏感宿主信息，再经**允许的代理**发出去。最终应围绕具体可访问对象设计最低权限和负向验证，不声称能消除所有设备/位置指纹。
- 十四项当前属于`DAILY_READ_ONLY_DIAGNOSTIC_NOT_BROKER_ADMISSION`；既不签发可信令牌，也没有实时安装/Job/WFP/身份绑定。结果里的单项 PASS 仅表示该项有限观察通过。`BrokerSecurityAdmissionPresent` 与 `LaunchAuthorized` 必须保持 false。未来强制准入必须由已安装的可信 Broker 基于新鲜、原子绑定的安全证据作决定，不接受 GUI/日常 CLI 的历史报告。
- Cloudflare trace 现有日常测试只记录国家，不记录可验证的出口公网 IP 或 ASN；所以 `egress-public-ip`、`egress-ip-consistency`、`egress-asn` 仍是 UNKNOWN，绝不凭 `loc=US` 赋 PASS。
- 新增的主机名/地址分类是筛选明显危险输入，不是已核验的 DNS 解析和连接对象证明；实际代理路由、出口身份、系统 DNS 服务流量与真实位置隐私仍须实机核验。

## 交给桌面 Work 的统一检查

1. 在**保留原工作区未提交修改**的前提下单独检出此分支，确认基线及与其它 ChatGPT PR/本地工作无冲突。不要直接覆盖 main 或合并未验收代码。
2. 先静态审查整个 diff，特别是 C# 8.0/SDK 8 与 PowerShell 5.1 的语法和入口契约。此提交未执行编译，不得冒充 BUILD。
3. 在用户决定且符合现有安全停止条件时，可独立运行纯托管 `tests/PolicySmoke`（无本机系统管理功能）；检查十四项完整性、失败/缺测/过期/重复的拒绝、网络私有目的地拒绝和网络请求精确白名单。
4. 即使纯托管测试通过，也**不能自动恢复产品构建、安装、系统级 WFP/Job/Watchdog 实验**。2026-10-27 蓝屏 `0x1E` 的故障模块和归因仍 UNKNOWN，需依照既有 `docs/INCIDENT-20261027-SYSTEM-CRASH.md` 单独处理。
5. 逐步接入独立系统安全准入，由可信 Broker 持有授权权威；现有 `preflight` 命令不得被升级为可绕过 Broker 的启动入口。与 Watchdog PR #1 分开评审合并。
6. 后续真正的“真实 IP / 网络元信息隔离”要在受保护工作负载和可信转发侧同时建立机制，用正向工作区/编程工具可用 + 负向敏感数据读取/未经授权网络投递共同验证。

本分支不更改全机时区、IPv6、DNS、FlClash/TUN、反病毒软件、WFP/Job 持久对象，不运行真实 Claude。
