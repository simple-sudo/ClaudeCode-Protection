# 当前状态（权威摘要）

更新时间：2026-11-13（GitHub 只读核查）。本页记录本次文档同步前的产品源码基线；文档同步提交本身只改变交接文档，不改变该产品源码基线。历史快照见 [CURRENT-STATE-HISTORY-20261112](CURRENT-STATE-HISTORY-20261112.md)。开发过程与能力证据分别见 [STATUS](STATUS.md) 和 [PROJECT-ACCEPTANCE](PROJECT-ACCEPTANCE.md)。

## 1. GitHub 与开发基线

| 项目 | 2026-11-13 核查事实 |
|---|---|
| 仓库 | simple-sudo/ClaudeCode-Protection |
| 可见性 | Public |
| 默认分支 | main |
| 当前开发分支 | codex/integrate-privacy-admission-20261027 |
| 当前 codex HEAD | bdbd667545519952e5f4bb8464fd782364d18f8c（在产品源码基线 622700e 上增加 1 个文档同步提交） |
| 最近产品源码行为基线 | 622700ebefa685eaf2179d032bcd3da352e83065 |
| 现有产品架构冻结基线 | d7507e57959c8c580a79657b756ec5fc6611b6db |
| PR #3 | CLOSED / MERGED，2026-11-13 06:17:18Z |
| PR #3 来源分支与 HEAD | chatgpt/complete-git-workflow-20261110 @ d7507e57959c8c580a79657b756ec5fc6611b6db |
| PR #3 目标分支 | codex/integrate-privacy-admission-20261027 |
| PR #3 原目标基线 | 8d56b0c40ef92d384b572bb168eec6bcd8a44d4e |
| PR #3 merge commit | d7507e57959c8c580a79657b756ec5fc6611b6db |
| main 分支当前 HEAD | af59eb0bf4f90d6114a58e0e3ac0b45c032003b5（安全门禁文档曾短暂误建后已删除，当前树中无该文件） |
| PR #4 | OPEN / DRAFT，head `chatgpt/p0-assurance-host-20261113`，base `codex/integrate-privacy-admission-20261027` |

**PR #3 已经合并，不是 OPEN / DRAFT。** GitHub 返回 merged=true、closed 状态；merge commit 为 d7507e5。不要重新打开、重复合并或把旧 Draft PR 记录当成当前状态。

**当前 codex 分支包含 PR #3 的全部成果及后续开发：**

- PR 原目标基线 8d56b0c → PR merge commit d7507e5：318 个提交。
- PR merge commit d7507e5 → 产品源码基线 622700e：额外 16 个提交；之后 bdbd667 又增加 1 个文档同步提交。
- 原目标基线 8d56b0c → codex HEAD bdbd667：共领先 335 个提交；其中最后 1 个提交只更新文档。
- d7507e5 是 622700e 的祖先；PR #3 的来源分支不是当前开发主线。

main 与 codex 已分叉。此前统计的 ahead/behind 数字已因后续文档提交及 main 上的临时 add/delete 更正而过期，后续如需比较必须重新查询。2026-11-13 曾因 GitHub Contents API 漏传 branch 参数，将本门禁文档短暂创建在默认 main；随后已复制到本独立分支并从 main 删除。main 当前树不含该文件，但历史保留新增与删除两个提交（main HEAD `af59eb0`）。**不要自动将 codex 同步、覆盖或合并到 main。**

## 2. GitHub Actions 与验证边界

PR merge commit / 产品源码基线 d7507e57959c8c580a79657b756ec5fc6611b6db 对应的三组 GitHub Actions 均为 SUCCESS：

- [Hosted Windows compile only](https://github.com/simple-sudo/ClaudeCode-Protection/actions/runs/43354304869)
- [Offline workspace Git workflow verification](https://github.com/simple-sudo/ClaudeCode-Protection/actions/runs/43354304588)
- [Safe managed policy smoke](https://github.com/simple-sudo/ClaudeCode-Protection/actions/runs/43354304617)

这些成功结果只覆盖 d7507e5，不自动覆盖后续 16 个提交。对 622700e 的 GitHub Actions workflow-run 查询和 combined-status 查询均未返回记录。因此，**不得把 d7507e5 的三组 CI SUCCESS 写成 622700e 已通过 CI**。本次文档提交也不新增产品构建或实机验收证据。

## 3. PR 合并后的 16 个提交：当前源码进展

d7507e5 之后的 16 个提交继续在现有 ProtectionLifecycle / WFP 方向推进全机公网出口验证切片，最后提交为 622700e（Require stable fresh proxy route observations for endpoint leases）。主要新增或调整：

- 双栈 WFP 出站探针策略、精确接口/接收端约束及中止式事务。
- 投递证据、三阶段发送、受控发送端、路由核验和网络变更通知。
- WFP 历史丢弃事件选择、Ethernet 帧匹配及完整采集窗口判定。
- 双栈持久隔离策略、意图记录、精确恢复状态与过滤器对象回读。
- FlClash Core 进程身份、选定代理路线摘要和新鲜稳定观察绑定的端点租约。
- 对应的 WfpReadStatus 测试与 NETWORK-SCOPE、STATUS、PROJECT-ACCEPTANCE 文档更新。

这批工作是全机网络主线的增量源码和限定验证，不是完整网络产品交付，也不改变 2026-11-12 冻结的既有产品入口和资源所有权基线。详细源码/机制边界见 [NETWORK-SCOPE](NETWORK-SCOPE.md#2026-11-12-全机-wfp-可行性审查与首个实证切片)、[开发记录](STATUS.md) 和 [验收账本](PROJECT-ACCEPTANCE.md)。

## 4. 当前网络实现与未证明范围

正式目标仍为：用户明确启用 Protection 网络模式期间，全机所有应用和 Windows 服务的公网流量经过指定 FlClash 美国住宅代理；不允许未授权直连或 DIRECT 回退。FlClash TUN/Global 负责接管和选择路径，不是最终安全边界；Windows WFP/可信 Owner 才负责强制阻断。

**当前状态：全机模式仍为 DESIGN；若干拒绝策略、探针、事务、隔离恢复和代理端点租约已达到 SOURCE，部分受控 Windows 回环/路由行为有范围受限的 VERIFIED 证据。**

仓库验收记录描述的限定验证包括：IPv4/IPv6 × TCP/UDP × 新建/既存套接字八组回环正向控制、24 条独立发送回执、原生路由查询和路由/地址/接口变化通知。它们证明的是受控回环、发送端和路由控制面范围，不等于物理公网出口验收。

以下仍为 NOT_RUN 或未完成：

- 全机 WFP 持久拒绝规则在真实产品事务中的提交、仲裁、物理出口阻断及精确恢复。
- 可信采集端真实枚举 WFP 丢弃事件、物理接口 Ethernet/ETL 投递和零丢失窗口。
- Broker → 全机策略 Owner → WFP 的实际接线、权限和生命周期。
- FlClash Core 实际外层连接与真实远端代理端点的完整身份/路由/出口核验，以及动态端点更新。
- DNS、DoH、DoT、UDP、QUIC、IPv6、转发、虚拟网卡、网络切换和故障窗口的全覆盖。
- UU 远程全部控制、画面、键鼠、文件传输、UDP/P2P、中继和重连流量经代理的证明。
- 真实代理故障、TUN 退出、Owner/Watchdog 崩溃、重启及策略漂移时的 fail-closed 和精确恢复。

不得把回环测试、合成 WFP 事件、托管策略测试或 SOURCE 标记描述为完整全机网络能力。详细矩阵见 [NETWORK-SCOPE](NETWORK-SCOPE.md) 和 [验收账本](PROJECT-ACCEPTANCE.md#全机出口首个切片定向双栈-wfp-拒绝)。

## 5. 产品交付缺口与安装观察

以下仍不得标记为完整产品交付：

- 产品 Broker → Owned Job → LPAC 的 schema 2 多命令完整执行链及真实 token 访问边界。
- 产品实际创建工作区的完整端到端时序、持久状态、崩溃/取消/超时与恢复。
- 真实 Claude Code 在完整受保护会话中的启动、工具调用、网络、文件访问和关闭验收。
- 全机公网 IPv4/IPv6 强制代理、DNS/UDP/QUIC、代理端点动态租约和故障窗口零直连。
- 全部 P0 宿主敏感信息隔离、跨来源画像与数据外传验收。
- 保留 GPU 计算能力同时隔离 GPU 稳定个体身份的完整验收。
- 安装、升级、恢复、卸载及安全软件兼容性的完整产品闭环。

最后一次有明确来源的安装观察是用户于 2026-11-12 提供的只读核验：Release f9e8d29d9c2c472495422dbffd40bffd、Activation INACTIVE、Package schema 32、25 项资产；Pointer ManifestSHA256 与安装 package.json 的 SHA-256 均为 5195D12C6A446BA3408D822C3907E5FD7E51BB4ED820A69BFCB08A16512BDBC2。2026-11-13 未重新读取本机安装状态，故不把该值表述为今天已复核的安装状态。源码内嵌旧 Bootstrap 批准包/迁移与该安装不匹配，不得复用。

## 2026-11-13 SECURITY_REVIEW_REQUIRED 分阶段门禁更新（PR #4）

设备所有者已明确授权：将无条件永久停止改为分阶段、卡巴斯基持续监控、新告警立即停止的门禁。该策略已在独立 PR #4 分支实现；PR #4 仍为 OPEN / DRAFT，未合并 Codex 主线。

- 当前仅 `DailyBuild` 阶段开放：固定日常 `ClaudeProtection.csproj`、Release、`dotnet build --no-restore`；不 publish、不安装、不执行生成的产品程序。
- `EngineeringBuild`、`CenterBuild`、`NativeBuild`、`IsolationProbe`、`WfpMutation` 均仍 BLOCKED。
- 运行前检查 Kaspersky 服务 `AVP21.26`、Windows Security Center Kaspersky 注册及既有 productState `266240`；构建期间约每 750ms 检查相关 Application 事件、每 3 秒重查服务和产品状态。新相关事件、状态变化或监控失败会终止被监控的构建进程树。
- 该观察不是完整 Kaspersky 厂商遥测，`FullVendorAlertVisibility=UNKNOWN`；本机执行阶段仍要求设备所有者同时观察卡巴斯基界面。不得关闭 AV、增加排除项、恢复隔离对象或规避检测。
- **当前门禁源码尚未在用户本机执行；DailyBuild 也尚未运行。** 现阶段仅为 SOURCE，不能标记 BUILD、AV 兼容 VERIFIED 或产品交付。完整范围见 [KASPERSKY-STAGED-QUALIFICATION-20261113](KASPERSKY-STAGED-QUALIFICATION-20261113.md)。

官方 Claude Code 每次执行及安装、提权、WFP/网络修改等高影响操作仍按各自当前授权和阶段门禁处理。

## 6. 公开仓库与证据治理

仓库当前为 Public；当前基线未发现根目录 LICENSE。公开可见不等于已授予开源复用许可。设备所有者已明确接受将研发必要的真实主机信息、敏感字段、私人路径、设备/网络/代理/远控元数据、原始日志和失败证据纳入当前 Public GitHub 仓库；后续开发不得默认脱敏或用合成数据替代。证据必须保留来源、时间、身份、工件 SHA 和上下文，见 [EVIDENCE-GOVERNANCE](EVIDENCE-GOVERNANCE.md)。可直接认证或重放的密码、Token、Cookie、私钥和代理订阅凭据仍独立管理。

## 7. 文档治理与后续开发顺序

本次 2026-11-13 文档同步更新：

- AGENTS.md：移除“线上研发必用 chatgpt/* + Draft PR”的过期固定工作流假设，改为以 CURRENT-STATE 和 GitHub 实时分支/PR 状态为准。
- CURRENT-STATE.md：更新当前 codex 开发线、PR #3 合并事实、16 个后续提交、CI 边界和网络状态。
- STATUS.md、PROJECT-ACCEPTANCE.md、ARCHITECTURE-BASELINE-AND-TARGET-20261112.md：增加 2026-11-13 分支/PR 纠正记录；保留 2026-11-12 当时 OPEN / DRAFT 的历史事实，并标明已被后续状态取代。

后续开发优先级：

1. 继续完成全机 WFP 首个切片：真实原生对象读回/提交与恢复、可信物理投递采集、WFP 丢弃事件和受控接收端的同流对账。
2. 将持久拒绝与精确恢复接入可信 Broker/Owner 生命周期，再实现经过实际验证的 FlClash Core 外层端点放行。
3. 逐项完成 DNS、双栈协议、UDP/QUIC、网络变化、代理故障和 UU 远程兼容性验收。
4. 并行按优先级推进宿主敏感信息 L3、受限进程与工具、设备及 GPU 身份、管理面自我保护、安装升级恢复卸载，最终完成正式 Claude Code 端到端验收。

