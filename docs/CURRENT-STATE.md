# 当前状态（权威摘要）

更新时间：2026-11-12。本文只保留当前可用的状态摘要；历史快照已归档至 [CURRENT-STATE-HISTORY-20261112](CURRENT-STATE-HISTORY-20261112.md)。开发过程和能力证据分别见 [STATUS](STATUS.md) 与 [PROJECT-ACCEPTANCE](PROJECT-ACCEPTANCE.md)。

## 1. GitHub 与开发基线

| 项目 | 当前事实 |
|---|---|
| 仓库 | simple-sudo/ClaudeCode-Protection |
| 可见性 | Public |
| 默认分支 | main |
| 当前线上开发分支 | chatgpt/complete-git-workflow-20261110 |
| 已继承的产品源码与架构冻结基线 | d7507e57959c8c580a79657b756ec5fc6611b6db |
| 本机开发分支 | codex/integrate-privacy-admission-20261027，在原工作区快进至线上交接基线，后续提交仅在本地 |
| 架构审查源码基线 | 74578e903c2584628d853598ef8f1910adf7da5b |
| 真实证据政策更新前 HEAD | 80a300f760a22b94060e598874b196f3e967dfef |
| 文档整理与语义修正验证基线 | 2a5e4a5bf26d0f723d4cbb08d59bd4419111a4fa（文档变更；产品源码未变） |
| PR | #3，OPEN / DRAFT |
| PR 目标分支 | codex/integrate-privacy-admission-20261027 |
| PR 目标基线 | 8d56b0c40ef92d384b572bb168eec6bcd8a44d4e |

线上交接分支比 PR 目标基线多 318 个提交，无落后提交。本机继承完整历史，GitHub PR #3 仍为 OPEN / DRAFT。

## 2. 最新云端验证

已按 HEAD 核对 `d7507e57959c8c580a79657b756ec5fc6611b6db` 的三组 GitHub Actions，均为 SUCCESS。

- [Hosted Windows compile only](https://github.com/simple-sudo/ClaudeCode-Protection/actions/runs/43354304869)
- [Offline workspace Git workflow verification](https://github.com/simple-sudo/ClaudeCode-Protection/actions/runs/43354304588)
- [Safe managed policy smoke](https://github.com/simple-sudo/ClaudeCode-Protection/actions/runs/43354304617)

该轮包含五个产品项目编译、六个聚焦 harness 编译、普通用户策略和 Runner Git 测试，以及提升权限的 NTFS fixture。本机另通过静态构建边界检查。验证范围详见 [验收账本](PROJECT-ACCEPTANCE.md#2026-11-12-架构交接源码与验证范围)。

## 3. 已有证据与未证明范围

已有局部证据包括：产品/测试项目托管编译、标准用户 Runner Git 工作流、Git 对象和回执独立核验、生产目录描述符在真实 NTFS fixture 上的权限/继承验证、限定任务目录恢复状态机测试，以及若干受限网络/代理资格源码和回归。

以下仍不得标记为完整产品交付：

- 产品 Broker → Owned Job → LPAC 的 schema 2 多命令完整执行链及真实 token 访问边界。
- 产品实际创建工作区的完整端到端时序、持久状态、崩溃/取消/超时与恢复。
- 真实 Claude Code 在完整受保护会话中的启动、工具调用、网络、文件访问和关闭验收。
- 全机公网 IPv4/IPv6 强制代理、DNS/UDP/QUIC、代理端点动态租约和故障窗口零直连。
- UU 远程所有公网传输路径均经指定代理的证明。
- 全部 P0 宿主敏感信息隔离、跨来源画像与数据外传验收。
- 保留 GPU 计算能力同时隔离 GPU 稳定个体身份的完整验收。

产品常规 Build 入口仍受 `SECURITY_REVIEW_REQUIRED` 硬停止约束。最近有证据的安装为 `f9e8d29d9c2c472495422dbffd40bffd`、INACTIVE、package schema 32、25 项资产，见 [安装观察](STATUS.md#2026-11-12-显式-git-工作流-schema-2对抗配置独立指标与结果快照验收)。本次普通权限读取私有版本指针被拒绝，当前安装状态未能独立复核。源码内嵌的旧 Bootstrap 批准包和更新迁移仍不适用于该安装。官方 Claude Code 每次执行及高影响系统实验按现行操作门禁取得具体决定。

## 4. 2026-11-12 网络架构更新

正式网络目标已从“Claude 进程专属防直连 + 用户临时控制全机 IPv6”升级为：

**用户明确启用 Protection 网络模式期间，全机所有应用和 Windows 服务的公网流量必须经过指定 FlClash 美国住宅代理。**

- FlClash TUN/Global 负责接管和选择代理路径；不是最终强制安全边界。
- Windows WFP/可信网络所有者必须阻断物理网卡上的未授权公网直连。
- IPv4、IPv6、TCP、UDP、DNS、DoH、DoT、QUIC 等分别验证；不支持代理的协议阻断，不允许 DIRECT 回退。
- 代理、TUN、端点或策略异常时保持 fail-closed。
- Claude 本机敏感资源隔离和数据外传审计仍是独立 P0。
- UU 远程在 FlClash Global 美国代理开启时能够正常使用，是用户观察到的应用兼容性证据；并未证明 UU 的全部 TCP/UDP/P2P/中继流量均经过代理。

**状态：全机模式 DESIGN，定向双栈拒绝资格已有 SOURCE。** 首个切片加入 WFP 出站包层规则定义及仅中止的原生对象资格代码。内存测试通过。普通权限读取本机 WFP 层字段返回 Win32 5。原生对象往返、投递、全机策略及恢复仍待验证。规范见 [NETWORK-SCOPE](NETWORK-SCOPE.md) 和 [PROTECTED-STARTUP-SHUTDOWN-LIFECYCLE-V1](PROTECTED-STARTUP-SHUTDOWN-LIFECYCLE-V1.md)。

## 5. 公开仓库状态与资料边界

仓库当前为 Public。当前基线未发现根目录 LICENSE；公开可见不等于已授予开源复用许可。历史文档部分形成于私有研发阶段，可能包含本机路径、对象摘要或个人环境上下文。本次文档重组不构成完整的公开历史、PR、Actions 日志或 Artifacts 审计。

设备所有者已明确接受将研发必要的真实主机信息、敏感字段、私人路径、设备/网络/代理/远控元数据、原始日志和失败证据纳入当前 Public GitHub 仓库；后续开发不得默认脱敏或用合成数据替代。证据必须保留来源、时间、身份、工件 SHA 和上下文，见 [EVIDENCE-GOVERNANCE](EVIDENCE-GOVERNANCE.md)。可直接认证或重放的密码、Token、Cookie、私钥和代理订阅凭据仍独立管理；历史公开内容的清理如有需要，另行制定凭据轮换、历史重写和缓存/Artifacts 方案。

## 6. 文档治理与最新验证状态（2026-11-12）

- 新增 [EVIDENCE-GOVERNANCE](EVIDENCE-GOVERNANCE.md)：设备所有者明确允许必要真实主机信息、敏感字段和原始证据进入 Public GitHub 仓库；不再默认脱敏或以合成数据替代真实证据。有效认证凭据仍独立管理，Claude 执行域不继承研发者证据权限。
- 重建 [DOCUMENTATION-INDEX](DOCUMENTATION-INDEX.md)：覆盖 docs 目录内 68 份 Markdown 文档及上游许可证文本；检查到的索引链接目标均存在。历史方案保留并标注历史效力。
- 修正 SECURITY-REQUIREMENTS 中旧 IPv4-only / IPv6 临时门范围，明确由 2026-11-12 全机公网代理目标取代；对 2026-11-02 宿主隐私交接补充历史效力说明，不改写当时事实。
- 在文档验证基线 `2a5e4a5bf26d0f723d4cbb08d59bd4419111a4fa` 上，GitHub Actions 三组均 SUCCESS：
  - Safe managed policy smoke：`43189433446`
  - Hosted Windows compile only：`43189433267`
  - Offline workspace Git workflow verification：`43189433650`
- 本轮只变更文档，不修改产品可执行源码，不构成实机安装、网络更改或正式 Claude 启动授权。

## 7. 架构冻结后的开发重点

现有产品模块和资源所有权以 `d7507e5` 冻结。带类型的资源意图、工作区租约和独立 Git 策略已经继承。收尾审查、冻结范围与后续调整条件见 [架构决策](ARCHITECTURE-BASELINE-AND-TARGET-20261112.md#14-2026-11-12-架构收尾与冻结)。

1. 全机公网出口保护进入主要开发顺序。首个切片验证持久拒绝、WFP 分层、新旧连接的物理投递和精确恢复。只读现场快照与 Windows 原语审查见 [全机 WFP 可行性审查](NETWORK-SCOPE.md#2026-11-12-全机-wfp-可行性审查与首个实证切片)。
2. 接入可信 Core 与授权端点、有限 DNS 引导、代理正向路径和故障收敛，再验证 UU 的实际控制与传输路径。
3. 按功能完成宿主敏感信息 L3、受限进程和工具、设备及 GPU 身份、管理面自我保护、安装升级恢复卸载，并最终完成正式 Claude Code 端到端验收。
