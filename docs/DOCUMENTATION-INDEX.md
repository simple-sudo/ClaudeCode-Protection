# 文档索引与职责规范

本页是仓库文档导航和维护规范。正式需求、当前状态、机制设计和历史证据必须分开维护；不要把同一套“当前结论”复制到多篇专题文档。

## 1. 权威入口

| 层级 | 文档 | 唯一职责 |
|---|---|---|
| 项目介绍 | [README](../README.md) | 产品定位、架构概览、当前重大限制 |
| Agent 规则 | [AGENTS](../AGENTS.md) | 开发行为、分支、测试和公开资料边界 |
| 当前状态 | [CURRENT-STATE](CURRENT-STATE.md) | 当前分支/PR/CI、实现基线、阻塞和下一步 |
| 正式需求 | [SECURITY-REQUIREMENTS](SECURITY-REQUIREMENTS.md) | 唯一规范性安全目标、优先级、威胁模型和术语 |
| 网络范围 | [NETWORK-SCOPE](NETWORK-SCOPE.md) | 全机公网出口强制代理、协议边界和验收矩阵 |
| 启停生命周期 | [PROTECTED-STARTUP-SHUTDOWN-LIFECYCLE-V1](PROTECTED-STARTUP-SHUTDOWN-LIFECYCLE-V1.md) | 网络模式与 Claude 会话的两个状态机 |
| 真实数据实验 | [REAL-DATA-ADVERSARIAL-ASSURANCE](REAL-DATA-ADVERSARIAL-ASSURANCE.md) | Claude 信息访问限制、真实内容对抗实验和数据流边界 |
| 自评/画像 | [ASSURANCE-AND-EXPOSURE-PROFILING](ASSURANCE-AND-EXPOSURE-PROFILING.md) | 可信自评、泄露字段和画像推断合同 |
| 过程索引 | [STATUS](STATUS.md) | 按时间组织的开发过程、修复和失败记录 |
| 验收账本 | [PROJECT-ACCEPTANCE](PROJECT-ACCEPTANCE.md) | 按能力和范围记录 PASS/FAIL/UNKNOWN/NOT_RUN |
| 文档地图 | 本页 | 文件分类、历史文档使用规则和公开内容治理 |

### 文档效力

1. SECURITY-REQUIREMENTS 定义“应该达到什么”。
2. NETWORK-SCOPE 和生命周期文档把需求拆成机制与验收条件，不得降低正式需求。
3. CURRENT-STATE 只说明“现在实际到哪里”，不得把设计写成实现。
4. STATUS 和 PROJECT-ACCEPTANCE 保存历史事实；历史中的“当前”“暂停”“授权”只对记录时点有效。
5. 专题源码说明只解释对应机制，不可自行授予系统操作或 Claude 启动许可。

## 2. 按主题浏览

### 2.1 产品架构、生命周期与恢复

- ARCHITECTURE-MAINTENANCE-20261107.md
- ARTIFACT-LIFECYCLE.md
- CENTER-PROJECT-FLOW.md
- PROTECTED-SESSION-CHAIN.md
- PROTECTED-STARTUP-SHUTDOWN-LIFECYCLE-V1.md
- SECURE-LIFECYCLE-SOURCE.md
- LIFECYCLE-RECOVERY-SOURCE.md
- CREATION-IDENTITY-SOURCE.md
- COMPLETION-RECOVERY-SOURCE.md
- EXACT-UNINSTALL-SOURCE.md
- PENDING-WRITE-CLEANUP-SOURCE.md
- OWNED-JOB-SOURCE.md
- RUNTIME-WATCHDOG-SOURCE.md

### 2.2 网络、代理、WFP 与隐私

- NETWORK-SCOPE.md
- PERSISTENT-FENCE-SOURCE.md
- WFP-RECOVERY-PROTOCOL.md
- LOCAL-MANAGEMENT-BOUNDARY-20261107.md
- NETWORK-QUALIFICATION-20261027.md
- PROXY-TLS-PRIVACY-20261031.md
- TLS-REVOCATION-SOURCE.md
- SCHANNEL-FAILURE-BOUNDARY-20261107.md
- FIXED-NO-CONTENT-HTTPS-CANARY-20261106.md
- AFD-TRANSPORT-CREATE-DIAGNOSIS-20261106.md
- HOST-PRIVACY-AUDIT-DIRECTION-20261102.md
- HOST-PRIVACY-EXECUTION-SEAL.md
- HOST-PRIVACY-NAMED-RESOURCES-20261101.md
- REAL-DATA-ADVERSARIAL-ASSURANCE.md
- ASSURANCE-AND-EXPOSURE-PROFILING.md
- POWERSHELL-ETW-REGISTRATION-METADATA-20261031.md
- POWERSHELL-ETW-SECURITY-EVIDENCE-20261031.md

### 2.3 工作区、Git、开发工具与 GPU

- WORKSPACE-TRANSFER.md
- CENTER-WORKSPACE-RESULTS.md
- CALLER-CSHARP-PROJECTS.md
- BUNDLED-PROJECT-DEVELOPMENT.md
- BROKER-OFFLINE-BUILD-SCOPE.md
- OFFICIAL-CLAUDE-OFFLINE-QUALIFICATION.md
- LPAC-TOOL-LAUNCH-NEXT.md
- GPU-HOST-REFERENCE.md
- OWNED-OBJECT-DEFAULT-DACL-CANDIDATE-20261105.md

### 2.4 本机验证、源码审查与许可证

- LOCAL-OPERATING-BASELINE.md — 2026-11-04 本机网络操作基线，已被全机公网出口模式取代。
- LOCAL-VALIDATION-PLAN.md — 本机分阶段验证和系统操作边界历史计划。
- SECURITY-SOURCE-REVIEW.md — 早期静态源码审查记录。
- SECURITY-REVIEW-20261112.md — 静态构建边界复核；不是完整产品安全审计或公开发布审计。
- UPSTREAM-REUSE-20261026.md — 固定上游来源复用审查。
- UPSTREAM-REVIEW.md — 开源参考项目审查。
- UPSTREAM-LICENSE.txt — 上游许可证文本，不等于本仓库根目录许可证。

### 2.5 历史决策、事件、迁移和交接

以下文件按日期保存当时事实，不再作为现行需求入口：

- PRODUCT-DIRECTION-20261026.md
- PRODUCT-DIRECTION-20261027.md
- PRODUCT-DIRECTION-20261028.md
- INTEGRATION-20261027.md
- MIGRATION-20261031.md
- VALIDATION-S1-S2-20261026.md
- PRIVACY-PREFLIGHT-HANDOFF-20261027.md
- WATCHDOG-MEMBERSHIP-HANDOFF-20261027.md
- AGENTS-HISTORY-20261102.md
- STATUS-HISTORY-20261027.md
- STATUS-HISTORY-20261102.md
- INCIDENT-20261025-KASPERSKY.md
- INCIDENT-20261025-PROXY.md
- INCIDENT-20261027-CODEX-SYSTEM-WATCHER.md
- INCIDENT-20261027-SYSTEM-CRASH.md
- INCIDENT-20261029-SYSTEM-CRASH.md
- CURRENT-STATE-HISTORY-20261112.md — 旧版长篇 CURRENT-STATE 快照，仅供追溯，不代表当前状态。

## 3. 历史文档和证据规则

- 日期文档中的“当前”只表示其记录日期，不代表当前安装、当前分支或当前授权。
- 不把历史失败改写成成功，也不把历史成功自动迁移到新工件。
- 不删除原始失败记录、哈希或边界说明来制造表面进度；需要纠错时新增带日期的更正，并保留原记录。
- STATUS 是过程索引；PROJECT-ACCEPTANCE 是能力证据账本；两者可以详尽，CURRENT-STATE 必须保持精简。

## 4. 公开仓库内容治理

本仓库当前为 Public。历史文档部分形成于私有研发阶段，可能含有本机环境观察、历史路径、对象摘要和当时的个人操作上下文。**本次文档重组不等于完整公开内容审计，也不证明全部历史提交、PR、Actions 日志和 Artifacts 适合公开。**

- 新增公开文档不得包含真实公网 IP、MAC/BSSID、SSID、设备 UUID/序列号、个人路径、代理凭据、认证令牌或原始连接/崩溃日志。
- SECURITY-REVIEW-20261112 是静态产品构建边界检查，不是 Secret Scanning、完整历史审计或公开发布审计。
- 根目录未发现 LICENSE；在完成所有权、依赖和上游许可证核查前，不宣称本仓库已获 MIT/Apache 等许可。
- 如需清除已提交的真实秘密或个人标识，必须单独制定凭据轮换、历史重写、分支/PR/缓存/Artifacts 清理方案；仅删除当前文件不等于从公开历史移除。
