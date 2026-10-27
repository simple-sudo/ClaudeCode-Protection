# ClaudeCode-Protection

**面向 Windows 的 Claude 进程安全隔离与网络保护项目。**

> **开发中 · 尚无可供日常使用的正式保护版本。** 本仓库已有真实安装、WFP 规则和受限测试进程的部分验证，但**尚未完成真实 Claude 会话的持续网络保护、宿主机信息隔离及完整故障恢复验收**。请勿将当前代码当作已通过安全认证的一键保护工具。
>
> 当前实现状态以 [docs/STATUS.md](docs/STATUS.md) 为准；本 README 主要面向新成员和合作开发者，介绍长期目标、架构与参与方式。

## 1. 我们想解决什么问题？

Claude Code 不只是聊天程序，它可以读取代码、调用终端、启动子进程、使用 Git/Node.js/Python、运行测试，甚至参与需要 GPU 的开发任务。

这些能力很有价值，但也带来一个问题：**AI 开发工具所需要的项目权限，不应该自动等于 Windows 宿主机的全部权限。**

ClaudeCode-Protection 希望在**不明显牺牲正常开发能力**的前提下，提供由操作系统强制执行的保护边界：

- **网络保护**：受保护进程只能使用已授权的网络通道；代理不可用、策略异常时不自动回退到未经授权的直接外联（fail-closed）。
- **进程与数据隔离**：受保护进程及其工具、子进程不应访问无关的宿主机文件、代理节点配置、订阅凭据、代理管理接口等敏感资源。
- **完整开发能力**：尽可能保留终端、文件操作、Git、编译器、包管理器、MCP / Hooks 等真实开发工作流。
- **本机 GPU 计算**：优先探索 Windows 原生隔离，保留 NVIDIA CUDA / PyTorch 等本机 GPU 工作负载的可用性；**兼容性尚需实际验证**，不把传统虚拟机作为默认部署前提。
- **安全生命周期**：从安装、启动准入、运行监控，到停止、更新、恢复、卸载，都要明确权限、资源归属和失败状态。
- **不打扰日常使用**：尽量不改动全机网络环境；不因保护 Claude 而破坏 FlClash、浏览器、其他开发工具或用户的正常工作。

**初期重点是 Windows + FlClash + Claude Code。** 长期规划逐步覆盖受保护的 Claude Desktop、辅助程序、Agent、MCP、Hooks 等相关进程。它们的创建方式与身份可能不同，因此不会单纯靠扫描进程名称就宣称“全部受保护”。网页版涉及共享浏览器，不会不加区分地封锁整个 Edge / Chrome。

## 2. 预期如何工作？

下面是**目标架构示意**，不是当前版本已全部实现的运行链路：

```text
Windows 宿主机（正常运行）
├─ FlClash / 网络与代理配置 / 其他日常软件
│
├─ ClaudeCode-Protection
│  ├─ Protection Center：普通用户界面、检查与状态展示
│  ├─ Bootstrap / Broker：受约束的安装、管理与启动操作
│  ├─ Lifecycle：包验证、状态记录、恢复与清理
│  └─ Windows 原生安全机制
│     ├─ AppContainer：隔离身份和访问权限
│     ├─ Job Object：受保护进程及子进程生命周期
│     └─ WFP：按隔离身份限制网络连接
│
└─ 受保护的 Claude 开发环境（目标）
   ├─ Claude Code / 未来经验证的 Claude 组件
   ├─ PowerShell / Node.js / Git / Python / 编译工具
   ├─ 已授权的项目目录与开发资源
   ├─ 经过保护的网络访问 → 受信任网关 → FlClash
   └─ 按需使用本机 GPU（待兼容性验证）
```

基本原则是**启动前约束优先于启动后补救**：先建立可核验的隔离身份、进程归属和网络策略，再允许目标进程执行。网络规则、工具调用、文件权限和进程生命周期需要共同满足要求，单独启用防火墙规则并不等于完成全部保护。

目前源码中的代理端点主要针对本机 `127.0.0.1:7890`；它是现阶段测试基线，**不是已经完成的透明代理/隐藏代理元数据方案**。未来要将“允许联网”和“允许读取节点、订阅、管理 API”明确分开。

## 3. 当前进展（2026-10-27）

以下是 GitHub `main` 在提交 `31994ee` 附近的**已记录状态**。研发持续推进，后续请以 [实时状态账本](docs/STATUS.md) 为准。

| 领域 | 已取得的进展 | 尚不能宣称 |
| --- | --- | --- |
| 安装与界面 | 已在开发机完成一次受保护目录下的**未激活安装**；普通用户 WPF 界面能调用已安装 CLI 执行离线环境检查并保存报告 | 已发布通用安装包，或能够一键开启完整保护 |
| 安装文件安全 | 已核对限定安装包文件的摘要、所有权与部分普通用户权限拒绝行为 | 覆盖所有攻击方式、异常中断与重启 |
| WFP 网络屏障 | 已提交并独立回读 **6 条安装专属持久过滤规则** | 所有真实网络路径已验证无泄漏 |
| 进程启动准入 | 自有**无网络 canary 测试程序**已验证：创建时绑定 AppContainer 身份与 Job，检查完成后首次恢复执行，结束后核对 Job 清零 | Claude Code 及复杂工具链已经兼容 |
| 代理审核与网络资格测试 | 已接入特定 FlClash 身份核对、指定 IPv4 代理开放，以及 TCP / UDP / IPv6 / 受控 DNS 的测试矩阵；新代码已完成限定离线构建 | 新网络矩阵已经在安装环境中通过实际运行测试 |
| 故障监控与恢复 | 有 WFP、Job、恢复账本与生命周期基础代码 | 代理故障、控制器崩溃、系统重启和安全卸载全部通过验收 |
| 宿主机敏感信息隔离 | AppContainer 安全身份已有实验与准入基础 | Claude 无法读取 FlClash 节点、订阅、管理 API 或无关进程信息 |
| GPU / CUDA | 已纳入产品兼容性目标 | AppContainer 下的 CUDA、PyTorch、驱动接口与权限边界已验证 |
| 真实 Claude 会话 | **按项目当前要求延期**，不登录 Claude 账号、不以真实推理作为本阶段前置条件 | 已完成真实 Claude 保护验收 |

**重要：SOURCE、BUILD、INTEGRATED、VERIFIED 和 DELIVERABLE 是不同的证据级别。** 源码存在、编译成功、受控 canary 通过，都不能直接推导为整个产品已经安全可用。详细记录及历史失败见 [开发状态](docs/STATUS.md) 和 [验收账本](docs/PROJECT-ACCEPTANCE.md)。

## 4. 保护范围与明确的技术边界

**计划保护的对象**

- 经可信入口启动的 Claude Code，以及其明确归属的命令、工具和子进程。
- 未来经适配的 Claude Desktop 与独立辅助组件；不同组件需要分别证明身份绑定和权限继承。
- 宿主机未授权的代理配置、订阅凭据、代理管理接口、个人文件和敏感进程对象。
- 受保护身份的 IPv4 / IPv6、TCP / UDP、DNS 及其他潜在网络旁路。

**不作出的承诺**

- 不承诺完全隐藏公网代理出口 IP 或阻止远端服务根据连接特征作出推断。
- 不宣称 Windows 原生隔离能让所有系统信息、设备元数据和侧信道“绝对不可见”；具体保护范围必须通过权限和负向测试证明。
- 不把关闭整机 IPv6、修改时区、重置 DNS / 系统代理作为默认保护手段。此类系统级操作只有在明确必要、用户主动授权、可核验且可恢复时才考虑。
- 不用“进程名包含 Claude”作为可信身份或强制终止整组进程的依据；也不默认接管共享浏览器。
- 不把本项目用于绕过第三方服务的规则、身份验证或安全机制；目标是保护本机资源和网络边界。

详见 [网络保护范围](docs/NETWORK-SCOPE.md) 与 [产品目标与原则](docs/PRODUCT-DIRECTION-20261026.md)。其中部分文件是历史决策记录，后续范围变化以最新审查结论为准。

## 5. 代码结构

| 路径 | 主要用途 |
| --- | --- |
| [src/ProtectionCenter](src/ProtectionCenter) | WPF 图形界面：环境检查、用户操作与状态展示 |
| [src/ClaudeProtection](src/ClaudeProtection) | 日常 CLI：环境与代理检查、用户配置维护 |
| [src/ProtectionLifecycle](src/ProtectionLifecycle) | 安装生命周期、安全状态、AppContainer / Job / WFP、代理与网络资格逻辑 |
| [src/ProtectionBroker](src/ProtectionBroker) | 受约束的管理端入口 |
| [src/ProtectionBootstrap](src/ProtectionBootstrap) | 安装引导与固定包批准 |
| [src/ClaudeProtection.Engineering](src/ClaudeProtection.Engineering) | 独立工程实验，不属于日常生产入口 |
| [src/NativeFence](src/NativeFence) | 较早的原生 WFP 探针与辅助源码 |
| [scripts](scripts) | 构建、环境审计和受限资格验证脚本；**不是全部可直接运行的通用安装脚本** |
| [tests](tests) | 协议与静态检查 |
| [docs](docs) | 当前状态、验收记录、架构决策及故障记录 |

项目主体使用 **C# / .NET 8（Windows）**、WPF、PowerShell 和 Windows 原生 API。网络保护以 WFP 为核心，进程控制主要使用 AppContainer 与 Job Object。当前不以引入完整虚拟机或额外大型运行时作为默认方案。

## 6. 合作开发者如何开始？

### 获取与阅读

仓库目前是私有仓库。请先获得访问权限，再在 Windows 开发机上克隆：

```powershell
git clone https://github.com/simple-sudo/ClaudeCode-Protection.git
cd ClaudeCode-Protection
```

建议按以下顺序阅读：

1. **本 README**：项目价值、目标、架构与当前边界。
2. [docs/STATUS.md](docs/STATUS.md)：**最新实际进展、可运行证据及剩余缺口**。
3. [docs/PRODUCT-DIRECTION-20261026.md](docs/PRODUCT-DIRECTION-20261026.md) 和 [docs/NETWORK-SCOPE.md](docs/NETWORK-SCOPE.md)：产品原则与网络设计范围。
4. [AGENTS.md](AGENTS.md)：本项目自动化开发、提交、安全限制与证据分级规则。
5. [docs/PROJECT-ACCEPTANCE.md](docs/PROJECT-ACCEPTANCE.md)：完整历史账本。按时间阅读，旧结论不自动覆盖新实现。

### 开发环境与安全检查

当前曾用于开发验证的环境包括 Windows、PowerShell 7.4+、.NET SDK 8.0.422，以及相应的 .NET 8 Windows 引用组件。**这是已记录的研发环境，不意味着程序已支持所有 Windows/.NET 版本组合。**

在依赖齐备的受控开发环境中，可运行仓库现有的**无产物源码语义检查**：

```powershell
pwsh -NoProfile -File scripts/Check-SourceTypes.ps1
```

这个检查不执行产品程序，也不等同于真实构建、安装或安全验收。它有自己的 SDK、引用组件和简单项目结构假设；失败时应记录原因，而不是将其当成产品运行结果。

**不要直接将根目录的构建、保护、探针、管理员脚本当作安全的一键使用命令。** 某些入口仍保留限制或用于特定历史资格批次；涉及 WFP、提权、AppContainer、系统设置或故障注入的操作，必须先看对应的范围与安全条件。

### 推荐协作方式

- 按可交付的功能链工作，例如“隔离启动 → 授权网络 → 故障阻断 → 恢复”，尽量复用现有模块；不要只增加暂时无法接入产品的接口、协议或测试框架。
- 将功能变更与证据记录联系起来：清楚说明本次实现了什么、实际验证了什么、哪些仍是 UNKNOWN / BLOCKED。
- 新成员建议在独立分支提交小范围改动，通过 Pull Request 讨论并合并；**不要覆盖他人的未提交工作，也不要强制推送 `main`**。现有 Codex 本地工作流遵循 [AGENTS.md](AGENTS.md)，不自动代用户推送远端。
- 不提交账号凭据、代理订阅、节点信息、认证文件、用户配置备份、日志、运行状态、构建产物及私人数据。仓库的 [.gitignore](.gitignore) 有基础排除规则，但不能代替提交前审查。
- 遇到真实安全软件告警、系统网络异常、权限隔离失败时先停止相关实验，保存证据，避免通过关闭防护或绕开检查来“让测试变绿”。

## 7. 接下来重点建设什么？

产品主线是**把已有安全基础连成可安装、可使用、可恢复的完整程序**，而不是无限扩展独立研究组件：

1. 让已构建的代理准入和 TCP / UDP / DNS / IPv6 网络资格逻辑获得明确的实际运行证据，验证网络屏障真正有效。
2. 完整实现代理失效、规则漂移、守护异常、控制器中断时的 fail-closed 与精确恢复。
3. 从自有 canary 逐步拓展到真实工具进程及 Claude Code，再覆盖经确认的其他 Claude 组件和子进程。
4. 建立可执行的敏感信息访问限制，证明受保护进程无法读取未授权的 FlClash 节点、订阅、管理 API、私有文件和进程信息。
5. 单独验证 **NVIDIA CUDA / PyTorch 与正常 AI 开发工具链**，在隔离强度与 GPU 能力之间寻找可维护的 Windows 原生实现。
6. 完成安装、更新、回滚、重启后恢复、卸载、用户界面以及最终真实使用场景的验收。

这是一份**方向说明，而非强制的线性任务清单**。实现顺序、架构演进和开源组件复用可由开发者根据实际证据调整，但应始终使真实产品可用性与研发投入同步提升。

## 8. 安全说明与文档索引

项目曾在旧综合测试程序上遇到卡巴斯基 `PDM:Trojan.Win32.Generic` 告警，原因尚无最终鉴定。旧样本不应恢复或重跑，也不应通过关闭安全软件、添加排除项或重新包装规避检测。相关经过与现有准入约束见 [安全事件记录](docs/INCIDENT-20261025-KASPERSKY.md)。

补充技术资料：

- [当前开发状态与运行证据](docs/STATUS.md)
- [完整验收账本](docs/PROJECT-ACCEPTANCE.md)
- [网络范围](docs/NETWORK-SCOPE.md)
- [产品目标](docs/PRODUCT-DIRECTION-20261026.md)
- [安装与安全生命周期](docs/SECURE-LIFECYCLE-SOURCE.md)
- [WFP 规则与恢复](docs/PERSISTENT-FENCE-SOURCE.md)
- [Job 与进程归属](docs/OWNED-JOB-SOURCE.md)
- [上游项目复用与许可审查](docs/UPSTREAM-REUSE-20261026.md)

本仓库当前为**私有协作开发仓库**。不要将引用的第三方 MIT / MS-PL 等许可证误认为整个仓库已获得统一的开源授权；对外分发与第三方代码复用须另外核对授权和许可证。

---

**项目的最终目标：让 Claude 在被授权的开发环境中保留足够强的编程、工具和 GPU 能力，同时不给它不必要的 Windows 宿主机权限。**
