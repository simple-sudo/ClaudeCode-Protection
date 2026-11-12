# ClaudeCode-Protection

**面向 Windows 的原生 Claude 开发保护系统：在保留本机开发与 GPU 能力的前提下，隔离 Claude 可访问的宿主资源，并在保护模式启用期间强制全机公网流量经过指定 FlClash 美国代理。**

> **项目状态：研发中，不是正式安全产品。** 当前源码、CI 与历史实机证据只覆盖各自明确的范围；真实 Claude 完整会话、全机公网出口强制代理、完整宿主隐私隔离、故障恢复和 GPU 身份隔离尚未完成整体验收。不要将当前分支或测试包当作可直接部署的完整保护产品。

> **仓库状态：当前为 Public。** 当前基线未发现根目录 LICENSE。公开可见不等于授予代码复用许可；在许可证审查和正式发布流程完成前，不要宣称本仓库已经采用某种开源许可证。历史研究文档也尚未完成全面公开内容审计。

## 1. 项目目标

Claude Code 不只是远端聊天界面。它会在本机调用 Shell、Git、Python、Node.js、MCP、编译器和其他开发工具。因此，保护目标同时包括：

1. **本机资源访问**：Claude 及其工具链只能访问明确授权的项目、工具和设备资源，不能因此取得整个 Windows 用户环境的权限。
2. **网络出口**：保护模式启用期间，全机公网出口统一经过用户指定的 FlClash 美国住宅代理；任何应用或系统服务都不能因进程名称、域名或协议不同而直连。
3. **数据外传**：代理只控制网络路径，不会自动阻止应用把已读取的数据经允许的代理连接发送出去。必须同时限制本机敏感数据读取，并验证目的地和实际数据流。
4. **保护系统自身**：Claude 及派生工具不能读取、篡改、停止或卸载可信管理面、内部配置、凭据和运行状态。
5. **开发能力**：保留授权项目开发、Git、编译、测试及本机 NVIDIA GPU/CUDA 能力；不以完整虚拟机或 CPU-only 作为默认替代方案。

本项目优先采用 Windows 原生进程与资源隔离，而不是把 Claude 放进传统虚拟机。原生隔离是否兼容具体驱动、GPU 和工具链，必须以实际证据逐项确认。

## 2. 三个相互独立的保护平面

### 2.1 全机公网出口强制代理（当前正式目标，尚未实现完整产品链）

当用户明确启用 Protection 网络模式时：

- 全机应用和 Windows 服务产生的公网 IPv4/IPv6 流量都必须经过 FlClash TUN 与 Global 代理路径。
- FlClash 只允许连接当前经可信核验的指定代理端点；物理网卡上不得存在其他未授权公网直连。
- DNS、TCP、UDP、QUIC、IPv6 和其他协议都必须纳入策略。代理不支持的协议应阻断，不能回退 DIRECT。
- 代理、TUN、节点、策略或监督组件故障时，持久出口屏障继续阻断公网直连。
- 只允许严格限定的本机控制面和网络引导通信；不得把整个局域网或某个远程软件设成宽泛直连例外。

这不是只给 Claude 设置 HTTP_PROXY，也不是只检查 FlClash 是否显示 Global。FlClash 负责流量接管和转发，Protection 必须通过 Windows 网络强制边界验证并阻断绕过路径。

### 2.2 Claude 本机资源隔离

使用 AppContainer/LPAC、受保护 DACL、Broker、Job、WFP、可信 Owner 和精确生命周期管理等机制，限制 Claude 主进程、派生工具、MCP、Hooks、后台组件及独立辅助进程的真实权限。

网络出口控制不能替代文件、注册表、进程对象、设备 API、服务、代理管理接口和保护系统自身的访问控制。

### 2.3 数据外传与可见面控制

即使所有公网连接都经过美国代理，Claude 仍可能先读取本机 SSID、路由、设备标识、时区或其他环境数据，再通过合法代理发送出去。因此：

- 本机敏感信息读取限制必须独立验收。
- 网络目的地控制和数据流审计必须独立验收。
- 美国代理出口不代表设备真实位于美国，也不代表代理服务商看不到来源连接。
- 本项目不承诺完全匿名或消除所有侧信道。

## 3. Protection 网络模式的生命周期

| 状态 | 目标行为 |
|---|---|
| INACTIVE | 不改变用户现有网络配置；不持有活动中的全机出口阻断策略 |
| PREPARING | 先建立持久阻断，再核验 FlClash 身份、TUN、Global、代理端点、DNS 和出口资格 |
| ACTIVE | 全机公网流量统一走指定代理；所有未授权直连被 Windows 强制阻断 |
| DEGRADED | 代理或策略异常时关闭公网转发、撤销 Claude 会话许可并保持阻断；不自动直连 |
| SESSION_STOPPED / ACTIVE | Claude 会话可以结束，但用户可选择继续保持全机代理模式 |
| EXIT_PENDING | 只有用户明确退出 Protection 网络模式后，才精确撤销本产品拥有的规则并恢复原有网络行为 |

FlClash 由用户管理。Protection 不擅自切换节点或关闭代理。用户关闭 Claude 不应自动关闭 FlClash，也不应自动解除仍在使用的全机代理保护。

## 4. 兼容性要求

- **UU 远程**：不得因维持远程连接而开放公网直连例外。用户已观察到 UU 在 FlClash Global 美国代理开启时能够正常使用；这只证明应用层面可用，不证明 UU 的所有 TCP/UDP/P2P/中继流量均经过代理。必须通过连接归属和实际网络路径测试。
- **GPU**：保护模式应保留本机 NVIDIA 计算能力；CUDA、NVML、WDDM、PnP 与硬件唯一标识分别验收。
- **开发工具**：PowerShell、Git、Python、Node.js、MCP、编译器和依赖管理工具不得成为身份或网络旁路。
- **局域网和系统控制面**：ARP、DHCP、IPv6 邻居发现等必要链路通信不能被误称为公网代理流量；例外必须最小化、明确记录并验证。不得因此放行宽泛 RFC1918 局域网访问。

## 5. 系统结构

| 组件 | 职责 |
|---|---|
| Protection Center | 展示状态、用户操作和可信检查结果 |
| Daily CLI | 普通用户环境检查与限定维护入口 |
| Bootstrap | 安装包完整性、版本与批准清单核验 |
| Broker | 执行明确范围的可信系统管理动作，不提供通用提权 Shell |
| ProtectionLifecycle | AppContainer/LPAC、Job、WFP、网关、租约、状态和恢复 |
| NativeFence | Windows 原生网络过滤实现与实验 |
| Tests / Scripts | 自动化回归、静态边界检查和受控验证 |

## 6. 当前实现与证据边界

- 已有 WFP 持久隔离、受保护身份、代理身份核验、固定会话网关、路由观察、工作区/Git 数据处理及部分 NTFS/恢复验证。
- 当前 SessionProxy 的固定资格通路不是全机通用代理，也不是所有 Claude 域名的完整生产网络通道。
- 当前 CI 通过不等于真实产品 Broker、Owned Job、LPAC、真实 Claude 或全机网络出口已通过。
- **2026-11-12 新增的全机公网出口强制代理是正式需求与架构设计，状态为 REQUIREMENT_ONLY / DESIGN；尚未完成产品实现和 Windows 实机验收。**
- 当前开发基线、最新 CI、安装观察与缺口见 [CURRENT-STATE](docs/CURRENT-STATE.md)。

## 7. 证据规则

使用 REQUIREMENT_ONLY / DESIGN、SOURCE、BUILD、INTEGRATED、VERIFIED(scope)、CAPABILITY_DELIVERED(scope) 和 PRODUCT_DELIVERY_ACCEPTED 区分设计、源码、构建、接线、限定实测和完整产品交付。普通用户测试、管理员 NTFS fixture、实际 LPAC token、产品 Broker 和真实 Claude 会话不可相互冒充。

真实主机 IP/IPv6、MAC/BSSID、SSID、设备标识、私人路径、SID/ACL、代理/远控元数据、原始命令输出、日志和失败回执，均可能是必要的研发证据；设备所有者已明确接受将必要真实证据写入当前 Public GitHub 仓库。不得以默认脱敏替代真实实验，也不得将真实值伪装成合成结果。原始证据、来源、时间、执行身份、工件 SHA、哈希和分析结论应可追溯。可直接认证或重放的密码、Token、Cookie、私钥、签名密钥和代理订阅凭据仍须独立管理，不作为普通证据原值提交。研发者获准分析真实证据，不意味着 Claude 受限执行域获准访问。完整规则见 [EVIDENCE-GOVERNANCE](docs/EVIDENCE-GOVERNANCE.md)。

## 8. 文档入口

真实开发证据与敏感信息的采集、GitHub 保存、原值审阅和凭据边界见 [EVIDENCE-GOVERNANCE](docs/EVIDENCE-GOVERNANCE.md)。

从 [文档索引](docs/DOCUMENTATION-INDEX.md) 开始。正式需求以 [SECURITY-REQUIREMENTS](docs/SECURITY-REQUIREMENTS.md) 为准；网络设计以 [NETWORK-SCOPE](docs/NETWORK-SCOPE.md) 为准；启动/退出设计见 [PROTECTED-STARTUP-SHUTDOWN-LIFECYCLE-V1](docs/PROTECTED-STARTUP-SHUTDOWN-LIFECYCLE-V1.md)。历史记录不能覆盖最新需求，也不能授予操作许可。
