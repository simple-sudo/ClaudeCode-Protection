# 受保护启动与安全退出生命周期 V1：开发与验收计划

> 2026-11-04 用户确认的新目标。**REQUIREMENT_ONLY / DESIGN / NOT_RUN**：本文仅改变需求与计划，未更改系统、未实现新 GUI、未安装规则、未启动真实 Claude。
> 权威安全需求：[SECURITY-REQUIREMENTS](SECURITY-REQUIREMENTS.md)；最新安装/失败/授权：[CURRENT-STATE](CURRENT-STATE.md)；历史证据仍以原版本和场景为限。本计划不构成 UAC、安装、全机网络更改或真实 Claude 启动许可。

## 2026-11-04 新增安全前置：真实敏感数据强制实验

本生命周期的 P0-HOST/NET/SELF/ASSURANCE 验收遵循
[真实敏感数据强制对抗实验规范](REAL-DATA-ADVERSARIAL-ASSURANCE.md)。
用户允许 Codex/ChatGPT 充分读取和分析本人真实宿主指纹、物理网络、FlClash/UU 等信息作为研发数据；
不得因为它们“对 Claude 敏感”或开发模型在云端就改用模拟测试。
完成 GUI、IPv6 门和网络准入设计/源码不构成宿主隐私通过：
关键目标必须用与 Claude 等价的**实际受限身份**尝试获取真实内容，
由可信 owner 记录原值、来源、跨源画像和实际拒绝；L3 未完成不得把正式 Claude 会话列为验收通过。
开发者的真实数据访问权不得转交正式 Claude，原始实验信息不自动发布到 GitHub/CI/Anthropic 通道。
本段是 REQUIREMENT_ONLY / NOT_RUN，不解除现有正式启动和高影响系统操作门禁。

## 1. 三个独立控制面

### 2026-11-05 协调源码切片（不是原生交付）

新增`ProtectedLifecycleCoordinator`编入保护库，限定五类用户请求、flow/revision顺序、
原owner准入引用及必需停止/恢复条件。`IProtectedLifecycleOwner`是未来可信原生适配器
合同，没有生产实现或运行调用点；fixture的布尔观测不能成为产品真实证据。原生适配器
必须复用原ProtectedState/VerifiedVersion/ProtectedSession/Job/WFP及可信IPC：Prepare
真实阻断并回读，Check/Start真实复核P0与人类许可，Stop精确关闭并排空且识别未知actor，
Restore重新核验用户主动关闭代理且只撤销拥有的临时规则、永久Claude屏障仍有效。

协调层不接受路径/PID/脚本/ACL或代理开关参数；报告的LaunchAuthority恒为false。过期
和重放请求不能启动；故障及组件释放只触发原owner有界关闭，不自动恢复IPv6，失败Stop
不重试。重启有未核对拥有门或UNKNOWN直接锁闭，不能以报告恢复或认领资源。源码由
普通L1场景检查，真实原生门、外部Claude屏障、GUI交互/崩溃/恢复仍NOT_RUN。

| 控制面 | 目标、拥有者与不可交换的边界 |
| --- | --- |
| **Claude 永久防直连（P0-CLAUDE-FENCE）** | 原可信 owner/WFP/受限身份/Job 在任何代理与 IPv6 状态下阻止官方 Claude Code 和所有纳管派生工具、MCP/Hooks、后台组件通过宿主 Wi-Fi/IPv4/IPv6/DNS/UDP 非授权路径直连。恢复普通 Windows IPv6 绝不解除此屏障；外部启动/脱离 Job 的 Claude 必须另外受控制与验收，不能仅按进程名称猜测已纳管。 |
| **全机 IPv6 临时外联门（P0-HOST-IPV6-GATE）** | 用户主动请求“准备启动”后由可信服务启用并回读全机未经授权的原生 IPv6 **出站通信阻断**；用户完成安全退出、手动关闭 FlClash 后再请求恢复，只撤销本安装拥有的临时 IPv6 规则。不得卸载 Windows IPv6、禁用适配器或重置全机网络；必要链路本地/隧道基础通信单独界定、验证且不得成为公网直连例外。 |
| **FlClash Global + TUN（P0-PROXY-EGRESS）** | 用户手动开启、选择美国住宅代理、手动关闭。保护程序验证代理入口、出口与系统 DNS/IPv4/UDP/路由/IPv6 状态，但不自动开关 FlClash、不切节点、不替代代理核心。目标是所有应代理的互联网流量正常使用指定出口；系统基础链路、隧道建立与明确例外另行审查，不把 Global/TUN 或单次公网 IP 检测视为全机无旁路证明。 |

网络可用性与 P0-HOST/SELF 隐私隔离同为必须通过的条件；不能为了修 Winsock 或使用 GPU 而开放敏感 registryRead、FlClash/UU 数据、真实设备唯一标识及跨来源画像线索。可信宿主维护可以保留，但不能让 Claude 取得通用管理员通道。

## 2. 用户明确确认的启动顺序

1. 用户打开 **ClaudeCode-Protection**，点击 **「准备启动」**。可信 owner 先核验 Claude 持久防直连，再施加、持有并回读全机原生 IPv6 出站阻断；失败/UNKNOWN 不显示可继续。
2. GUI 提示“**可手动打开 FlClash**”。用户自己启动 FlClash，选择美国住宅节点、Global + TUN；本程序不操作 FlClash。
3. 用户返回 GUI 点击 **「开始检查」**。可信 owner 重新检查规则、代理健康、实际出口/路由/DNS、原十四项环境准入、P0-HOST/NET/SELF、工具/工作区与权限边界；FAIL、UNKNOWN、过期均不授予启动权。
4. 检查合格后 GUI 才启用 **「启动 Claude Code」**。原 InstalledBroker → ProtectedSession → LPAC/Job/WFP → Gateway/Watchdog 原子创建受保护官方 CLI；在恢复首次执行前复核资格并约束全部纳管相关进程。禁止先从普通终端启动 Claude 再追加沙箱。

## 3. 用户明确确认的退出和 IPv6 恢复顺序

1. 用户在 GUI 点击 **「一键关闭所有 Claude 进程」**；由原可信 owner 先撤销会话准入、关闭转发并保持强制隔离，再精确终止持有且身份可验证的根进程、Job 成员与工具，并核验旧连接、隧道排空、未知/未纳管进程与停止错误。
2. **只有确实证明安全关闭**，GUI 才显示“**可以手动关闭 FlClash**”。若发现未知进程、脱离 Job、连接残留、服务/规则漂移或无法证明，报告 BLOCKED/UNKNOWN，不能提示安全关闭。不要靠按名称强杀未知进程制造成功。
3. 用户可选择**继续保留 FlClash**，此时全机 IPv6 临时阻断仍有效；或者自己关闭 FlClash，之后返回 GUI 点击 **「恢复 IPv6」**。
4. 恢复前可信 owner **再次**核验无获准或遗漏的 Claude 会话、永久 Claude 防直连仍有效、临时 IPv6 规则属于本安装且未漂移、连接关闭与恢复账本一致；只撤销本次拥有的全机 IPv6 阻断并回读。恢复失败则保持阻断并报告，不修改 FlClash/UU/代理配置。恢复后普通 Windows 可使用 IPv6，但 Claude 不得直连。

## 4. 与主动关闭不同的故障路径

代理节点、FlClash Core、TUN、路由、DNS、WFP/owner/Watchdog 健康异常或配置漂移时进入 **FAULT_LOCKDOWN**：
- 预先存在且有效的 OS 强制屏障应拒绝任意未授权直连，不能只靠监控轮询“尽快发现”来防泄露。
- 立即撤销准入、关闭网关和已有上游/转发，依原持有的身份/Job 尽快终止全部纳管 Claude 进程族，原子性和连接重授权须验证；不承诺零毫秒全部退出，但不得存在可用的直接网络后备路径。
- **不自动恢复 IPv6**；故障不是用户主动关闭 FlClash，只有用户在安全退出并自行关闭代理后显式触发恢复步骤。
- GUI 退出、Broker/Watchdog 异常、系统重启、旧连接存活、BFE 故障、规则丢失/竞争、任务失联必须分别测试；未知即拒绝准入，不能以进程消失/绿色报告推导清理成功。

## 5. GUI 状态与权限合同

| 状态 | 允许的用户动作 | 可信 owner 必须证明 |
| --- | --- | --- |
| IDLE / IPV6_RESTORED | 准备启动 | 无可用 Claude 非授权直连；已有未知状态必须标示 |
| PREPARING / WAIT_MANUAL_PROXY | 准备完成后手动开 FlClash | 临时 IPv6 外联阻断已安装、回读、可恢复 |
| PREFLIGHT_FAILED / READY_TO_LAUNCH | 检查失败重审；通过可启动 | 新鲜安装/token/Job/WFP/代理/P0/十四项准入，过期需重审 |
| PROTECTED_RUNNING | 安全退出 | 受限官方 Claude 与关联进程始终由可信 owner 持有监督 |
| STOPPING / SAFE_TO_CLOSE_PROXY | 停止已证实后手动关 FlClash | Admission 已撤销、隔离有效、Jobs 归零、连接排空与未知进程状态 |
| IPV6_RESTORE_PENDING / RESTORED | 显式恢复 IPv6 | 原 Claude 屏障有效、无会话/旁路、只撤销拥有的临时 IPv6 规则 |
| FAULT_LOCKDOWN | 显示故障/修复，拒绝启动和自动恢复 | 原生阻断持续有效，收敛为安全态并保留审计/恢复证据 |

这些是界面**设计状态**而非现有 GUI 功能；GUI 只是有限请求与状态展示层，不得自主授予权限、修改任意 WFP/ACL 或静默开启 FlClash。可信用户手动决定不等于跳过安全门禁。

## 6. 分阶段开发计划与交付标准

| 顺序 | 工作包 | 最小可交付验收 |
| --- | --- | --- |
| P0-1 | 复用现有 Broker/ProtectedSession 添加固定 GUI 状态机、有限 IPC、可信回执与恢复账本 | 状态机真实可操作；重复/乱序/恶意请求、GUI 崩溃/恢复、旧报告、UNKNOWN 按设计拒绝；不制造通用提升入口 |
| P0-2 | 分离永久 Claude WFP 屏障与用户启停的全机原生 IPv6 阻断 | 分别验证原有 Claude 防直连和全机 IPv6 拦截/恢复；规则所有权、重启/漂移、IPv4 与其他软件兼容；恢复 IPv6 后 Claude 仍拒绝直连 |
| P0-3 | FlClash Global/TUN 真实资格及受限 Winsock 初始化兼容 | 在不增加 P0 读取面的前提下定位现有 6800 的 SOCKET_STARTUP10107；一次真实授权 HTTPS 经代理成功，明确原生绕过拒绝；全机出口例外审查 |
| P0-4 | “一键关闭”进程族、连接与代理异常锁闭 | Held Job/子进程/MCP/未知外部 Claude、旧连接排空、错误中断、服务崩溃和用户人工关闭分别有正反证据；失败不释放 IPv6 |
| P0-5 | 真实官方 CLI 受保护开发与自评 | 经新的具体授权，白名单项目、真实 Git/依赖/编译与必要 GPU 的渐进验证；P0-HOST/NET/SELF 与自评画像报告仍需实证，缺项不得宣布完整产品验收 |

复用现有固定离线 C# 开发及失败回执，避免无限重复证明；报告清晰区分 SOURCE / BUILD / VERIFIED(scope) / CAPABILITY_DELIVERED(scope) / PRODUCT_DELIVERY_NOT_ACCEPTED。高影响系统操作、UAC、全机规则更改、故障注入和真实 Claude 启动必须另有具体人类决定，本次文档更新不授权执行。

## 7. 核心反例

- 恢复普通 IPv6 后，未获准 Claude 仍不能直连；已获准会话未闭合时不能恢复。
- 故障与用户主动关闭不是相同状态；故障保持 IPv6 拦截和网络关闭，不会误解锁。
- 代理关闭后，外部自行启动 Claude 或逃出原 Job 的组件不能构成直连旁路；未知则阻止“安全关闭”结论。
- 保持 FlClash 的情形不需要恢复 IPv6；全机代理正常不代表能读取节点/UU/设备/运营商/位置秘密。
- 不要把美国出口本身误当宿主位置证明，也不能用本机外网 IP 的单次检测证明所有进程无旁路。

最终验收仍须满足 [PROJECT-ACCEPTANCE](PROJECT-ACCEPTANCE.md) 的完整交付语义；当前产品未达到该状态。
