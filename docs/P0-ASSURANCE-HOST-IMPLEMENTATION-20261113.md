# P0-ASSURANCE + P0-HOST：实现与验收记录（2026-11-13）

状态：**PARTIAL_SOURCE_IMPLEMENTATION / PR #4 Draft**。本文件记录网页端独立开发分支的实现事实；不覆盖 Codex 网络主线的 CURRENT-STATE，也不表示整个 P0-ASSURANCE、P0-HOST 或产品已经交付。

- 开发分支：`chatgpt/p0-assurance-host-20261113`
- 当前分支 HEAD：`b7e9c080cfbb50f048a1fce820cfae3ee23c3d71`；最近完成代码验证的 HEAD：`f819ddfd05ac3e2c9ce22770c3347c93e3c94812`
- PR：[ #4 — owner-attested host evidence contract ](https://github.com/simple-sudo/ClaudeCode-Protection/pull/4)，Draft，目标为 `codex/integrate-privacy-admission-20261027`
- 基线：从实时核实的 Codex HEAD `bdbd667545519952e5f4bb8464fd782364d18f8c` 创建；不修改 Codex 分支。
- 本分支没有修改 WFP 策略、FlClash/全机网络资源 owner、Bootstrap、Manifest、安装协议或 GPU 能力。

## 1. 已实现：可信证据合同

新增 `src/Shared/HostPrivacyEvidence.cs`，定义宿主参考、受限 Actor 观察、内容读取、明确拒绝、目标不存在、UNKNOWN 和 NOT_RUN 的不同模型。

核心约束：

1. 受限证据绑定固定 Session 和 Actor；宿主参考必须标记为 `HostReferenceOnly`，不能计入 Claude 暴露。
2. 必须提供受限来源、字段、采样时间、有效期、Artifact SHA-256、Owner 封存与内容验证状态。
3. `ContentRead` 只有在 Owner 封存、内容验证、原生状态一致且实际值满足要求时才会分类为 `ConfirmedDirect`。
4. 明确的 Win32 error 5、无内容、Owner 封存的读取结果才分类为 `DeniedConfirmed`；目标不存在、未知和未执行不能冒充拒绝。
5. P0 目标清单由可信调用者显式提供；证据不能自行把 P0 降级为非 P0。
6. 每个 P0 目标必须同时具备可信宿主参考和受限 Actor 结果。缺失、过期、UNKNOWN、NOT_RUN、目标不存在或无法解码均保留为 P0 UNKNOWN。
7. `P0Exposure` 是一票阻断：任一 P0 敏感字段被实际读取即为 true，不以拒绝数量平均抵消。
8. 推断要求同一 Claim/CorrelationKey 至少有两个不同 SourceFamily 和 SourceId；同源重复读取不会增加独立佐证。
9. 非敏感空清单可以证明该次清单读取成功，但不能伪造敏感暴露。

`OwnerSealed` 是当前可信 Owner 内部流程产生的证据状态，不是可由任意调用者自行签发的密码学许可证。真实网络垂直切片由 `ProtectedState.WriteNew` 写入受保护状态；该方法在发布前会重新打开文件、核对对象身份并回读 SHA-256。后续仍需审查该证据记录只能由可信 Owner 创建和消费，不能让受限 Actor 或报告调用方自行构造并注入产品准入链。

## 2. 已接入的第一个真实内容来源：OfflineConsoleNetworkSurvey

扩展现有 `OfflineConsoleNetworkSurvey.Seal`，复用既有可信 Broker/Owner、ProtectedState、同 Job 子进程和真实 LPAC worker，不另造宿主管理执行器。

受限 worker 的身份检查沿用 `AtomicChild.AssertOfflineConsoleWorkerIdentity`：

- Windows AppContainer；
- LPAC access check 已观察；
- Package access mask 精确为 2；
- Low Integrity SID 为 `S-1-16-4096`；
- 零 capability；
- 禁止创建子进程。

当前垂直切片覆盖：

| P0 目标 | 实际来源 | 记录字段 |
|---|---|---|
| `network.adapter.guid` | `GetAdaptersAddresses` | 接口 GUID |
| `network.adapter.mac` | `GetAdaptersAddresses` | MAC |
| `network.adapter.address` | `GetAdaptersAddresses` | Unicast IP |
| `network.adapter.dns` | `GetAdaptersAddresses` | DNS 地址 |
| `network.adapter.gateway` | `GetAdaptersAddresses` | Gateway |
| `network.tcp.v4` | `GetExtendedTcpTable(AF_INET)` | TCP endpoint、PID |
| `network.tcp.v6` | `GetExtendedTcpTable(AF_INET6)` | TCP endpoint、PID |
| `network.processes` | 受限进程枚举 | FlClash / FlClashCore / GameViewerService / MuMuRemoteBackend / MumuRemoteHealthd / MuMuRemoteService 的名称、PID、创建时间 |

流程：

1. 可信侧先捕获宿主参考；受限 worker 在原 LPAC/Job 创建链内通过真实 Windows API 尝试读取内容。
2. Owner 按实际 child PID、创建时间、Session 和网络采样时间读取受限输出并严格解析；宿主前后进程快照用于稳定性核验。
3. 受限 HostIdentity receipt 先由 Owner 封存；网络 Seal 必须核对该 receipt SHA-256、Session 与受限 PID，并将其 SHA 同时绑定进 network survey 与 profile。Owner 再将宿主与受限的原始网络缓冲、进程清单及宿主后置快照分别写入 ProtectedState，并回读校验 SHA-256。
4. 确定性画像只使用通过来源/身份/时间/内容验证的记录；宿主原值只作为参考，不会被当成受限 Actor 已读取。
5. Profile 原值和关联证据写入受保护状态文件 `host-privacy-network-profile-<job>.json`；普通报告只输出 profile receipt SHA-256、直接观察数、推断数、P0Exposure 和 P0Unknown，不把原始值注入 Claude 工作区或普通工具上下文。
6. OfflineConsoleQualification 的限定完成条件要求原固定网络读取资格通过、Profile receipt 存在、P0Exposure=false 且 P0Unknown=false。此条件只属于该限定资格报告，不是正式 Claude 准入许可。

ProcessView 已增加独立 CapturedFileTime 并将 OfflineConsoleNetworkSurvey 数据 schema 提升为 2，避免把进程枚举时间误写成网络 API 的结束时间；创建时间必须不晚于该次进程清单采样。

## 3. 自动化验证与证据等级

新增/扩展测试：

- `tests/WorkspacePipe/HostPrivacyEvidenceCases.cs`：来源/Actor/Session 绑定、宿主参考隔离、内容与拒绝区别、P0 一票阻断、缺失目标 UNKNOWN、过期证据、同源不独立、跨源推断、证据伪造和 P0 降级拒绝。
- `tests/OwnedToolLaunch/OfflineConsoleNativeCases.cs`：在 Windows Runner 的普通测试进程中，使用真实网络 API 内容验证 survey schema、profile 字段映射及 Actor/OwnerIdentity/NetworkSurvey receipt 绑定；此测试明确标记为 ordinary fixture，不是 LPAC 或 L3 证明。
- 两个项目的显式 Compile 清单和 WorkspacePipe 测试入口已更新。

证据分级：

| 级别 | 当前状态 |
|---|---|
| T0 源码/契约 | 已实现，仍需 PR 审查 |
| T1 托管策略测试 | Safe managed policy smoke 在 `f819ddf` PASS |
| T2 Source-linked / Windows Runner | 普通 Windows 网络内容映射与 receipt 绑定测试在 `f819ddf` PASS；不是 LPAC |
| T3 实际安装 Broker + 同 Job LPAC 网络内容对抗 | **NOT_RUN（本次新 profile 集成后）** |
| T4 多工具/派生链和跨来源完整画像 | NOT_RUN |
| T5 真实受保护 Claude 完整链 | NOT_RUN |

历史记录中指定 API 的 LPAC size-query error 5 仍是历史事实，只能证明当时指定接口和执行的结果；不能直接替代本次 schema 2/Profile receipt 的真实实机验收。

## 4. 明确未覆盖范围

本切片不覆盖或不声称覆盖：

- UDP、DNS API/cache、路由表、ARP、BSSID/SSID、Wi-Fi 驱动和其他网络替代 API；
- ASN/ISP/运营商归属、物理出口及跨会话网络画像；
- FlClash 配置文件、订阅/节点、9090 管理接口及代理服务内部状态；
- UU 服务配置、会话/中继端点和所有远控派生来源；
- 设备 MachineGuid、主板/BIOS/磁盘、PnP、NVML/CUDA/GPU UUID；
- 注册表、COM/CIM/WMI、服务、句柄、事件日志、PowerShell/Python/Node/MCP/Hooks 的全部派生路径；
- 其他网络或系统资源 Owner、正式 Claude 完整准入链。

目前证据模型中的 `OwnerSealed` 仍是可信内部调用链状态，后续需完成 Owner-only 创建入口、证据读取/复核和不可伪造绑定审查。该模型不签发运行许可，不替代原 owner 的强制机制。

## 5. 下一步验收

1. `f819ddf` 的 Hosted Windows compile 与 Safe managed policy smoke 已 PASS；Offline workspace Git workflow 尚在运行。文档同步 HEAD `b7e9c08` 的 CI 需继续核对，不能把旧 SHA 的 PASS 视为当前 HEAD 全绿。
2. 在用户 Windows 11 上，用当前独立分支构建的工件走现有安装/版本/Owner 链，执行一次固定 OfflineConsoleNetworkSurvey schema 2 的真实 LPAC 对照；不关闭 GPU，不修改全机代理/WFP。
3. 由可信 Owner 核验真实 host references、restricted raw bytes、process receipt、Profile receipt 的文件身份/哈希/权限和实际内容；保存桌面日志并回传。不能只看退出码或摘要。
4. 对本次实际读取结果逐字段分类：CONFIRMED_DIRECT、DENIED_CONFIRMED、UNKNOWN、NOT_RUN；若任何 P0 内容真实可读，保留原值与证据并记录 FAIL，再修复复验。
5. 在本垂直切片闭环后，再串行推进 FlClash/UU 管理面、设备身份、环境位置和其他替代来源。

**当前结论：已经从纯设计合同推进到可信证据模型 + 真实网络 API profile 源码接线；尚未完成新的真实 LPAC L3 实机验证，更不是整个 P0-ASSURANCE / P0-HOST 或 ClaudeCode-Protection 的交付验收。**
