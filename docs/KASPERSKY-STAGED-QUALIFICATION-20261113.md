# 卡巴斯基监控与分阶段验证门禁（2026-11-13）

状态：**SOURCE / staged gate implemented; local execution NOT_RUN**。本文件记录设备所有者于 2026-11-13 明确授权的门禁策略更新，取代 2026-10-25 历史告警后“无条件永久停止构建/执行”的旧门禁；不改写历史事件证据，也不宣称卡巴斯基厂商已判定误报。

## 1. 当前决策与边界

设备所有者正式授权：在独立开发分支上，将 SECURITY_REVIEW_REQUIRED 从无条件永久停止，改为分阶段、卡巴斯基持续监控、新告警立即停止的测试门禁。

本次只修改项目自己的构建/测试入口与资格策略：
- 不关闭、暂停或修改卡巴斯基。
- 不增加卡巴斯基排除项，不恢复隔离对象。
- 不通过改名、重打包或替换发布身份规避检测。
- 不自动运行构建产物，不安装产品，不修改 ACL/WFP/网络接口或 FlClash。
- 新告警、AV 服务停止、Security Center 状态变化或监控查询失败均按 fail-closed 处理。
- 旧事件的具体触发行为、DLL/依赖历史身份和厂商判定仍为 UNKNOWN；用户的误报判断是设备所有者的风险接受决定，不等同厂商鉴定或整机安全证明。

## 2. 当前阶段门禁

| Stage | 当前状态 | 允许范围 |
|---|---|---|
| DailyBuild | **OPEN（首阶段）** | 只编译日常 ClaudeProtection.csproj；Release、no-restore；不 publish、不安装、不执行产物 |
| EngineeringBuild | BLOCKED | 工程/Job/LPAC 相关独立构建 |
| CenterBuild | BLOCKED | Protection Center 构建 |
| NativeBuild | BLOCKED | Native Fence 编译 |
| IsolationProbe | BLOCKED | 隔离探针及任何执行实验 |
| WfpMutation | BLOCKED | WFP/防火墙启用、恢复、租约和其他策略修改 |

后续每个阶段必须先审查对应源码/依赖/输出范围，再更新明确阶段资格；不能通过调用者参数、环境变量或过期时间自动打开其他阶段。当前阶段参数不是操作系统安全边界或签名授权，仅用于让项目入口按审查过的阶段 fail-closed。

## 3. 卡巴斯基监控机制

scripts/Assert-ProjectSecurityClearance.ps1 现在要求调用者显式提供 Stage。只有 DailyBuild 能通过当前 gate。

首阶段预检及运行期间检查：
1. AVP21.26 服务必须存在且 Running；版本/服务名改变即停止并重新审查。
2. root/SecurityCenter2 必须恰好报告一个显示名为 Kaspersky 的产品，productState 必须与本机既有合格观察 266240 一致。
3. 从本阶段开始时间起检查 Windows Application 日志中的 avp / kaspersky Provider 事件。
4. 构建期间每 750ms 轮询事件；每 3 秒重新检查服务与 Security Center 状态；构建结束后再做一次最终核验。
5. 监控证据以 JSONL 持续写入 `%LOCALAPPDATA%\\ClaudeCode-Protection\\security-stage\\<run>-DailyBuild-kaspersky-monitor.jsonl`：记录预检/周期健康快照、进程启动/退出、监控失败、新告警和进程树终止结果。事件查询正常且无告警时不逐次写入空轮询，避免日志膨胀。
6. 出现新相关事件、事件日志不可读取、服务停止或产品状态变化，终止构建进程树并报告停止原因。

**覆盖限制：** 目前监控依赖固定服务名、Security Center 注册状态和 Windows Application 日志中的相关 Provider。它不是 Kaspersky 内部遥测 API，不能保证捕获所有弹窗、隔离动作、其他日志通道或厂商云端告警。输出明确保留 FullVendorAlertVisibility=UNKNOWN。**本机阶段测试时，设备所有者必须保持卡巴斯基界面可观察；看到任何新告警立即停止并回传截图/事件与完整构建日志。**

## 4. DailyBuild 第一阶段的精确范围

scripts/Build.ps1：
- 先调用 Assert-ProjectSecurityClearance.ps1 -Stage DailyBuild。
- 通过 Invoke-ProjectSecurityMonitoredProcess 启动固定 dotnet.exe 构建。
- 只执行 dotnet build，不再使用 dotnet publish。
- 使用 --no-restore，不触发依赖恢复或下载。
- 输出日志放在 %LOCALAPPDATA%\ClaudeCode-Protection\security-stage\。
- 构建退出码非零、监控异常或 AV 新事件均为失败；不自动重试。
- 产物只留在 bin/current，本阶段不启动、不安装、不签名、不发布。

若当前工作区缺少有效 project.assets.json 或依赖缓存，--no-restore 构建可以失败；应保留失败，不切换在线 restore 来“修绿”。后续如需离线依赖恢复，先单独审查并开放专门阶段。

## 5. 后续阶段顺序

1. **S1 / DailyBuild：** 在本机执行一次固定 Git SHA 的日常 Release 编译；检查输入/输出哈希、工具链、退出码、AV 前后状态和持续监控日志。此步骤尚未执行。
2. **S2 / 普通权限只读：** 单独审查具体只读命令及产物身份后开放；不自动执行正式 Claude、不修改系统状态。
3. **S3 / Engineering、Native、LPAC：** 分别审查工程源码、原生代码、Token/Job/LPAC 创建链及调用参数；逐项开放，不捆绑。
4. **S4 / WFP 与网络修改：** 另行审查精确资源 owner、回滚/恢复与故障停止条件；当前仍关闭。
5. **S5 / 安装和真实 Claude：** 安装、激活、正式 Claude 启动仍需要其各自的当前授权和完整验收资格。

每阶段记录精确 SHA、构建/执行身份、卡巴斯基状态、原始日志、输出工件哈希、PASS/FAIL/UNKNOWN/NOT_RUN。BUILD 不等于运行安全；一次无告警不证明旧事件误报，也不证明整机安全。

## 6. 本次源码变更清单

- scripts/Assert-ProjectSecurityClearance.ps1：永久 throw 改为显式 Stage、预检、事件监控与进程树停止。
- scripts/Build.ps1：DailyBuild-only、no-restore、受监控的非发布构建。
- scripts/Build-Engineering.ps1、Build-Center.ps1、Build-NativeFence.ps1：分别请求仍关闭的阶段。
- scripts/Invoke-IsolationProbe.ps1：明确隔离探针阶段，仍关闭。
- scripts/Set-MainProtection.ps1、Test-ScopedFirewall.ps1、Use-ProbeLoopbackLease.ps1：明确 WFP mutation 阶段，仍关闭。
- scripts/Test-ProductBuildBoundary.ps1：静态检查阶段白名单、监控机制、日常构建入口及其他关闭阶段。

本次尚未运行 PowerShell 门禁、未查询本机卡巴斯基状态、未构建/安装/执行任何产品程序。GitHub CI 的静态脚本检查完成前，不能把本次修改标记为 BUILD 或 VERIFIED。
