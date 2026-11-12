# 2026-11-12 静态构建边界安全复核（不解除硬停止）

## 目的与范围

本记录只审查 2026-11-12 当前源码中日常 CLI、工程专用程序、历史聚合 SelfTests 与本机 Build 入口的静态边界。它用于为后续审查提供可重复证据，**不构成 Kaspersky 误报结论、不构成二进制安全鉴定，也不授予本机 BUILD、执行、安装或提权资格**。

复核源码基线：`f687cd874bd9ae2473eb5688d6b90af74daab577`。静态检查脚本：`scripts/Test-ProductBuildBoundary.ps1`。Hosted Windows compile workflow 在编译产品项目之前执行该脚本；脚本只读取文本/XML/JSON 与 PowerShell AST，不运行产品代码。

## 已核对的静态事实

1. `src/ClaudeProtection/ClaudeProtection.csproj` 使用 `EnableDefaultCompileItems=false` 和显式 Compile 清单。日常产品清单没有 `SelfTests.cs`、`NativeJob.cs`、`SandboxToken.cs`、`ControlledLoopback.cs`、`ExperimentMonitor.cs` 或 `IsolationExperiment.cs`。
2. 日常 `src/ClaudeProtection/Program.cs` 没有 `selftest` 命令分支，也没有 `SelfTests.Run()` 调用。
3. `src/ClaudeProtection.Engineering/ClaudeProtection.Engineering.csproj` 是独立显式编译清单，包含 NativeJob/Token/Sandbox 实验实现；不引用日常产品项目。历史聚合 `SelfTests.cs` 也没有被该工程项目编译。
4. 当前 Bootstrap 的批准包清单没有 Engineering、SelfTests、Sandbox 或 NativeFence 资产。该清单本身仍是历史 schema 6，不代表当前 schema 32 安装的批准包。
5. 常规 `scripts/Build*.ps1` 入口在调用 dotnet、创建构建目录或调用 native compiler 前均先 source `Assert-ProjectSecurityClearance.ps1`。
6. `Assert-ProjectSecurityClearance.ps1` 的 PowerShell AST 只有一个无参数、无条件的 ThrowStatement，消息为 `SECURITY_REVIEW_REQUIRED`；没有环境变量、命令参数、过期时间或自动重置分支。

## 可重复自动检查

`scripts/Test-ProductBuildBoundary.ps1` 验证上述日常/工程源文件隔离、工程资产不进入批准包，以及安全停止脚本仍是无条件硬停止。它不执行 Build 脚本，也不尝试通过 GitHub Actions 或其他入口绕过本机停止。

Hosted CI 对该脚本的 PASS 只证明当前文本边界满足这些断言。Hosted CI 仍会编译产品项目；专项 CI 也会运行测试 harness、被测托管数据/策略代码及 Runner Git。它不会运行已安装产品 Broker、ProtectedSession、Owned Job、AtomicChild/LPAC 产品链、Claude 或调用方项目源码。

## 事件与结论边界

2026-10-25 Kaspersky 记录的检测对象是日常 CLI EXE，事件命令行为该程序加 `selftest`。历史 SelfTests 将普通数据检查与进程树终止、守护强制结束和故障注入放在同一入口。当前源码的日常产品已显式排除该聚合源并移除对应 dispatcher 分支，这是一个可审查的源码隔离事实；它**不能证明历史检测由该代码触发，也不能证明新版二进制不会触发检测**。

用户报告此前已清理且 Kaspersky 当前显示正常；该用户观察被保留，但不等同于厂商样本鉴定。检测原因、规则、调用栈、旧时载入的 DLL/依赖和完整 AV 告警覆盖仍 UNKNOWN。

## Bootstrap 批准清单差异

静态读取当前源码的 `ApprovedPackage.json` 得到 schema 6、Release `7df61706780c433f9dc5e7ddf5bc6f28`、24 项资产。当前安装基线由用户只读核实为 schema 32、25 项资产；schema 32 的 `PackageAssetCatalog` 额外包含固定 `broker-session-zero-startup-witness`（`bin/admin/SessionZeroStartupWitness.exe`，8192 bytes，固定 SHA256）。因此不能仅修改 Release/Transition 字段，也不能把 24 项历史批准清单当作当前 schema 32 的批准包。候选包必须按 schema32 完整资产集合重新构建、逐项计算长度/SHA256，并解决 Bootstrap 自引用/内嵌清单的一致性后再建立 transition。

## 明确保持的硬停止

- 本机 `Build*` / 安装 / 产品执行入口继续被 `SECURITY_REVIEW_REQUIRED` 阻断。
- 历史 S1 日常 CLI 与一次性 Broker 离线构建授权均已消耗，不得复用。
- 不通过新 workflow、artifact、改名、重包装、参数或环境开关绕过本机硬停止。
- 本记录不授权加载程序集、执行任何产品二进制、UAC、安装/更新、WFP、Job、网络或 AV 策略操作。
- 新版 package approval 与 inactive-update transition 必须等候候选包真实资产完整生成、逐项哈希核验后再建立；当前安装 Release `f9e8d29d9c2c472495422dbffd40bffd` 的 ManifestSHA256 已由用户只读核实为 `5195D12C6A446BA3408D822C3907E5FD7E51BB4ED820A69BFCB08A16512BDBC2`。历史 `4d186bcb→7df61706` Transition 不适用于该安装。

**结论：** 本次形成了可重复的静态源码边界复核，但 `SECURITY_REVIEW_REQUIRED` 仍然有效。不得将静态复核、Hosted compile 或 CI PASS 升级为本机 BUILD、AV 兼容、产品执行或 Broker→Owned Job→LPAC 端到端验收。
