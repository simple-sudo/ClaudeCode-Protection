# S1/S2 实际验证记录

日期：2026-10-26（America/New_York）。用户在原聊天 `01a175d2-12fc-77f2-8bd5-2f9be137bcba` 明确授权冻结日常 CLI 的单次离线构建，并有条件授权两个普通权限离线只读命令。该授权取代旧的“尚待 S1 答复”，不解除其余构建/启动硬停止，不判定旧卡巴斯基事件为误报。

## S1：BUILD，仅冻结的日常切片

- 源码基线 `c419a6e3c619ff72b5fb769c3c0f6bc7d3863d1e`；实际开始时 HEAD `6bbb601d5393691455370b3f8412c6ace46ff768`，原工作区干净。执行前 15 输入、5 工具、163 引用及4保留文件共187项摘要全部一致。
- 固定 SDK 8.0.422、引用包 8.0.28、唯一日常 csproj；7份源及SDK生成的程序集属性/全局using。保留原程序集名。无工程/GUI/native/生命周期/selftest输入。
- `scripts/Invoke-S1DailyBuild.ps1` 是固定历史单次入口；既有 Build/Assert/cmd 未改。消耗标记不自动清除，不接受其他源码/SDK/项目/输出参数。
- 87个实际展开导入均为固定SDK或当前项目；拒绝用户通配符和父目录构建覆盖。依赖恢复只用本地空源，资产表无第三方包或项目引用。没有下载、publish、安装或提权。
- 09:16:09–09:16:18 EDT：预处理、离线 restore、唯一一次 Release/no-restore/no-dependencies build 均退出0；0错误、0警告。关闭共享编译、SDK分析器和分析诊断；编译器仍列出引用包自带的6个生成器，**不宣称真实构建完全没有生成器**。完整SDK任务/生成器签名闭包仍未鉴定。
- 原始日志、87导入摘要、工件摘要及前后观察保存在本地忽略目录 `work/s1-daily-c419`。未运行产物，直至后续独立S2资格完成。

| S1 工件 | SHA-256 |
|---|---|
| ClaudeProtection.exe | `9290B9187CA1A989F6A5870C2EAD244DAABDF71AD69ACA8288685CE3D81931A6` |
| ClaudeProtection.dll | `A526AD5CEDE79E57D7A5364C4E54CA15B67211C0B44CFF04110A9AF0A6CAC0AB` |
| 原 Read-Environment.ps1 | `C31D9A0C107E157D01C5C1B607F358CA3E0B9D134D7DC559EF2A5BEF0AC67319` |

## S2：两个命令的有界运行证据

先独立读取PE元数据而不加载项目程序集：类型不含Job/隔离/selftest，模块无初始化方法；依赖仅.NET共享框架。检查Program分派、静态初始化、两个调用树、只读native查询和worker。不据此批准二进制中其他命令。

原审计worker调用Get-AuthenticodeSignature，无法将其证书/撤销验证资格认定为完全离线。因此在运行audit前移除此调用，签名明确UNKNOWN；worker的模块路径只允许系统内置模块。新脚本SHA `3731AB7E6B9B18F19CD7F4150D023F6F06E0DF8D26EFB1A60D46DE6B5BB77A8D`。原S1脚本另存 `work/s2-offline/s1-original-worker.ps1`，原工件manifest不改写；S2更新清单独立保存。EXE/DLL/程序集名未改变，没有再次构建或重包装规避检测。

首次system-proxy-baseline在.NET宿主阶段退出 `-2147450730`：执行包装错误设置 `DOTNET_ROLL_FORWARD=Disable`，要求未安装的8.0.0，尚未进入managed程序。原失败在 `work/s2-offline` 保留。明确复核本机仅装8.0.28，并记录hostfxr/coreclr/hostpolicy摘要后，将该子进程选择限制改为LatestPatch；未安装运行时、未改工件或系统环境。独立复核后的恢复执行在 `work/s2-offline-recovery`，不是隐藏自动重试。

| 实际命令 | 结果 | 范围 |
|---|---|---|
| system-proxy-baseline | 09:19:44 EDT，退出0 | ProxyEnabled=true，APIsAgree=false，ExpectedFlClashProxy=false；读取成功不等于代理配置合格。指纹 `F1054AE8D57120BA927A176D44DDF525A9B1405A1CFF1FE6141A5CF09C699046`。不输出原始代理/PAC/绕过值，不自动修改。 |
| audit（无--online） | 09:19:54 EDT，退出2 | 19项：9 PASS、2 FAIL、8 UNKNOWN。两条真实Claude规则禁用为FAIL；签名、有限进程查询、DNS/UDP/子进程/IPv6功能及未做在线检查保留UNKNOWN。拒绝准入符合现有限定行为，不是网络隔离验收。 |

普通权限、无真实Claude启动、无auth.json读取、无在线请求、无配置/网络/AV策略变更。前后settings摘要一致，FlClash/Core PID不变，TUN观察为Up，BFE及AVP21.26运行，两条真实Claude规则仍禁用。只读WMI注册状态与Application观察未见新AV事件；**完整厂商告警可见性仍UNKNOWN**，不能声称全面AV兼容或整机安全。原始配置/脚本/防火墙备份四项最终摘要一致。

## 执行后修正与剩余范围

本次实测发现代理API不一致只出现在独立baseline命令中，CLI的audit未消费该事实。现将现有UserProxyBaseline.Read接入EnvironmentAudit.Run：不符合预期即必需项FAIL，查询不可用即UNKNOWN，无修复或系统设置写入。这是**后续SOURCE**，四项目非生成语义检查0错误/0警告；未重编译、未用S1/S2工件冒充该新调用点的运行证据。类型检查首次仅因报告父目录缺失退出1，创建输出目录后成功；未改产品源码来掩盖这一记录错误。

当前允许的S1已消耗，S2有限检查已完成。真实配置修复/撤销、合成故障、GUI、工程/native/生命周期和新managed修正的构建/运行仍BLOCKED于各自安全资格；包批准pin为空。真实Claude登录/推理/启动DEFERRED_BY_USER。保护宿主、原子进程绑定、代理开放、持续Watchdog、可信安装及精确卸载仍未贯通，完整产品尚非DELIVERABLE。后续应按这些实际缺口形成生产调用链，不能再次用“尚待同一S1授权”停止，也不能把新源码当成已验证程序。
