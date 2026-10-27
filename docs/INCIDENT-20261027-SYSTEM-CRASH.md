# 2026-10-27 系统蓝屏事件：运行测试停止

## 已确认事实

Windows System日志1001/Microsoft-Windows-WER-SystemErrorReporting明确记录bugcheck 0x0000001e（0xffffffffc0000005,0,8,0），ReportId ba6f3990-c859-4189-abe0-ca70d278d5f7。Kernel-Power41及EventLog6008记非正常关机；系统启动时间2026-10-27T07:56:31.5Z（本地03:56:31）。小转储C:\Windows\Minidump\102726-15281-01.dmp存在，7030648字节，写入07:56:43.804Z。普通用户读取转储摘要返回AccessDenied，SHA/故障栈/驱动归因UNKNOWN，未改ACL或复制绕过。

本代理未发起关机/重启命令、未自动确认UAC、未变更AV/驱动/全机网络；但崩溃位于安装后Watchdog成员诊断尝试窗口内，不能排除相关性或测试触发内核/驱动问题，不能据此宣称与测试无关。6008另有较早的previous-shutdown文本时间，需结合事件/转储判断，不据单条文本强定崩溃秒点。

814cf4331fcb4fd6a95fee2973b734a6安装已完成；首次成员诊断helper在只读规则前置回读后中断，结果文件含不完整数据，无新814cf准入/Job/成员回执，UNKNOWN而非正常退出。重启后独立只读回读6角色仍完整（filterId103080–103085），22历史Job均有关闭回执、20次豁免有cleanup，但这些仅为本机恢复后观察，不是全量重启/断电保护验收。FlClash重启后PID28088/Core16112，未由代理启动/重配。

## 操作纠正与当前状态

在查明重启原因前又启动了第二次限定成员诊断（Watchdog-Members-r2-20261027），该决定过早。现已终态退出3（08:00:13.919Z），after记录AV/BFE运行、FlClash28088/Core16112、有限Application新AV事件0（完整覆盖UNKNOWN）。当前未见ProtectionBroker/ProtectionBootstrap/ProtectionCenter/ClaudeProtection测试进程存活。

停止新增产品构建/安装/执行和故障注入，当前只做只读事件/转储诊断及证据/文档保存，先明确故障栈/模块和关联后再决定安全验证路线。此停止是对实际系统崩溃的响应，不将未知根因写成软件已安全或已交付。目标未完成，保留active，不自动后台重跑。

原始System事件导出与转储索引在work/system-crash-20261027（不入Git）；原转储保留系统位置，未删除/修改。前序失败、两次helper、私有state与安装包保留。

## 2026-10-27 08:12Z 只读诊断接续

上轮分类progress：保留系统bugcheck、停止新增运行验证；本轮未构建/安装/运行产品或实施故障注入。系统启动时间仍07:56:31.5Z，没有新重启证据。

- 已通过固定只读helper取得原小转储SHA256 C38F6F02C3CEEBC6FD2A9628C76E2D671D0C8D855E6AAD5997291989D3A1FC92，长度7030648，原文件未复制/修改/上传。
- WER Report.wer固定路径、36678字节、148行、UTF16LE，EventType=BlueScreen，参数与System1001一致，OS10.0.26200；没有故障模块/栈分类。原诊断输出ProgramFiles/ClaudeCodeProtection-CrashSingle-r2-20261027（只含选定元数据，不含raw dump）。0x1E及0xC0000005对应内核未处理访问违例，见微软bugcheck文档；不能据此锁定任何驱动。
- 停止前第二次成员诊断的已有回执指出Job bf82d7d48d594e94a7e92e8a8d459cbf中PID22320为安装Broker，额外27796为System32/conhost.exe；均确认属于同一Job、同一安装AppContainer SID、Low4096/capability0。该事实解释唯一成员检查为何拒绝，不证明conhost导致蓝屏，不作为放宽检查或恢复运行许可。

### 只读helper自身异常及已完成精确停止

第一版WER目录枚举helper PID18080（创建08:03:09.7750859Z）取得dump摘要后CPU/内存持续增加，WER输出未完成；静态原因尚未定位。发现时内存约4.4GB，不能把“只读”当作资源无风险。首次精准终止UAC被取消，未绕过；用户明确选择“再次显示UAC，我来确认”后第二次仅结束该PID/创建时间/映像匹配的PowerShell，08:06:15.580Z确切退出，父helper终态-1。原异常helper及首次取消记录不改写；reader-stop.json为明确停止回执，当前该进程不存在。

后续弃用目录枚举，限定单个已知Report.wer、1MiB数据/8192行；首次因长行限制拒绝，修正版跳过超长非目标行并正确识别UTF16，08:07:44.09Z退出0。该修正不改变产品、驱动、AV、信任库或网络配置。当前AV/BFE运行，FlClash28088/Core16112，有限Application告警0、完整覆盖UNKNOWN。所有读取脚本/结果在work/crash-*-control及ProgramFiles对应目录保留。

### 官方离线调试器准备与自动审查阻断

微软官方appinstaller给出WinDbg1.2610.1001.0，来源https://windbg.download.prss.microsoft.com/dbazure/prod/1-2610-1001-0/windbg.msixbundle，bundle1203512387字节/SHA4662AE17BC0DC77DB987B89CCCEA32C30058BAA06268F861D09E0AB4E4F45C20。仅下载/解包到忽略的work/crash-debugger，未安装到系统。选定12文件：cdb/引擎/扩展DLL等PE签名Valid、Microsoft签发，另2项官方非执行triage数据；精确源/版本/各文件摘要在source.json和stage-pins.json。没有运行调试器、安装驱动或附加任何进程。

尝试准备受保护工具目录并启动“固定dump + !analyze -v/.bugcheck/kv/lmtn + 180秒/1GiB上限”的离线分析动作被自动审批审查拒绝；返回仅blocked by policy，无细分理由。整个该调用在执行前被拒绝，未创建该次analysis控制目录/执行调试器，不换入口或工具绕过。故障栈/驱动归因/是否由本测试触发仍UNKNOWN。产品runtime/build/install/fault injection继续BLOCKED；目标未完成，当前不是三次同一阻塞停滞的审计结论，不标complete或假称后台继续。

## 尚需的实际证据

下一项有效证据是由获准的微软调试器离线打开这一个转储后得到的故障模块/异常上下文与调用栈。官方说明：[WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/)，[0x1E](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x1e--kmode-exception-not-handled)。若由本人使用已批准的WinDbg，可打开原C:\Windows\Minidump\102726-15281-01.dmp，然后执行以下纯dump分析命令：

```
!analyze -v
.bugcheck
kv
lmtn
```

不安装/启用Driver Verifier、不更改驱动/AV策略、不重跑产品来复现。所需回传仅BUGCHECK、MODULE_NAME/IMAGE_NAME、FAILURE_BUCKET_ID、异常上下文及相关栈帧；不要上传整个转储或其他内存内容。自动调试器启动当前被审查阻断，不能用根因猜测替代这份证据或自行恢复测试。