# TextSummary 项目开发流程

本源码在原 Broker、原 ProtectedSession、原 Job/严格 LPAC 工具创建和关闭后导出流程内，增加显式 `develop-bundled-project`。它只执行仓库内 TextSummary 项目的固定维护任务：读取源码，给行数统计库增加 Unicode 空白分词统计，增加三个回归用例，调用已固定的 Roslyn/ref 资产编译并执行六项测试，保存运行结果，再由原 owner 在 Job 闭合后核验及保存结果。`export-developed-project SESSION HASH` 只有成功/清理回执绑定后才导出结果。

这是新的项目代码执行范围，源码/普通测试不构成实际受保护运行授权或成功。当前安装53f3ee98仍没有这项功能；下一步需要完整构建和普通资格、具体候选审查，再取得新的人工UAC决定。不能执行历史冻结计划、把旧 DATA 输入或已消耗诊断授权转换成项目代码授权。

原 DATA 使用v3计划、不执行项目代码；新任务必须有v4/DevelopProject=true、精确嵌入项目输入摘要及固定工具参数。DATA不能选择project工具，普通工具链资格仍要求PowerShell，不能由C#项目任务替代其成功条件。新工具仍是原Broker映像的受限入口，不是另建执行器或提升子进程；不载入PowerShell引擎，不改ETW/AMSI、宿主权限、网络或capabilities，不执行MSBuild项目文件、包、构建任务、生成器或分析器。任意调用者项目支持、真实宿主隐私/网络/GPU/十四准入及GUI交付仍需完成。

2026-11-01已核对的官方源码中，PowerShell7.6.6及当时master的EventProvider仍对非零EventRegister返回抛异常，PSEtwLogProvider仍在类型构造中创建该provider。本次未下载安装或运行新版PowerShell，不能推定单纯升级修复当前LPAC问题。原始源码摘要见work/etw-supported-route-20261101/source-downloads.json。

微软的[EventAccessControl](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/nf-evntcons-eventaccesscontrol)、[EventAccessQuery](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/nf-evntcons-eventaccessquery)、[EventAccessRemove](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/nf-evntcons-eventaccessremove)说明了权限操作及注册表/默认读回；本轮检索没有找到现存内核条目同步刷新的文档化保证，不能把“未找到”当作Windows完全不存在该机制。已实测令牌判定与内核实际描述符的区别仍须保留。参考[7.6.6 EventProvider](https://raw.githubusercontent.com/PowerShell/PowerShell/v7.6.6/src/Microsoft.PowerShell.CoreCLR.Eventing/DotNetCode/Eventing/EventProvider.cs)和[7.6.6 PSEtwLogProvider](https://raw.githubusercontent.com/PowerShell/PowerShell/v7.6.6/src/System.Management.Automation/utils/tracing/PSEtwLogProvider.cs)。
