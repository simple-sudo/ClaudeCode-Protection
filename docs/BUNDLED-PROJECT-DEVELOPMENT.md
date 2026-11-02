# TextSummary 项目开发流程

> 文档效力（2026-11-02）：固定项目开发切片与原版本证据。支持的TextSummary路径不等于任意项目、正式Claude会话或完整产品；不将其工具能力扩张为宿主路径/管理员权限。
> 最新状态/授权只见[CURRENT-STATE](CURRENT-STATE.md)，正式目标与术语见[SECURITY-REQUIREMENTS](SECURITY-REQUIREMENTS.md)。以下旧状态与操作许可不自动延续。

2026-11-01 09:16:01Z普通用户入口已实机通过：两次本人授权/UAC后，实际安装INACTIVE
14ea8f9c/F415392F/334E9AA8。普通daily的workspace-sample -> workspace-develop ->
workspace-review -> workspace-extract经原Broker/Job/严格LPAC完成任务和成功清理导出，
sessionfb3c01e8771d4461ac27f6d5e7299e7e。结果5977313F...A715F，七份提取文件摘要/长度
独立匹配；交付work/ordinary-project-delivery-20261101，六测试/Lines2/Words5，原项目
未覆盖，宿主未执行输出DLL。无强制停止/自动恢复/权限或网络变化，无产品进程。
本次不读私有Job/Stop/错误；原owner成功导出+认证v4回复是闭合清理依据，不称作新的
独立raw Job快照或真实敏感资源拒绝矩阵。两次授权均消耗，固定控制不得重新运行。
详见ordinary-project-control-20261101/observed-result.json SHA440B881D。
以下源码/READY/旧acc版本段落是准备与历史状态，当前安装为14ea8f9c。

## Ordinary installed workflow — source integration (2026-11-01)

The new daily commands are `workspace-sample NEW_BASE_BUNDLE` followed by
`workspace-develop BASE_BUNDLE NEW_RESULT_BUNDLE`. The first writes only the four
embedded TextSummary source files. The second requires their exact serialized
baseline bytes before reserving a fresh result and requesting human UAC. It uses
the original installed Broker, original task/Job/tool owner and successful-cleanup
export. Existing `workspace-review` and `workspace-extract` review and extract the
result into a new directory; no automatic source merge or host execution occurs.

This is a fixed sample task, not caller-selected project execution. The separate
Broker pipe entry and v4 reply require the explicit TextSummary scope and compiled
baseline. The v3 `workspace-process` DATA contract stays unchanged and cannot
accept a project reply. Both ordinary-user entry and elevated caller validation
now query TokenIsAppContainer and reject confined tokens or failed queries before
granting caller authority. Same human, current installed image, held process,
authenticated pipe and original cleanup/export checks remain in place.

Source9b12e1c's 84-input offline build, four IPC/token/DATA/prior-pin fixtures and
three ordinary daily dispatch cases passed; library334E9AA8 adds only the reviewed
read-only token query import. The sample hash matches ED3DDCB2. The new client
refused a changed valid baseline before UAC/output reservation and reviewed the
reused actual result's five changes. Initial harness DLL-path failure and the raw
prior fixture's stale installed53f text are preserved; actual fixture constants
use acc7825b, and the source label is now corrected. No new project execution.
Candidate14ea8f9c/F415392F stages3 changed/11 reused assets. Source9518a25's82-input
Bootstrap reused exact334E9AA8; the complete20-file stage and embedded manifest
match. Two held-input preflights/three strict binder refusals and exact runner
2 positive/17 negative cases pass, not live Job proof. Controls are READY but
NOT_AUTHORIZED/NOT_RUN, under work/ordinary-project-control-20261101; full concrete
scope is system-operation-review.md. Only the runner's exact own ordinary daily
may be stopped on its180s deadline, not elevated owner. No private error/raw Job
read, automatic retry/recovery or additional network grant is included.
Any new system operation remains pending; actual acc7825b success below is reusable
evidence. No new UAC authorization transfers from that consumed run. The new
token guard is not yet an observed rejection of an actual LPAC caller, and no
broader host-sensitive privacy or arbitrary-project claim follows.

2026-11-01已实际完成：人工UAC更新到INACTIVE acc7825b/656D8690/A126301D后，session3b009cf24b5b43e59a6cca610b36330a在原严格LPAC/零capabilities/Job中读改源码、编译、执行六项测试及计数器，原Job关闭/零成员、成功清理回执后导出；普通daily review/extract0，七份文件独立核对摘要一致，宿主没有执行项目DLL。结果85DDA341C8422E060BEB5C3C4B8E359717B5AA6F83EF36C887C680A2F9018EF0；交付work/textsummary-delivery-20261101，归一化证据bundled-project-r2-control-20261101/observed-result.json SHA2C1E196310C375AFBD162E84B69853770137ABF451F5EFEBEF1CBDABB146A58D。五root拒绝和Git两自身拒绝通过，编译工具需通过自身两拒绝才能退出0（非单独raw记录）；无强制停止/权限变更/网络/恢复，授权已消耗。仅此固定仓库项目切片已验证，不是任意调用者项目、全部真实宿主隐私、PowerShell或完整产品资格。

2026-11-01候选/控制已READY：acc7825b881a40efb7b7f2cd7005f8d1 / manifest656D8690F56C5A085E1379B923692D2AC409F4B83E11BD18DE929033DC8C06E1，69输入Bootstrap复用A126301D、20文件暂存匹配。新持有预检与严格开关拒绝、22个helper判断逻辑用例通过，尚未授权或安装。完整两次人工UAC范围见work/bundled-project-r2-control-20261101/system-operation-review.md；普通用例不是实际Job或LPAC证明，当前安装仍53f/B5CFD0ED/04357BC8。

本源码在原 Broker、原 ProtectedSession、原 Job/严格 LPAC 工具创建和关闭后导出流程内，增加显式 `develop-bundled-project`。它只执行仓库内 TextSummary 项目的固定维护任务：读取源码，给行数统计库增加 Unicode 空白分词统计，增加三个回归用例，调用已固定的 Roslyn/ref 资产编译并执行六项测试，保存运行结果，再由原 owner 在 Job 闭合后核验及保存结果。`export-developed-project SESSION HASH` 只有成功/清理回执绑定后才导出结果。

普通资格已通过：source79626d9、68冻结输入、库A126301D，四模式均0/无stderr。普通自身项目确实完成上述读/改/编译/运行六项测试/快照核验/提取，七份结果文件摘要与提取副本独立一致，无SMA引擎加载。证据work/bundled-project-r2-build-20261101/qualification.json及qualification-closeout.json；前者摘要12ED9257C844B75FFAF1BCC1611099041C3E7CA977F183E3130CA011E59B89FC。这不是实际LPAC、原Job、工具拒绝或宿主隐私资格。首次构建的测试重名编译失败保留，修正r2通过；原receipt的InputCount63继承常量由伴随记录说明实际68，不改原件。

这是新的项目代码执行范围，源码/普通测试不构成实际受保护运行授权或成功。当前安装53f3ee98仍没有这项功能；下一步需要完整构建和普通资格、具体候选审查，再取得新的人工UAC决定。不能执行历史冻结计划、把旧 DATA 输入或已消耗诊断授权转换成项目代码授权。

原 DATA 使用v3计划、不执行项目代码；新任务必须有v4/DevelopProject=true、精确嵌入项目输入摘要及固定工具参数。DATA不能选择project工具，普通工具链资格仍要求PowerShell，不能由C#项目任务替代其成功条件。新工具仍是原Broker映像的受限入口，不是另建执行器或提升子进程；不载入PowerShell引擎，不改ETW/AMSI、宿主权限、网络或capabilities，不执行MSBuild项目文件、包、构建任务、生成器或分析器。任意调用者项目支持、真实宿主隐私/网络/GPU/十四准入及GUI交付仍需完成。

2026-11-01已核对的官方源码中，PowerShell7.6.6及当时master的EventProvider仍对非零EventRegister返回抛异常，PSEtwLogProvider仍在类型构造中创建该provider。本次未下载安装或运行新版PowerShell，不能推定单纯升级修复当前LPAC问题。原始源码摘要见work/etw-supported-route-20261101/source-downloads.json。

微软的[EventAccessControl](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/nf-evntcons-eventaccesscontrol)、[EventAccessQuery](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/nf-evntcons-eventaccessquery)、[EventAccessRemove](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/nf-evntcons-eventaccessremove)说明了权限操作及注册表/默认读回；本轮检索没有找到现存内核条目同步刷新的文档化保证，不能把“未找到”当作Windows完全不存在该机制。已实测令牌判定与内核实际描述符的区别仍须保留。参考[7.6.6 EventProvider](https://raw.githubusercontent.com/PowerShell/PowerShell/v7.6.6/src/Microsoft.PowerShell.CoreCLR.Eventing/DotNetCode/Eventing/EventProvider.cs)和[7.6.6 PSEtwLogProvider](https://raw.githubusercontent.com/PowerShell/PowerShell/v7.6.6/src/System.Management.Automation/utils/tracing/PSEtwLogProvider.cs)。
