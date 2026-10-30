# 当前工具故障：已确认项目异常，下一次验证具体范围

当前安装df6ff338081b43e4ac4691598c108f71/manifest9239BB32，INACTIVE。本人UAC于08:23:36Z完成更新及官方PowerShell7.4.22固定目录创建；15产品文件、552工具文件/110目录的摘要、可信owner、保护DACL及无非可信写入已独立匹配。

08:24:15Z sessionac45262cde9d40b1b6b79b8048f6f98f运行失败，PowerShell未到READY，原根在WAIT_FIXED_POWERSHELL到10秒期限。用户截图并明确确认刚才UAC后本项目进程弹出托管异常E0434352，地址00007FFAEB181ADA；该事实已接受并留档，不因未抓到匹配事件/PID否定。精确异常类型/根因尚未捕获。报告8E1E6153，截图及用户确认在work/powershell7-r2-control/run-evidence。原Job1bc7bc5b关闭归零、Stop无失败，未强杀owner，根I/O/四拒绝5通过；宿主SideBySide权限独立完全不变，本轮无注册表授权。PowerShell/Git/编译未成功，无成果，不能将安装和普通测试写成工具可用性。

## 已实施并限定验证的修复

在原Broker的工具CreateProcess窗口内串行设置其自身错误模式0x8003，子进程继承后立即精确恢复原Broker模式，避免无人值守任务被critical/GP-fault/OpenFile弹窗挂住。仅进程范围，未改全机WER、用户、AV或网络设置；仍把异常、退出和超时当失败。依据[Windows进程错误模式及继承文档](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-seterrormode)。普通自有子进程实际继承和父进程成功/异常路径精确恢复已通过，无故意崩溃。

固定工具标准流现在边读边保留有界快照；超时不再等待EOF后丢弃已收到错误。最多两段各2048字符原始文本仅由同一原Broker存入私有证据；普通响应只给已限定异常类型或摘要。普通匿名管道实测EOF前快照、4096字符上限拒绝、类型筛选通过。原准入/LPAC/零capability/原Job/对象权限/工具参数和自有C#样本不变，不为通过测试增加资源权限。

源码7a39567、嵌入e686fe0：60输入Broker/Library构建和61输入Bootstrap通过，后者复用原资格库F82A46E3而未重建。10PE/6managed、内嵌manifest核对通过；生产仅增加kernel32 GetErrorMode/SetErrorMode，测试未新增本机导入。证据work/tool-fault-build-r1/qualification.json。这还不是实际LPAC无弹窗证明，更不是PowerShell启动根因已修复。

## 待本人授权的两个系统操作

1. 一次本人UAC：仅将产品更新为新df6ae4f0、保持INACTIVE，然后只读manifest资源检查。既有552工具文件不修改，不新建工具目录，不创建Job/profile，不授予注册表权限。
2. 更新成功并独立核对15文件后，另一次本人UAC：一轮原Broker固定PowerShell7/Git/自有C#编译执行验证，应用上述已修改的异常处理与私有错误保留。保持严格LPAC、原Job和现有停止/拒绝/清理链。主期限40秒、排空1秒，异常只结束本次新建且持有句柄、映像/创建时刻匹配的确切Broker；不把退出当Job证明。不自动重试或恢复，不故意触发崩溃，不执行输入项目代码、真实Claude或网络访问；宿主SideBySide完整权限独立比较必须不变。

| 冻结输入 | 标识或SHA256 |
|---|---|
| 新Release | df6ae4f02e67434dbb91b9a0addaf80a |
| 新manifest | D2CABD45BCF2965F8BC982669C0478958B80CD5F22807CCB76134DE8B0626AE8 |
| Lifecycle库 | F82A46E34DC038E4C772AD0D14592E484C1C67DE30F1739C752A576FA8310B08 |
| 安装plan | 8350912756339CBF6931FF7258E3B97C195EED6FC910A7E59C936A1356446A60 |
| 安装helper | 70BB65DCC767DB56E8FCB5CE13C22D0443D1105D4C6B3C8BADE6EB3DF0A47686 |
| 运行plan | E763F4518B850D1CD34BA170953B2A68016B1473C4BF3B503A86BBBDAD91B4DE |
| 运行helper | D8068C760F9709819044AFB63AF15BF22BBE24BC0D3115BB0EAFCD557219991D |

work/tool-fault-control/system-operation-review.json为完整冻结审查。两个launcher普通Preflight已实际返回，未知参数拒绝，无本次UAC/claim。按用户指示和AGENTS.md，新工件安装/受保护运行需要具体授权和本人UAC；这两个操作尚未授权或执行。用户此前的两个df6ff338操作已完成并消耗，不延伸为本次授权。保持日常AV/驱动/FlClash/UU/网络、现有旧证据和包。全面敏感数据/网络/14项/GPU/项目编译仍未整体验收，历史蓝屏根因未关闭。
