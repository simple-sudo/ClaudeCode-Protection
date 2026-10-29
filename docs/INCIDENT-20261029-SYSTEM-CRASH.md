# 2026-10-29 蓝屏重启：项目数据处理窗口

当前结论：两份原转储的有效符号栈强烈支持相同故障机制：ProtectionBroker目录枚举，经Wof/FLTMGR/NTFS，在Ntfs间接调用处跳向空地址。造成错误调用目标的根因/责任驱动及具体源码调用点仍UNKNOWN；不能将WinDbg分类直接升级为Wof自身缺陷，也不能排除本项目触发。用户后续明确重新授权修复验证，名称查询修复已通过下方限定资格，旧blanket build/runtime停止要求不再阻塞这一授权范围；原事故负载/安装/自动恢复不因临时样本通过而放行。真实Claude/AV/FlClash/UU/全机网络限制保持，事故开放，整体goal未暂停/完成。

## 后续授权的实际数据操作已正常返回，事故根因仍开放

08:31Z安装ac570b47（INACTIVE）后的四文件daily数据往返退出0，session d57cf00754fc45c8b599617f2c5e41be；原Broker/ProtectedSession固定Git、闭Job/精确清理和成功账本导出条件均已走通，结果经普通用户比较/提取及独立摘要核对。成果快照也已复用同一class12名称查询，不再走旧元数据枚举；这把缓解证据推进到真实生产数据链。此前90079258第一次请求125保留，查出调用者令牌QUERY不足以支持WindowsPrincipal检查，修复并普通自令牌复现/复测后才使用新工件和人工UAC。未复跑旧事故会话或自动恢复，不能从新成功断言旧中断状态已清理，也不归责Wof/AV/硬件。boot仍05:44:54.5Z，AVP/BFE/FlClash/UU保持；证据work/workspace-pipe-repair-control，完整标识与摘要见STATUS。

## 较早修复安装，实际Broker只读入口正常返回

用户明确允许安装5bc986e1并仅做Broker只读及相关后续。07:37:29Z普通launcher持有control/source祖先和20个工件，核对helper1FB8496C、planE40CC54F、最终库70EF78FE；本人UAC后helper34408创建07:37:31.155Z。

- 07:37:41.631Z，Bootstrap4204退出0，PINNED_INACTIVE_UPDATE_COMPLETED；ecb06a→5bc986e16e9a44ca856a1b56b90328aa，manifest048E974CD4611B4DB7B577B64DAA5842C5CA02FE08D63298382BBC001FBBEC37，operation=d6e5f46005234e67b3124a7ce175cbd0，INACTIVE。现有更新owner的闭合Job/隔离/指针检查均是操作前置条件，没有放宽为自动恢复或删除遗留。
- 当前指针独立回读相同新版本/manifest/operation。07:37:44.500Z，原安装Broker inspect-session-environment退出2/MISSING、stderr为空。缺少环境意图是原接口的明确返回，未自动配置timezone/locale或借此签发准入。其VerifiedVersion和LifecycleRecovery状态清点已使用新名称查询正常完成；这将修复证据从临时样本推进到安装后实际调用链。
- 07:37:45.981Z完成回执REPAIR_INACTIVE_UPDATE_AND_INSTALLED_READ_ONLY_COMPLETED；launcher07:37:46.008Z取得helper退出0。无测试会话、profile/Job创建、WFP修改或自动恢复。不是凭无新事件猜测成功。
- 普通用户独立核对15个安装文件hash及文件/5目录trusted owner、受保护DACL、无不可信写grant均通过，不执行写入测试。旧ecb06a及659d76df未删除/改写。
- boot仍2026-10-29T05:44:54.500Z；AVP/BFE运行，FlClash/Core24520/17272和UU服务7056保持，无产品测试进程。有限Application AV事件0，完整厂商覆盖UNKNOWN。

原受保护回执位于ProgramFiles/ClaudeCodeProtection-Update-5bc986e16e9a44ca856a1b56b90328aa，选定小型证据副本work/names-only-control/installed-evidence；completed.json SHA256=67F00587CA0EB51E3BB43854C57BFD02AF901E48DF56B1DC2F38CAD1D2D0DA14，current-readback=7CCC532057EAFD791A8AF001E29E8A666413327A35A4BE4ABA0F8B06200F47FA，ordinary-installed-readback=07D6036ABE7A3F98B0EB11B7C4D4045E6D3DC7373218B0C3D1DD040DDEC0C012。

继续同一授权下的inspect-installed-fence只读隔离核对，使用4694CF45…E7EC8固定helper。首次UAC在07:42:28Z返回“The operation was canceled by the user”，无helper创建/无Broker开始或结果，原failure SHA256=C4B0AA1028F47C3F514A4D5657503BE46712BB7D4F0C0ADCE1E0E9AC312481F3保留，没有自动重试或换入口。

用户随后明确“uac再弹一次”；保持同一helper/包/操作/输出目录，r2仅更换launcher尝试claim与启动日志名，原失败不覆盖。本人UAC后helper21264退出0（07:43:57.935Z），原安装Broker inspect-installed-fence退出0。观察1个健康subLayer、六角色ipv4-address/ipv4-port/ipv4-protocol/ipv6-deny/quarantine-v4/quarantine-v6，filterId107465–107470，全部Present/Persistent/PolicyMatches=true，PolicyModified/JobApiCalled/NetworkBehaviorQualified=false。没有执行Create/Reinstate/迁移/恢复函数，现有WFP只读事务不改变策略。

fence-read-completed.json SHA256=0DD871C32B7DEA605E563F00D27BC779B89B5FB66D692BA30F724E53FAAB3D9D，原stdout SHA256=3008E418C49CF4E22DB2F710FBBD22604C597B95B6E495480EE18D7857476E02；副本同样保存在installed-evidence。boot仍05:44:54.5Z，FlClash/Core24520/17272、UU服务7056，未见Broker/Bootstrap残留。此次安装及两条生产只读入口正常结束，为有效修复进展；不把系统对象观察称为网络行为或原负载恢复证明。下方安装前“尚未安装/待决定”为历史。

## 本人重新授权后的构建与原生资格

### 最终安装候选（尚未安装）

推进原安装链时发现ecb06a清单尚未在更新器精确prior pin中；d38901d仅增加85170193…238C6这一项，不放宽闭合Job、FullQuarantine、当前指针或原子生命周期检查。新53输入的Broker/Lifecycle/DirectoryNames冻结构建0错误/警告；因库字节变更，独立审查后pages-only与owned-fixture对最终库再执行一次，均0，484项跨页及原拒绝边界全部通过。没有重复不变实验去制造更多PASS。

最终库SHA256=70EF78FEE0D73FE5FF9B23B446B15FE928EFE4DB5C8DA0B52FEF50453470B1D5；DirectoryNames DLL=A84A2E87545FA9D73D1137D4C6C1F2A0437C31324CB68CEEE575E1BFAF282BC2。run-result SHA256=855950AF1C7754A502D4F44A810F9144532FFB811CCE12472DE760D4071DF9E9，构建回执E36F807D2A648652AEA9CB4D5714C14935ED45F9CBB3242B73A3A28C8B07FB3E，保存在work/names-only-product-build-r2。之前05316042库及其成功原样保留，不冒充最终包测试。

cf63e34嵌入修复包5bc986e16e9a44ca856a1b56b90328aa，manifest048E974CD4611B4DB7B577B64DAA5842C5CA02FE08D63298382BBC001FBBEC37；Bootstrap离线build0且使用--no-dependencies/BuildProjectReferences=false，实际复制的库与上述资格字节一致。Bootstrap回执SHA256=E92640226FB07A1864068728E56936F73E089F81E7EAC236FA4F4D21AACFF440。包仅3项Broker资产变化，11项原字节复用；准备脚本首次计数写成5/9，保留原报告并按完整清单更正3/11，不据此重做复制或构建。

20文件工件闭合、10PE/6managed元数据及内嵌清单逐字节核对通过，无module initializer。准备的受控系统动作只有inactive更新，以及安装后的原Broker只读inspect-session-environment：它经VerifiedVersion和LifecycleRecovery对实际布局/私有账本做名称清点，不产生会话或恢复。缺少环境意图时退出2/MISSING是有效只读观察，不能改成配置/保护PASS。安装路径仍需用户决定及本人UAC，未启动launcher或改动现有安装。

固定审查：install-plan SHA256=E40CC54F1293107DBDD6EBAF433BE1D2D0D161F77D8869E3B80DBBAFDFADF8C6，helper=1FB8496C6C005389D58AFC45CFBA7CB65A725E71CA18EF71C6A9D5272F0F775F，launcher=CCCB605B37C02BC7822502334C8B1AE945C23B41BE0ABAF145B7E591E5D247CB。全部在work/names-only-control，批准范围不含旧process-workspace-data/qualify/recover/网络修改。事故开放，原负载和恢复仍NOT_CONFIRMED。

### 首轮名称查询资格

用户明确“允许你进行验证，之前的要求停止可以修改掉”。冻结2173dcb的51个输入，经原审查SDK8.0.422/ref8.0.28、独立离线输出/空源/SDK导入清单核对、禁止分析器及共享编译，restore/build均0，零警告/错误。生成文件独立元数据审查：两份x64 managed程序集无module initializer，测试无直接PInvoke，依赖仅自身和Lifecycle；新增查询绑定为WindowsPathSeal.NtQueryDirectoryFile/ntdll，固定dotnet 8.0.28启动。

- Lifecycle SHA256=05316042C9D040BA20DF007576981ABA25EBE817F4347408C00AEDF4FAAEB5CC；DirectoryNames DLL=C89DE4F2889179774A606B58BE177A1D1CE7B867B88C0AD30949429F98A64FAB。
- pages-only=0：完整/Unicode/dot/255字符名称与截断、非法长度/偏移/续项重叠、隐藏记录、UTF16错误、路径片段等拒绝通过。
- owned-fixture=0：原生产方法清点全新普通用户临时目录，初始483项+后加1项；编码记录总长度超过64KiB，强制真实分页。空目录/Unicode、文件和目录名称、嵌套不递归、重复独立游标、容量拒绝、后续新增及持有DELETE权限目录句柄时的查询均通过。样本保留，没有递归删除或私有state读取。
- 运行终态NAMES_ONLY_BOUNDED_QUALIFICATION_PASSED；开始/终态、stdout/stderr、工件审查和原样本在work/names-only-qualification-20261029-r1。run-result.json SHA256=E0FA45AC48DC971721E1CC4855AE1CC7423343FFEC1B090D00F651E6C33928DE，build receipt SHA256=B8070E23F24ED60BBC4AD63189C09F667A741D99048E8D3701E4B44A385CDAC2。
- 本轮普通用户执行，无UAC/安装/产品入口/AppContainer/Job/WFP/系统设置变化。boot仍05:44:54.5Z，AVP/BFE运行，FlClash/Core24520/17272及UU服务保持；有限Application AV事件0，完整厂商覆盖UNKNOWN。没有产品测试进程遗留。

限定VERIFIED为名称解析和本机名称查询行为，不能记为事故已解决；安装后的版本核验/私有状态清点/资源生命周期仍待证据。下一步复用这份合格库准备实际Broker/Bootstrap工件，保持具体审查和人工UAC，不能再用旧冻结反复阻断同一限定修复资格。下方“未构建/待授权”为此前阶段历史。

## 2026-10-29 06:53Z：本人授权的已安装WinDbg比较完成

### 继续解决：已接入名称查询修复候选，未结案

用户随后明确要求继续解决，不能把不完全定责当成结案。追加离线反汇编仅回答可规避的分支问题，未再次执行产品或复现事故。current-r6.txt中WofPreDirectoryControlCallback+0xb7–0xea按FileInformationClass分流：掩码900000600000000Eh包含1/2/3/37/38/60/63，另处理78–81及33；类12不在其中，走+0x8da的退出路径。类2进入+0x472，随后转换为0x4e并在+0x695同步调用下层；与两份事故栈一致。字段含义对应微软[FLT_PARAMETERS.QueryDirectory](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_parameters)。这是当前匹配版本的分支证据，不是证明错误内存由谁写入。

current-r6.txt SHA256=2D8781D7DDF7879E1733023F389158D5D43FB9E0D82C9D2CB38FAE9B216CC01D；07:11:30Z追加分析的GUI31932及其引擎也已按精确身份结束，原dump摘要再次一致。没有遗留本轮新增分析进程。

[.NET 8.0.28实际实现](https://raw.githubusercontent.com/dotnet/runtime/v8.0.28/src/libraries/System.Private.CoreLib/src/System/IO/Enumeration/FileSystemEnumerator.Windows.cs)对普通Directory枚举请求FileFullDirectoryInformation（2），不是只查询名称。修改通配符或限制递归并不会改变它的类别。采用微软文档支持的[NtQueryDirectoryFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerydirectoryfile)及[FileNamesInformation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_names_information)（12）作为具体修复候选，避免本次观察到的Wof元数据转换路径；不禁用Wof、不改系统压缩/驱动/AV，也不添加另一个执行器。

SOURCE / INTEGRATED：原WindowsPathSeal新增有独立同步游标、持有父目录且核对同一NTFS身份的名称清点；状态清点、版本布局、精确卸载、profile与task清理已接入。名称只作发现，原有逐项文件身份/ACL/创建tag/无reparse与关闭Job要求仍保留。未匹配状态名的对象不被授予权力；同名前缀目录将由后续文件验证拒绝，不静默略过。缓冲64KiB、记录偏移/UTF16/单叶名/重复/容量/x64 ABI及协作时间预算均拒绝不完整结果，不回退到原完整元数据枚举。同步内核调用本身不可由这个协作预算抢占，不宣称硬超时能阻止蓝屏。

六个产品项目及PolicySmoke/DirectoryNames测试源码的非生成语义检查0错误/0警告。测试已编写：原始记录截断/越界/奇数长度/续项重叠/UTF16/路径片段等拒绝；单独的普通用户入口只创建自己的新临时样本，调用同一生产方法核对空目录、Unicode、文件/目录名称、独立重复游标、容量拒绝和后续新增。没有编译、运行或安装这些新源，所有测试仍是待执行，不得标PASS或写成“蓝屏修好”。

下一项具体资格是冻结的Lifecycle库+DirectoryNames离线构建、独立工件审查，然后普通用户pages-only及owned-fixture；不调用Broker/Bootstrap、读取私有state、创建AppContainer/Job/WFP、运行原事故请求、改变系统或要求UAC。这会执行新的原生目录查询，仍受当前build/runtime事故hold约束，须本人对该限定范围作出新决定。原安装/未完成会话/工件均保留，事故继续开放。

### 两次故障证据

用户后续明确授权调用/操控已安装Microsoft WinDbg，UAC均由本人确认，替代下方历史的手动回传等待。使用WinDbg 1.2610.1001.0，未安装调试驱动、附加活动进程或内核、执行产品、修改ACL/安全/网络设置。安装程序显示已安装，没有再次安装。

| 核对项 | 2026-10-27原转储 | 2026-10-29原转储 |
| --- | --- | --- |
| 原文件 | 102726-15281-01.dmp | 102926-16031-01.dmp |
| 转储内时间（UTC） | 07:56:18.117Z | 05:44:40.737Z |
| Bugcheck | 0x1E(C0000005,0,8,0) | 相同 |
| 当前进程（内核截短名） | ProtectionBrok | ProtectionBrok |
| 入口系统调用 | nt!NtQueryDirectoryFile+0xe0 | 相同 |
| Wof栈帧 | WofPreDirectoryControlCallback+0x695 | 相同 |
| NTFS返回位置 | FindNextIndexEntry2+0x675 | 相同 |
| 后续NTFS帧 | NtfsContinueIndexEnumeration+0x10e / NtfsQueryDirectory+0xd32 | 相同 |
| 异常上下文 | RIP=0，执行访问违例 | 相同 |
| 完整符号分类 | AV_Wof!WofPreDirectoryControlCallback | 相同 |
| 分类摘要 | 3ae300a6-24ac-569b-3ce2-789a00065d56 | 相同 |

两次地址因重启不同，但模块内偏移与相关链一致。匹配符号的Ntfs反汇编显示返回位置前一条为guard_dispatch_icall调用；结合RIP=0，支持空目标间接调用。初始trap不含全部寄存器、栈含一个未命名帧，不把所有参数/回溯帧都视为完整可信。没有证据据此认定Wof写坏内存、Kaspersky冲突、GPU故障或硬件正常。当前核实的是共同失败路径，责任归因仍待更具体证据。

内核、Ntfs及Wof图像均10.0.26100.8875，FLTMGR为10.0.26100.8521；提供System32/驱动图像路径并启用严格符号匹配，使用微软公开服务器下载的对应PDB。未启用忽略GUID/版本或强载错误符号。主机只读版本查询为Windows 11 25H2 / 26200.8875，不将调试器通用的Windows 10内核标签当成宿主产品版本。

原有分析失败继续保留：current-r1内核符号错误；current-r2未产生分析日志；current-r3中.sympath将后续分号内容当作路径元素，破坏原本已匹配的路径。修正为启动参数日志/图像/符号路径与逐行的纯调试命令文件，current-r4及previous-r2取得内核/NTFS栈；补齐Wof/FLTMGR符号后，current-r5及previous-r3回答具体函数问题。日志完成标记、符号及内容共同确认分析完成，不以GUI退出码作结论。

原始日志/符号来源及摘要/固定脚本/授权启动回执保留于忽略的work/windbg-installed-20261029：

- current-r5.txt：36380字节，SHA256=A4203689C2AE1C263DD8A71FCCD2B0A9FC54525ADD13D9D5A2B723048E204542。
- previous-r3.txt：33149字节，SHA256=2558DB9BA799D7A134FBCE71D2F19151A632B852EE66A20551D628F055EBF41A。
- 06:53:47Z本人UAC固定收尾复核两份原dump摘要仍与此前相同，未复制/上传/改ACL。精确身份/创建时间/映像/签名核对后结束本次7个分析GUI及其7个引擎，14项终态保存；GUI强制结束为-1、引擎退出0，不能记为调试器自然成功退出。原先空白WinDbg27332/32124未动。
- close-owned-result.json SHA256=923380E7CCC5571F2B56B5F6F44ED1E2770BAB67D11E94C6887F928DBF355B31。

只读CompactOS查询为当前未压缩，未改变状态。另找到一份[用户直接发布的相似栈报告](https://learn.microsoft.com/en-us/answers/questions/5814272/wof-sys-bsod-0x139-kernel-security-check-failure-i)，包含相同Ntfs/Wof偏移，但其系统/bugcheck不同、归因有争议，并非微软承认或修复公告。仅作为线索，不接受其“确定Wof/并发根因”或压力复现/改系统建议。

源码只读追踪：ProcessWorkspaceData在执行输入操作前以及ExecuteResourceQualification开始处调用LifecycleRecovery.AssertNoPending；它经FencePlan等进入ProtectedState.ListLeaves的目录枚举。此为当前共同前置路径的优先排查点，不是已确认崩溃源码行；小转储缺少IRP内容及可用NTFS blackbox，不能确定目录、原查询参数、CLR调用栈或更早破坏源。现有无新会话回执与这个早期路径相容，不能据此宣布从未创建过资源。后续应围绕这一具体调用链设计修复/资格，不重复已回答的栈比较或直接恢复产品负载。

依据微软文档：[启动参数](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/windbg-command-line-preview)、[逐行调试命令文件](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)、[公开符号](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/microsoft-public-symbols)。以下保持事故过程中的原始观察与失败，不视为当前尚未运行WinDbg。

## 确认事实（UTC；括号为America/New_York）

- 05:44:27.873Z：普通launcher持有源/控制目录及21个固定输入，记录计划/Helper/Library摘要，等待本人UAC。没有自动确认。
- 05:44:29.875Z：记录elevated PowerShell helper PID1868启动。工具会话后来丢失；进程现已不存在，未据观察失联重启。
- 05:44:37.920Z：受保护helper保存Bootstrap退出0及`PINNED_INACTIVE_UPDATE_COMPLETED`。从659d76df更新为ecb06a57929a45d1adf9dd1d8415c4a4；manifest=851701939666F35F4E0C4323C408E00690B4CFB96165C81F5C6092AF5D8238C6，operation=adfe129138634224858b9bea430a9570，仍INACTIVE。
- 05:44:39.556Z：privileged current.json回读相同选择。它是崩溃前回执，不冒充重启后的直接私有state回读。
- 05:44:40.343Z：故意错误输入SHA的`process-workspace-data`返回125/InvalidDataException，stdout为空；记录已落盘。随后helper按源码启动同一操作的正确摘要请求。
- 正确请求没有`resources.stdout/result`、工作区结果/清理、completed/failure或launcher终态记录；不能记成功、失败退出码、Job归零或恢复已完成。最后落盘点不等于实际执行停止点。
- 05:44:54.500Z（01:44:54）：OS本次启动时刻（CIM与System12一致）。System41记录非正常重启；System1001明确bugcheck `0x0000001e (0xffffffffc0000005,0,8,0)`，ReportId=eec06fd4-ebfe-4c8b-8971-9d3a8e945579。Event6008另报前次意外关机时间01:43:12，与应用落盘时间不能直接拼为精确崩溃时刻，保留原值。
- 小转储`C:\Windows\Minidump\102926-16031-01.dmp`存在，7226559字节，LastWriteUtc=05:45:07.601Z。CreationTimeUtc是较早的2026-05-15，不据文件创建时间推断本次事故。普通用户读取SHA被UnauthorizedAccess拒绝；没有改ACL、复制转储、上传或运行调试器。

微软对[0x1E](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x1e--kmode-exception-not-handled)的解释为内核异常未处理，C0000005为访问违例；这些数值本身不能锁定驱动、AV、GPU、内存硬件或本项目。与2026-10-27事故参数相同，也不能据此认定根因相同。

## 重启后的有限核对

05:48Z普通用户核对：新受保护staging与ecb06a版本目录存在，旧659d76df manifest仍保留且摘要未变；没有ProtectionBroker/Bootstrap/Center/daily产品进程。AVP/BFE为Running；FlClash24520、Core17272；UU对应GameViewer/Healthd/Server/Service进程均存在。仅为进程/服务观察，不保证远程稳定性、WFP实际对象、当前指针或原未完成profile/Job恢复。

事故过程中早期`Directory.Exists`曾返回false，稍后明确目录枚举读到了崩溃前落盘文件；不把早期false当成不存在证明，不据它回滚或重复安装。正确请求在私有state中的最后持久阶段、是否已创建profile/Job、重启后的精确恢复均待独立读取。不要自动执行recover-session-resources、quarantine、测试或重新安装来把未知变绿。

原始System/Application事件XML、launcher/计划摘要、安装/当前指针回执、错误输入拒绝及文件时间库存保存在忽略的`work/system-crash-20261029-0544Z`，16个文件及校验表；源包/私有状态/所有工件和旧失败保留。当前库SHA=2B59401D305E3FA7B3A8387B7397E6F5EC5B1C66CD44DCCA0430BEE102578788，helperSHA=7B25425FC2588A4B47133776D004D28A6EEBC873814C47915DCAD73AD45AE7ED，planSHA=14736D26C9856825B2FDF0C30DADB1A8279DDCF5EABBC487DB8175E3361D6FFA。

## 下一项有效证据

### 05:58Z本人UAC的只读补充

固定只读采集没有加载产品/调试器、执行恢复或修改输入。r1退出125：脚本把ISO带Z时间转换成Local，再与LastWriteTimeUtc比较，导致时间窗口误拒绝；仅确认了current指针，不能把空RecentRecords用于任何判断。原脚本/失败/输出保留。r2只把时间边界改为DateTimeOffset.UtcDateTime，重新审查并由本人UAC后退出0，耗时307ms。

- 重启后直接读取current.json，确认ecb06a57929a45d1adf9dd1d8415c4a4、manifest85170193、operationadfe1291仍为INACTIVE。
- 有界库存1501项；明确UTC事故窗口05:44:27Z–05:45:10Z内，没有匹配已定义resource-session/profile/Job/task/data回执前缀的新文件。这不是全量重启恢复证明，不等于产品请求完全未执行；没有据此自动清理。
- 本次原转储7226559字节的SHA256为B81AB79BF339A8FB89833C564F86483B950409B3D836BA7D80D46CEC09BD47F3。未复制、上传或导出转储内存内容。
- r2报告SHA=8E0C715B282F39CE113E3AEAEF38F6922163B6D4D41095CF5E31F903F636E903，保存于work/system-crash-20261029-0544Z/readonly-r2；r1报告3506711A01A045755F5A76E6100683BA244A0E9A308B89ACD167F3F1B15BBE95原样保留。
- 旧官方调试器12个已审查文件的当前摘要/长度再次静态核对一致，未执行。旧自动审批拒绝原因仍只有blocked by policy，不换工具或入口自动绕过。

用户明确选择本人手动WinDbg分析两份转储，开发侧等待有效文字结果，未请求停止或完成整个goal。此前普通读取AccessDenied是当时证据，不覆盖本次经本人UAC的只读成功。

下一步是比较两份转储的有效异常上下文/模块/调用栈，不执行或恢复负载。排除/修正具体原因前，新产品系统验证BLOCKED，普通旧入口仍保持hard stop，目标未完成。
