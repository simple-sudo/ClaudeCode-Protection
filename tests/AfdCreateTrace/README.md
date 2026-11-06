# 有限 AFD 创建事件观察器

研发观察器，不能运行子进程、修改设备/WFP规则、调整Token或授予产品启动许可。
`--inspect`只检查SDK x64结构；普通身份调用`--run-fixed`在任何创建动作前拒绝。
真实采集必须另有固定工件/输入/输出及具体人类批准，由本人确认UAC；该文档不授权运行。

目标观察90秒、AFD provider E53C6823…、keyword4/level4、64KiB buffer、8–16 buffers、
16MiB circular ETL。不声称provider侧PID或event-ID过滤，可能含其他进程的网络元数据，
不请求数据包内容。原ETL只留新的受控Program Files研发目录，APP/RAP明确拒绝；
当前可信用户可读，管理员/SYSTEM可写，不改现有对象权限。根路径及session名固定且
必须全新，原StartTrace返回句柄与session GUID核对后才能停止，不能认领同名旧会话。
普通新目录控制已确认GRGX会映射为0x1200A9；使用后者核对实际目录DACL字节，避免
把等价掩码误当seal失败。就绪发布前核对实际ETL文件的APP/RAP有效deny，摘要先写新
pending文件、核对其deny后原子发布；停止后再核对ETL。这里仍需要真实原生资格，不能
用目录控制当受限身份读取拒绝或完整L3证据。
最终普通自有文件对照验证：有效APP/RAP deny接受，缺RAP deny及allow在deny前的
非规范DACL拒绝。只验证文件检查函数，真实trace文件的创建/权限/停止仍NOT_RUN。

只有ETW的start/enable/query/stop操作；正常期限或新AV/服务故障都只尝试一次停止自己
证明拥有的trace。原LPAC/Job/应用停止仍归原owner，观察器没有任何目标进程控制API。
失败不重试，不回收未知session、不删除证据；停止失败为UNKNOWN，需要另行恢复决定。
系统API阻塞时不能保证硬截止；外部只保留原进程句柄等待并记UNKNOWN，不能强停或认领
同名替换session来假装清理成功。
丢事件/缓冲失败/可能绕卷均不能证明完整覆盖。原进程Token权限/提升事实前后不同时
不算通过。当前普通结构/拒绝检查不是原生trace启动/权限/关闭的实测证据。

本机事件1000包含Location/Status/ProcessId。固定镜像调用点：family35的Location3EB、
flags2为3E9；3F1是creator SD捕获失败，3F3是transport创建失败，3F4为成功尾段。
需实际事件、原owner闭合后释放的actor/输入/返回值及对应镜像资格共同核对。
缺事件不能当分支不存在，事件元数据或离线反汇编不能当实际采集证明。

2026-11-06固定联合实验原观察器终态125，无ready/terminal，未发起LPAC或读ETL；
后读固定根不存在。失败阶段及内核trace闭合仍UNKNOWN，原审查C23381A3…许可消耗，
不从缺目录或进程退出推断无副作用。原工件/输入/回执保留，未自动重试或恢复。

后续ObserverOutcome用有限0x43500000标记的进程退出码报告首次失败阶段，原UAC
发起者从自己持有的进程句柄读取，无新IPC、路径参数、目标控制或权限。旧125、崩溃码
及未知值保持UNKNOWN；此通道不证明trace拥有权、停止或清理。完整错误仍仅在受控
回执可发布时保留，不通过退出码传原始Token数据。后续失败不覆盖首次失败阶段。
新版BUILD、普通结构/创建前拒绝及实际普通子进程退出码传递通过；管理员采集NOT_RUN。
不解锁或重跑旧冻结版本；后续仍需新固定审查与具体人类决定。

下一固定版本A300344F…实际阶段TokenBefore（1129316357），没有ready/terminal或原
LPAC启动。随后普通自身检查复现TokenElevation(class20)零缓冲查询错误24；它是
固定DWORD，改成直接4字节精确读取，class3权限数组仍用原变长严格查询。普通修正
读取成功，不证明原提升场景已修复。`--inspect-own-token`仅读自身有限标量，无trace/
文件写入/权限变化；主采集入口仍强制完整提升/非AC/无冒充及前后权限一致。
新目录创建并seal后才进行驱动/Token门，以便门失败也能留有限真实诊断；采集门仍全部
在StartTrace之前。前后TokenObservation仅保留query kind/大小/失败码/提升标量，成功
查询的GetLastError不作为错误，查询开始清空旧returned length，首次失败阶段不被覆盖。

93B193D4版本首次真实采集/自身Stop0/Token保持通过，原项目Run失败未释放结果且
ETL未读。691个64KiB缓冲/16MiB circular存在绕卷可能，不能称完整覆盖。后续版
请求ETW manifest event-ID过滤，仅event1000，keyword4/level4及90秒/16MiB不变；
6字节EVENT_FILTER_EVENT_ID、16字节descriptor与48字节version2参数已普通布局/
内容检查，不代表Windows实际过滤已验收。原PID不在provider端过滤，其他actor创建
元数据仍可能出现，完整覆盖仍须检查loss/wrap。新session/目录仅用于新实验归属，
旧受控ETL/回执原位保留，不认领/停止旧session，不为绕过检测改名。

后续TCPIP定向版本在同一自有trace请求AFD1000，以及本机TCPIP provider
2F07E2EE…/keyword1024/level4的1001、1010、1011、1012、1013、1562六事件。两次
Enable仍只管理同一StartTrace返回的句柄，失败仅停止自有trace；不改Token、WFP或
设备权限。TCPIP事件可能含其他进程的本地socket地址等元数据，留新受控ETL，不请求
包内容。普通数据布局/固定六ID通过，真实双provider启用/采集尚NOT_RUN。
FlushTimer改为4秒，目标减少稀疏事件的整缓冲刷新开销；90秒/16MiB不变，不预设
不会绕卷。停止后仍核对loss/缓冲/哈希；该调整未进行新的系统实验。
