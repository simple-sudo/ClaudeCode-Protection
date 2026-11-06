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
