# 当前开发状态

日期：2026-10-27（America/New_York）；以下安装/界面实测发生于10月26日晚。用户已批准阻塞部分继续推进，并补充[完整产品方向](PRODUCT-DIRECTION-20261026.md)。本地自主开发与小范围提交，既有origin保留，不推送。不同源码与工件不互相继承运行证据。

## 当前成果与证据级别

| 工作 | 级别 | 当前事实及限制 |
|---|---|---|
| 当前六个项目 | SOURCE | 非生成语义检查0错误/0警告。日常CLI7源、GUI3源、工程11源、生命周期21源、broker1源、bootstrap1源；共享源重复计入其消费者。工程项目本轮未构建/运行。 |
| 当前产品四项目图 | BUILD | 457d22d的CLI、WPF GUI、broker及生命周期库离线restore/build成功，0错误/0警告。40项源/项目/资源，固定SDK8.0.422及引用8.0.28，无第三方包。work/product-final-build。 |
| 独立安装引导 | BUILD | 62986ed嵌入14资产批准清单，bootstrap单独离线构建成功，未重编生命周期库；共享同一已构建DLL。实际PE资源摘要与源清单一致、无模块初始化器。work/bootstrap-build及product-install-control/plan.json。 |
| 首次未激活安装 | INTEGRATED，成功路径已运行 | 人类UAC→固定摘要/全路径及文件租约→新受保护bootstrap→全包预检→全新私有状态→现有stager/版本核验/INACTIVE指针/完成账本，实际退出0。没有WFP/Job/Claude或用户配置修改。中断/重启/重复安装/卸载未据此通过。 |
| 安装后字节与权限 | VERIFIED，仅14文件与当前权限负向 | 14资产摘要/长度与批准包一致，管理员owner/受保护DACL；普通用户写打开全部被拒绝，私有current.json读取被拒绝。outputs/installed-package-readback.json。不是抗管理员攻击或断电验收。 |
| 已安装GUI离线检查 | INTEGRATED，当前真实调用链 | 普通用户界面“检查环境”→已安装CLI→inbox PowerShell→显示两阶段结果→当前用户报告。baseline退出0但APIsAgree=false；audit退出2，9 PASS/3 FAIL/8 UNKNOWN。保护仍未激活。配置修复/撤销按钮及在线按钮未运行。 |
| .NET/WFP只读诊断 | VERIFIED，仅只读native路径 | fc113de的.NET8.0.28/x64布局13项符合；普通用户GetByKey仍Code5。独立受保护资格副本人类UAC后读取固定V4/V6内置层成功，各42字段、Id48/50。没有过滤器、Job或跨对象原子策略快照。 |
| 固定管理隔离 | BUILD；quarantine功能未运行 | 当前已安装broker接受固定quarantine及两个只读诊断。quarantine核对管理员、固定私有状态、当前整版和自身路径后调用既有精确WFP/Job owner；停止/最终观察错误保留。尚非已交付Kill-Switch。 |
| 用户配置维护 | BUILD，尚无功能/故障运行验收 | GUI/CLI共享当前用户目录、独占锁、刷盘备份、先行pending及摘要冲突拒绝。未迁移旧备份、未修改真实设置。 |
| 原S1/S2及8a9c4b1构建 | 历史限定证据 | 原日志、失败、修正和UNKNOWN均留原处；见[原S1/S2](VALIDATION-S1-S2-20261026.md)与[首次broker构建](BROKER-OFFLINE-BUILD-SCOPE.md)。当前安装不升级这些历史结论。 |
| 全量保护宿主/故障/卸载 | 尚未完成；集成受缺失实现阻塞 | 原子进程准入、代理审核/开放、完整运行租约、Watchdog/漂移、资源最终清理及相应故障矩阵未贯通。首次fresh租约只适用新身份从未开放准入，不能授权更新/卸载或冒充一般进程所有权。 |
| 真实Claude登录/推理/会话 | DEFERRED_BY_USER | 不计通过，不阻碍独立工具能力。 |
| 完整产品 | 尚非DELIVERABLE | 已有本机安装后的离线检查切片；持续防直连、故障恢复和安全卸载仍须交付。 |

INTEGRATED是实际调用链；VERIFIED只适用于表中明确功能及负向；BUILD和SOURCE不能替代保护验收。用户授权是推进权限，不是功能通过。

## 本机安装及证据位置

- 包发布标识：`806b2b6997c84e0da4db46c9d267d7a0`；manifest SHA256：`1D83FA034A65DC58D1FFEB9C4F3A54EA52F1C3B7AF6156A54C752FA5D8801BAC`。批准清单在src/ProtectionBootstrap/ApprovedPackage.json；它是当前精确包的身份，不是任意新构建许可或AV安全结论。
- 受保护引导：`C:\Program Files\ClaudeCodeProtection-Bootstrap`；正式代码：`C:\Program Files\ClaudeCodeProtection\versions\806b2b6997c84e0da4db46c9d267d7a0`；私有状态：`C:\Program Files\ClaudeCodeProtection-State`。无服务、计划任务、自启动、全局PATH或快捷方式注册。
- 普通用户GUI：上述版本内`bin\center\ProtectionCenter.exe`；当前只实测“检查环境”。此前UI正常关闭因computer-use激活失败而保留窗口。10月27日用户明确要求不用就关闭后，核对该自建测试进程PID/创建时间/路径/摘要、后台操作已结束与报告已保存，精确结束此GUI进程；未按名称或进程树批量终止。关闭记录在outputs/installed-gui-close.json。没有保护后台运行。
- 实际安装记录在受保护bootstrap的install.stdout.txt/result.json/completed.json。原始控制、pins与源码/工件记录在work/product-install-control、product-install-recovery-control、bootstrap-build及product-final-build，不入Git。
- GUI报告在当前用户LocalAppData下ClaudeCodeProtection/reports；本次文件environment-20261027-035756-c34de8.json。摘要与状态汇总在outputs/installed-gui-audit-summary.json，界面文字在outputs/installed-gui-after.txt。报告及原始数据不入Git。

## 失败与修正

2026-10-27接续目标模式已实际建立。已安装固定`quarantine`首次经本人UAC执行，返回3：安装专属WFP事务内校验抛InvalidDataException，QuarantineObserved=false；登记Job为0，不能据此计保护成功。原记录在`C:\Program Files\ClaudeCodeProtection-Quarantine-20261027`及work/installed-quarantine-control。无Claude启动、FlClash/Core PID20944/14268不变、AV/BFE运行，有限Application观察无AV事件，完整告警覆盖UNKNOWN。当前异常缺固定细分阶段，根因待原生对象契约资格核验；不放宽检查或重复盲试。

新增固定`qualify-wfp-objects`仅SOURCE：受保护独立资格宿主、专用合成package SID及随机对象键，只在未提交事务内观察本次对象安全描述符/标量，必须Abort并独立回读两对象不存在；不打开安装状态，不进入生产quarantine或只读inspect命令。六项目非生成检查0错误/0警告；首次checker因报告父目录不存在退出1，建目录后通过。此项用于定位本次真实失败，不是防泄漏验收。当前生产安装仍为旧包。

1. WFP首版普通用户事务Code5/BeginWfpTransaction保留；固定内置元数据改为独立GetByKey后仍Code5/ReadBuiltinConnectLayer。管理员只读成功不覆盖这两次普通用户失败。读API与事务分别要求layer READ和engine BEGIN_READ_TXN，见微软[LayerGetByKey](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmlayergetbykey0)及[TransactionBegin](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionbegin0)。
2. 首次资格复制因PowerShell5.1不存在的FileSystemRights.ReadWrite枚举失败，原空资格目录保留；显式ReadData|WriteData经自建单字节文件验证，在新的-r1资格目录成功。资格目录不是正式产品根。
3. 产品图首次构建GUI因共享源码缺少System.IO失败；真实WPF默认global usings不含IO/Http，原checker超集漏检。修复共享源和checker后新目录完整构建成功。失败在work/product-payload-build；修正版在product-payload-recovery-build，最后输入绑定修正另在product-final-build。
4. 首次安装辅助脚本生成时误改载荷EXE名，固定输入核对在创建目录前失败；原脚本/终态保留。修正全部20项与计划逐一一致后，新控制目录运行成功，没有改名任何实际工件、没有用重包装绕过AV。

## 下一主线及安全边界

继续复用当前生产owner，实现精确身份的原子进程准入与代理限制；优先用自有合成进程独立验证IPv4/DNS/UDP/IPv6阻断、代理失效、控制器崩溃和恢复，随后接Watchdog及精确卸载。不得把轮询停止、配置正确或代理响应当无直连证明。

当前API不一致仍需只读分项定位；代理owner路径不可读保留UNKNOWN，不能按名称放行。UI离线检查的FAIL/UNKNOWN与旧S2各自独立。配置维护的冲突、中断、备份损坏分支仍需有界实测。

卡巴斯基事件未解决，不执行退休EXE/旧聚合selftest，不改AV或规避拦截。有限Application观察未见新AV事件，完整厂商告警覆盖UNKNOWN。AVP/BFE保持运行，当前窗口FlClash/Core PID一致，真实Claude规则仍禁用，原settings摘要未变。出现新告警立即停止。

FlClash Global、系统代理及TUN保持当前日常状态；全机时区/IPv6等可按用户新指导设计为有必要性、影响说明、明确选择与冲突安全恢复的高级能力，本轮没有实施。普通旧Build/Assert/cmd硬停止仍留作防误用；已授权且具体核验的当前路径不再以“等待相同许可”阻塞。UAC由本人确认，日常GUI与维护保持普通权限。

[上游复用审查](UPSTREAM-REUSE-20261026.md)已补充383f927→870c4ca的18提交；不复制Direct成功标签、盲目回滚或轮询无泄漏结论。历史逐项账本见[PROJECT-ACCEPTANCE](PROJECT-ACCEPTANCE.md)。会话停止不声称后台继续开发或持续保护。
