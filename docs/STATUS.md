# 当前开发状态

**最新统一目标：**已接入[用户2026-10-27完整指导](PRODUCT-DIRECTION-20261027.md)。严格十四项可信门禁、系统安全准入、宿主敏感信息隔离、完整开发工具/子进程能力及本机NVIDIA GPU与网络保护共同构成交付条件，不能以任何局部成功代替。网络矩阵继续。只读已发现RTX4060 Laptop GPU/驱动DLL/Toolkit13.3，隔离计算仍UNKNOWN。远端两次README改写已安全合并49ac5c1，源码/冻结构建输入未变，未推送。

日期：2026-10-27（America/New_York）；最初安装/GUI实测发生于10月26日晚，本轮WFP与原子准入实测发生于10月27日。目标模式已建立且仍active，完整产品目标未完成。用户已批准阻塞部分继续推进，并补充[完整产品方向](PRODUCT-DIRECTION-20261026.md)。本地自主开发与小范围提交，既有origin保留，不推送。不同源码与工件不互相继承运行证据。

## 当前成果与证据级别

| 工作 | 级别 | 当前事实及限制 |
|---|---|---|
| 当前六个项目 | SOURCE | 非生成语义检查0错误/0警告。日常CLI7源、GUI3源、工程11源、生命周期23源、broker1源、bootstrap1源；共享源重复计入其消费者。工程项目本轮未构建/运行。 |
| 当前管理图及bootstrap | BUILD | b5243ef管理图30输入、19fb254独立bootstrap31输入均离线restore/build0，0错0警告，SDK8.0.422/ref8.0.28。bootstrap复用冻结生命周期库且内嵌批准与实包一致；work/atomic-profile-recovery-*。旧构建/失败分别保留。 |
| 当前产品四项目图 | BUILD | 457d22d的CLI、WPF GUI、broker及生命周期库离线restore/build成功，0错误/0警告。40项源/项目/资源，固定SDK8.0.422及引用8.0.28，无第三方包。work/product-final-build。 |
| 独立安装引导 | BUILD | 62986ed嵌入14资产批准清单，bootstrap单独离线构建成功，未重编生命周期库；共享同一已构建DLL。实际PE资源摘要与源清单一致、无模块初始化器。work/bootstrap-build及product-install-control/plan.json。 |
| 首次未激活安装 | INTEGRATED，成功路径已运行 | 人类UAC→固定摘要/全路径及文件租约→新受保护bootstrap→全包预检→全新私有状态→现有stager/版本核验/INACTIVE指针/完成账本，实际退出0。没有WFP/Job/Claude或用户配置修改。中断/重启/重复安装/卸载未据此通过。 |
| 安装后字节与权限 | VERIFIED，仅14文件与当前权限负向 | 14资产摘要/长度与批准包一致，管理员owner/受保护DACL；普通用户写打开全部被拒绝，私有current.json读取被拒绝。outputs/installed-package-readback.json。不是抗管理员攻击或断电验收。 |
| 已安装GUI离线检查 | INTEGRATED，当前真实调用链 | 普通用户界面“检查环境”→已安装CLI→inbox PowerShell→显示两阶段结果→当前用户报告。baseline退出0但APIsAgree=false；audit退出2，9 PASS/3 FAIL/8 UNKNOWN。保护仍未激活。配置修复/撤销按钮及在线按钮未运行。 |
| .NET/WFP只读诊断 | VERIFIED，仅只读native路径 | fc113de的.NET8.0.28/x64布局13项符合；普通用户GetByKey仍Code5。独立受保护资格副本人类UAC后读取固定V4/V6内置层成功，各42字段、Id48/50。没有过滤器、Job或跨对象原子策略快照。 |
| 固定管理隔离与跨进程观察 | INTEGRATED，六规则提交/回读限定VERIFIED | 083d版本首次提交成功，后续只读安装诊断确认跨进程/更新/准入测试窗口6个filterId一致；当前5b版本quarantine维护再成功。精确安装SID、持久规则完整，子层实际weight65533；不是网络行为或重启证明。原两次失败保留。 |
| 原子准入有限canary | INTEGRATED，限定VERIFIED | 当前已安装5b版本真实CreateProcess同时绑定安装AppContainer SID和Job、挂起核对低完整性/零capability/确切镜像/唯一Job成员/完整隔离，先行记录后首次resume，canary退出42。随后准入封闭、Job零、profile精确Delete API0。无网络动作，不授予Claude/代理/崩溃资格。 |
| 已完成Job的后续维护 | INTEGRATED，限定VERIFIED | 新进程quarantine返回0：历史2个Job均核对绑定不可复用准入摘要的完成回执，不重新打开已终结namespace，CompletedAdmissionJobs=2，缺失项0。不是任意missing Job的零证明。 |
| 用户配置维护 | BUILD，尚无功能/故障运行验收 | GUI/CLI共享当前用户目录、独占锁、刷盘备份、先行pending及摘要冲突拒绝。未迁移旧备份、未修改真实设置。 |
| 原S1/S2及8a9c4b1构建 | 历史限定证据 | 原日志、失败、修正和UNKNOWN均留原处；见[原S1/S2](VALIDATION-S1-S2-20261026.md)与[首次broker构建](BROKER-OFFLINE-BUILD-SCOPE.md)。当前安装不升级这些历史结论。 |
| 全量保护宿主/故障/卸载 | 尚未完成；代理开放/网络行为/完整生命周期缺失 | 原子准入已贯通有限无网络canary；生产代理审核/开放、DNS/UDP/IPv6旁路负向、代理失效、控制器崩溃、完整运行租约、Watchdog/漂移与最终清理仍未贯通。限定inactive迁移仅消费固定旧包及严格关闭证明；不是活动升级/卸载或一般进程所有权。 |
| 真实Claude登录/推理/会话 | DEFERRED_BY_USER | 不计通过，不阻碍独立工具能力。 |
| 完整产品 | 尚非DELIVERABLE | 已有本机安装后的离线检查切片；持续防直连、故障恢复和安全卸载仍须交付。 |

INTEGRATED是实际调用链；VERIFIED只适用于表中明确功能及负向；BUILD和SOURCE不能替代保护验收。用户授权是推进权限，不是功能通过。

## 本机安装及证据位置

**当前选择：**`5bcaa958304246a78e8a4631dc9ae3a1`，manifest `9A3AFFC424CCB1D05691891A0F5EA99BFFECE30EDA801594825076C2DBB9E32F`，operation `18032154127b41d9893233e4f330b34b`，INACTIVE。原4版/原bootstrap均保留；以下083d/c810等条目是中间历史。正式目录为CodeRoot/versions/上述release；当前GUI/daily字节沿用原9资产，当前目录GUI未打开；没有常驻产品进程。

实际canary成功请求`ed43b46382474185bd80b002cecda550`，Job `ffa645dc222248ab86cd6068641813b1`，子进程43600；先行记录中是安装SID、Low4096、capability0、唯一Job成员且完整隔离；随后退出42、清零和封闭回执。ProgramFiles/ClaudeCodeProtection-Atomic-20261027-r2及work/atomic-profile-canary-control保留全记录。profile Delete API0，独立残留/中断清理仍UNKNOWN。首次Code2失败及其已封闭空Job记录保留。

后续新进程维护请求`c842dcd601ed40c897c6c8cf777a2e45`返回0，预期Job2、已完成准入Job2、名称缺失0、阶段错误0，完整隔离再回读。ProgramFiles/ClaudeCodeProtection-CompletedJobs-20261027及work/completed-job-maintenance-control。所有用户配置/AV/FlClash/TUN保持，真实Claude仍未启动。

当前选择已更新为`083d97b7e544434cbb0d900004035657`，manifest SHA256 `D21A7D9F39A93E82087062EAD14F49329E7DBDD2743B2DC12DE98CAB6DC691F1`；操作`24d00c69110d4b5b91598069edfd5e06`。两次更新都为INACTIVE，旧806b包和中间faa包完整保留，原bootstrap未改写；下面806b条目为最初安装历史。当前GUI/daily字节与原始一致，GUI尚未在当前目录重新运行。新14资产摘要/长度、管理员owner/保护DACL及普通写拒绝已核对。更新helper/嵌入批准检查在work/inactive-update-r2-*，结果在ProgramFiles/ClaudeCodeProtection-Update-20261027-r2。

当前安装专属隔离已真实创建：fence `3c4038f45a0e4dad8a4ab4d209d77d09`，6条持久filter，第三次quarantine请求`f1f5f82efd67435bb64a477448478699`退出0。提交后独立WFP回读全部匹配，原进程退出不主动清理持久规则；尚待新进程只读观察持续存在/真实负向网络与重启。无受保护进程、无Job，也不称后台保护已交付。原始记录ProgramFiles/ClaudeCodeProtection-Quarantine-20261027-r3及work/installed-quarantine-r3-control；前两次失败目录不变。当前普通GUI均关闭。

- 包发布标识：`806b2b6997c84e0da4db46c9d267d7a0`；manifest SHA256：`1D83FA034A65DC58D1FFEB9C4F3A54EA52F1C3B7AF6156A54C752FA5D8801BAC`。批准清单在src/ProtectionBootstrap/ApprovedPackage.json；它是当前精确包的身份，不是任意新构建许可或AV安全结论。
- 受保护引导：`C:\Program Files\ClaudeCodeProtection-Bootstrap`；正式代码：`C:\Program Files\ClaudeCodeProtection\versions\806b2b6997c84e0da4db46c9d267d7a0`；私有状态：`C:\Program Files\ClaudeCodeProtection-State`。无服务、计划任务、自启动、全局PATH或快捷方式注册。
- 普通用户GUI：上述版本内`bin\center\ProtectionCenter.exe`；当前只实测“检查环境”。此前UI正常关闭因computer-use激活失败而保留窗口。10月27日用户明确要求不用就关闭后，核对该自建测试进程PID/创建时间/路径/摘要、后台操作已结束与报告已保存，精确结束此GUI进程；未按名称或进程树批量终止。关闭记录在outputs/installed-gui-close.json。没有保护后台运行。
- 实际安装记录在受保护bootstrap的install.stdout.txt/result.json/completed.json。原始控制、pins与源码/工件记录在work/product-install-control、product-install-recovery-control、bootstrap-build及product-final-build，不入Git。
- GUI报告在当前用户LocalAppData下ClaudeCodeProtection/reports；本次文件environment-20261027-035756-c34de8.json。摘要与状态汇总在outputs/installed-gui-audit-summary.json，界面文字在outputs/installed-gui-after.txt。报告及原始数据不入Git。

## 失败与修正

2026-10-27接续目标模式已实际建立。已安装固定`quarantine`首次经本人UAC执行，返回3：安装专属WFP事务内校验抛InvalidDataException，QuarantineObserved=false；登记Job为0，不能据此计保护成功。原记录在`C:\Program Files\ClaudeCodeProtection-Quarantine-20261027`及work/installed-quarantine-control。无Claude启动、FlClash/Core PID20944/14268不变、AV/BFE运行，有限Application观察无AV事件，完整告警覆盖UNKNOWN。当前异常缺固定细分阶段，根因待原生对象契约资格核验；不放宽检查或重复盲试。

新增固定`qualify-wfp-objects`仅SOURCE：受保护独立资格宿主、专用合成package SID及随机对象键，只在未提交事务内观察本次对象安全描述符/标量，必须Abort并独立回读两对象不存在；不打开安装状态，不进入生产quarantine或只读inspect命令。六项目非生成检查0错误/0警告；首次checker因报告父目录不存在退出1，建目录后通过。此项用于定位本次真实失败，不是防泄漏验收。当前生产安装仍为旧包。

1104c4e独立29输入离线restore/build均0。五文件固定pin、元数据无module initializer、人类UAC及受保护专用资格副本后，合成对象检查实际退出0：BFE回读filter Flags=65（PERSISTENT|INDEXED），安全描述符管理员owner/保护DACL及两个SY/BA ACE正常。事务Abort成功，随后独立查询filter/sublayer均不存在。与生产`PolicyMatches`原先Flags必须精确等于1的条件结合，定位为INDEXED回读不兼容；微软[FWPM_FILTER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0)记录该标志用于索引。限定VERIFIED为此native对象契约，不是网络隔离。

初始资格生成launcher残留旧相对control导致固定plan拒绝；修正后helper残留旧目的地leaf导致创建目录前退出1。均未执行产品/创建资格目录，原脚本与失败保留work/wfp-object-contract-control；修正完整固定范围后work/wfp-object-contract-runtime-recovery成功，原工件名称未变，不涉及AV绕过。真实结果在ProgramFiles/ClaudeCodeProtection-Qualification-ObjectContract-20261027。修正生产读取只允许1或65，仍拒绝disabled及其他未知标志；同一生产匹配函数新增实际对象与16项标志负向资格，当前修正SOURCE待新工件运行，旧安装未改变。

1. WFP首版普通用户事务Code5/BeginWfpTransaction保留；固定内置元数据改为独立GetByKey后仍Code5/ReadBuiltinConnectLayer。管理员只读成功不覆盖这两次普通用户失败。读API与事务分别要求layer READ和engine BEGIN_READ_TXN，见微软[LayerGetByKey](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmlayergetbykey0)及[TransactionBegin](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionbegin0)。
2. 首次资格复制因PowerShell5.1不存在的FileSystemRights.ReadWrite枚举失败，原空资格目录保留；显式ReadData|WriteData经自建单字节文件验证，在新的-r1资格目录成功。资格目录不是正式产品根。
3. 产品图首次构建GUI因共享源码缺少System.IO失败；真实WPF默认global usings不含IO/Http，原checker超集漏检。修复共享源和checker后新目录完整构建成功。失败在work/product-payload-build；修正版在product-payload-recovery-build，最后输入绑定修正另在product-final-build。
4. 首次安装辅助脚本生成时误改载荷EXE名，固定输入核对在创建目录前失败；原脚本/终态保留。修正全部20项与计划逐一一致后，新控制目录运行成功，没有改名任何实际工件、没有用重包装绕过AV。

## 下一主线及安全边界

850d0a5前缀修正32输入BUILD0，系统工具正向句柄/通用单链接拒绝资格再次通过，普通管理命令拒绝符合预期。新批准626a6ff8672142c8ae9363e2f99a87eb，manifest D1B1982E41107A988E719BC8779CE66F62BE7FD1C9F28D8673557BC416B3EF87；待33输入bootstrap及真实更新/网络矩阵。此前95d更新125不因后续构建通过而改写。

95d修正版bootstrap33输入构建成功、受保护update-inactive实际125拒绝，未创建新正式版本/切换指针；current-readback仍466a/978CE/ae397c94。原因是新增AssertClosedHistory消费loopback-intent前缀，但ProtectedState固定枚举白名单漏加该项。系统工具资格仍有效于原限定产物，不能把它当安装成功。当前SOURCE只增加该固定前缀，其他未知前缀继续拒绝；历史helper/结果在work/network-utility-recovery-*与ProgramFiles/ClaudeCodeProtection-Update-20261027-network-r2。未启动新的网络矩阵，预备运行脚本因新版本不存在停止；不冒充产品矩阵故障。旧隔离/AV/BFE/FlClash保持。

766e01f修正管理图32输入BUILD0；独立普通权限、固定库字节快照及无module initializer后，仅调用只读OS工具句柄资格：OpenCheckNetIsolation成功，通用Open对同一4硬链接文件仍以原单链接错误拒绝。工具没有执行、无WFP/Job修改，限定VERIFIED为这两条路径。普通runtime/拒绝检查仍按预期。新批准95d24323588440989b3ee726bc4a75a8，manifest E9F06ED86C5C2245B79152402FE7CE8DF33A12BFACB58B69BBDCB8D73F964F4F，待独立bootstrap及真实更新/矩阵；466a首次失败不覆盖。

466a包已实际INACTIVE更新（operation ae397c94caeb48aca2bbde4e502c74e0）。首次qualify-network退出3，request24808d3065e24cb0adb3ee17988cc1dc：当前FlClash监听PID14268、E:\program\FlClash\FlClashCore.exe及创建时刻/磁盘hash已持有核对，主机显式HTTPS Microsoft200；6个TCP/UDP/IPv6/UDP53接收端基线全部返回成功且各1份nonce收据。此为限定真实基线，不是受保护网络矩阵通过。

运行在专属控制profile创建后、回环豁免添加前失败。原private记录与ProgramFiles/ClaudeCodeProtection-Network-20261027保留；loopback cleanup独立确认本次SID不存在、其他原1项未变，profile Delete API0，6规则完整回读。只读fsutil发现System32/CheckNetIsolation.exe实际有4条Windows servicing硬链接，原单链接payload校验误用于该系统工具，导致InvalidDataException。当前SOURCE增加唯一固定无参数OS工具打开方法，保持所有产品/源码/删除路径单链接限制、系统目录祖先/owner/DACL/无写入共享和最终路径核验；不改ACL、不拷贝改名系统工具。新增回环历史闭合检查及子工具终态未知不签发清理证明，待新构建/资格。未打开代理门、未恢复受保护网络子进程，无Claude/AV/FlClash/TUN变更。

49863d4的32输入管理图离线restore/build成功，0错误/0警告。元数据无module initializer；普通inspect-runtime0，admission-child/qualify-admission/inspect-installed-fence/qualify-network均125拒绝，没有网络或Job动作。下一批准包466a04443a294ba7a0aa7cff90ebd525，manifest978CE60499B05D76E2820F7ADD214727E3F417716A2EABD1EA34EB90FC14C5B4；待独立bootstrap构建/安装。当前5b正式包及隔离没有因SOURCE/BUILD改变。

网络矩阵纵向切片当前SOURCE：固定已安装`qualify-network`复用AtomicChild/OwnedKernelJob/PersistentFence，先精确持有既有FlClash Core进程/磁盘映像及127.0.0.1:7890监听身份，显式代理HTTPS Microsoft、默认TLS校验并开启吊销检查。只对工具安装SID或独立短名对照SID添加/移除精确回环豁免，保存其他项快照并核对不变，不恢复整张全局列表；现有豁免拒绝接管。Windows工具固定System32路径、ACL/文件句柄及最小环境，无Shell/UAC自动确认，不调整FlClash/系统代理/TUN。

矩阵有父进程接收端基线、无本工具WFP过滤器的独立AppContainer回环对照、完整隔离、仅指定IPv4代理开放、再次阻断代理路径。独占自有127.0.0.1/127.0.0.2/::1 TCP/UDP接收端含127.0.0.2:53原始DNS包，记录随机nonce收据；不占用已有53监听。代理开放事务只删除精确IPv4 quarantine角色，其他5角色保留，必须源策略摘要与编译端点一致、身份有效及提交后回读匹配；结束/失败恢复完整隔离，继续所属Job清零，再移除本次豁免/精确profile。每个阶段通过唯一继承报告管道返回PID/nonce/逐项结果，开放期间轮询所属代理/过滤器漂移。SOURCE非真实网络验收：系统解析器经服务代理DNS、外部物理出口、真实代理进程崩溃与控制器崩溃仍UNKNOWN；独立对照只向本次接收端发送，不访问外部站点。六项目非生成检查0错误/0警告，生命周期25源，待32输入管理图构建及独立资格/安装/实测。

当前实际安装已为c81055a2849c4c86a9d7f07524cc77d6，manifest F68329165AAAD7BF5C8CBB4B44111B715439395B850F9653C80D687843A006FA，update操作2288775b17db4e27accaf24a6d53795c；旧3版保留，指针仍INACTIVE。已安装只读inspect-installed-fence在首次quarantine进程退出后及canary尝试前后均返回0，6原filterId102364–102369一致，证明当前时段跨进程持久对象可读，不证明流量/重启。

首次qualify-admission实际返回3，CreateProcess在恢复前失败Win32=2/AtomicCreateSuspendedWithPackageAndJob，无子进程恢复。真实私有命名Job edfbfe75140d44769786802ce5e20502创建、ACL/tag/limits核验、终止/零成员及封闭一次性准入回执成功；不计进程准入通过。原记录ProgramFiles/ClaudeCodeProtection-Atomic-20261027与work/atomic-canary-control。根据微软[AppContainer启动流程](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)，补充此前缺失的专属current-user profile：先行意图、Create返回新SID核对，已有profile拒绝接管/删除，只有本次创建且同一Job观察零后才调用精确Delete；删除API成功与独立不存在仍区分。当前修正SOURCE，根因假设待复测，不以文档当成功。

后续固定未激活更新仅增加c810精确包：必须持有同一私有锁/旧版且每个Job都有绑定原意图/版本/不可复用准入摘要的封闭/清零回执；无回执/缺失/未结束均拒绝。不把任意空Job或轮询当准入关闭，不给活动宿主/一般升级授权。无新Claude/网络/AV变更，AV/BFE及FlClash20944/Core14268保持。

39cea24原子准入切片独立30输入离线构建成功，未安装运行新准入；元数据无module initializer，普通用户inspect-runtime退出0，admission-child/qualify-admission/inspect-installed-fence分别125拒绝，均无Job或网络动作。下一批准包c81055a2849c4c86a9d7f07524cc77d6，manifest F68329165AAAD7BF5C8CBB4B44111B715439395B850F9653C80D687843A006FA；待bootstrap单独构建及受保护安装。当前正式083d包和既有完整持久隔离保持。

后续原子准入纵向切片当前仅SOURCE：已安装broker固定qualify-admission→现有私有命名Job→CreateProcessW同时提交SECURITY_CAPABILITIES/JOB_LIST并初始挂起→核对当前包、确切镜像/创建时刻/令牌/AppContainer低完整性/零capability/唯一Job成员/已提交完整隔离→先行记录→首次Resume。子进程只能执行当前broker的200ms无网络canary并返回42，命令不接受外部路径/脚本/PID/参数。完成前封闭一次性准入、停止并观察Job零，保存绑定准入记录的完成回执；已关闭准入的专属回执可供后续管理跳过已终结Job，任意缺失名称仍UNKNOWN。新增inspect-installed-fence是独立只读入口，不借quarantine变更做观察。

新公开代码文件/目录增加标准ALL_APPLICATION_PACKAGES只读/执行ACE，使隔离进程可加载自己的代码；管理员/系统仍是唯一可写者，私有状态不加此ACE。迁移仅允许3个已核验无准入包的固定摘要，且无Job历史；允许保留完整既有隔离，拒绝部分/外来对象，不清理规则。六项目非生成检查0错误/0警告（生命周期23源）。此切片未构建/运行，不计原子准入、网络行为或崩溃通过。

1f3322d独立29输入构建成功；受保护-r4六角色native资格退出0，6身份/策略匹配及96项标志组合检查通过，实际子层weight65533；未提交事务Abort，7对象全部不存在独立回读成功。限定VERIFIED为对象契约；未提交测试不证明已安装隔离或真实网络防泄漏。批准下一未激活包083d97b7e544434cbb0d900004035657，manifest D21A7D9F39A93E82087062EAD14F49329E7DBDD2743B2DC12DE98CAB6DC691F1；复用已核验9个日常/GUI资产及新5个管理资产，待独立bootstrap构建与安装。此前失败不覆盖。

1345e11的六角色资格真实退出2（外部helper125），所有6个生产过滤器的身份/条件/标志/安全描述符均匹配；唯一失败为子层请求65535、BFE实际分配65533。Abort及7对象不存在均回读成功。微软[Installing a Provider](https://learn.microsoft.com/en-us/windows/win32/fwp/installing-a-provider)明确让BFE选择最近可用weight；源码现在保存实际weight并移除请求值必须原样返回的错误前提，不把权重或对象存在当真实阻断证明；[Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)中的hard-permit等组合仍须负向功能验证。当前修正SOURCE。未激活迁移白名单仅增添本次已安装、仍无准入命令的精确BB0A包；仍持有旧版/私有锁、无Job历史且逐意图验证所有BFE对象不存在，不增加资源删除或活动升级权限。

5627b65批准的新包faa9136470ae4ec8ba6273c10a91d19b（manifest BB0A619C10B53ECF4AC4E79578C9DF4A058E1758B3B111836A5172F46488E9FD）已通过独立payload及bootstrap构建、嵌入资源元数据核对和20项固定输入资格，实际`update-inactive`退出0，操作54bc6986cc7f4905b0c6b1d7ebd9683d，指针仍INACTIVE。旧版/原bootstrap及所有失败保留。新14资产摘要与普通用户写拒绝已回读；当前gui/daily沿用原来9文件，当前新版GUI未重跑。work/inactive-update-*及ProgramFiles/ClaudeCodeProtection-Update-20261027。

随后已安装新包quarantine复测仍退出3、QuarantineObserved=false，REINSTATE_QUARANTINE内InvalidDataException，原记录ProgramFiles/ClaudeCodeProtection-Quarantine-20261027-r2。INDEXED是已证实的单规则匹配缺陷，但不是完整失败的唯一原因。原子准入前须先定位剩余完整策略问题；不计保护成功。现在将六角色定义、身份/策略匹配直接共享给独立未提交资格入口，按角色记录native返回值；当前SOURCE待新构建。没有新增Job/Claude或日常网络/AV修改，原不明告警原因仍UNKNOWN。

c1ab0dc的修正版已独立离线构建，并在-r2受保护资格目录实际运行：生产`PolicyMatches`对BFE返回的65通过，16项标志组合只有1和65通过；Abort及两对象不存在均回读成功。资格仍只覆盖native对象/匹配契约，当前正式安装尚未改变。为将修正落入正式版本，新增SOURCE的`update-inactive`只允许从固定原始manifest迁移：持有旧整版、私有锁、INACTIVE指针、无任何Job历史，逐一核对原fence意图的BFE对象全不存在；不把failed intent当作不存在，不具备资源删除权或活动版本升级权。目标新清单仍由独立bootstrap内嵌批准，复用既有VersionLifecycle更新与完成账本；等待本轮限定构建/安装实测。

继续复用当前生产owner，实现精确身份的原子进程准入与代理限制；优先用自有合成进程独立验证IPv4/DNS/UDP/IPv6阻断、代理失效、控制器崩溃和恢复，随后接Watchdog及精确卸载。不得把轮询停止、配置正确或代理响应当无直连证明。

当前API不一致仍需只读分项定位；代理owner路径不可读保留UNKNOWN，不能按名称放行。UI离线检查的FAIL/UNKNOWN与旧S2各自独立。配置维护的冲突、中断、备份损坏分支仍需有界实测。

卡巴斯基事件未解决，不执行退休EXE/旧聚合selftest，不改AV或规避拦截。有限Application观察未见新AV事件，完整厂商告警覆盖UNKNOWN。AVP/BFE保持运行，当前窗口FlClash/Core PID一致，真实Claude规则仍禁用，原settings摘要未变。出现新告警立即停止。

FlClash Global、系统代理及TUN保持当前日常状态；全机时区/IPv6等可按用户新指导设计为有必要性、影响说明、明确选择与冲突安全恢复的高级能力，本轮没有实施。普通旧Build/Assert/cmd硬停止仍留作防误用；已授权且具体核验的当前路径不再以“等待相同许可”阻塞。UAC由本人确认，日常GUI与维护保持普通权限。

[上游复用审查](UPSTREAM-REUSE-20261026.md)已补充383f927→870c4ca的18提交；不复制Direct成功标签、盲目回滚或轮询无泄漏结论。历史逐项账本见[PROJECT-ACCEPTANCE](PROJECT-ACCEPTANCE.md)。会话停止不声称后台继续开发或持续保护。
