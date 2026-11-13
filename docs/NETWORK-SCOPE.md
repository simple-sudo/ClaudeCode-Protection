# 网络保护范围与开发优先级

## 2026-11-12 当前正式网络范围：Protection 启用期间全机公网出口强制代理

**本节是当前规范性网络范围，优先于本文件中 2026-11-04 以前及当日的较窄历史设计。** Protection 网络模式启用时，目标不是仅限制 Claude 进程或已知 Claude 域名，而是强制整台 Windows 主机的所有应用和 Windows 服务的公网/互联网出站流量经过用户指定的 FlClash 美国住宅代理。

### 核心规则

- FlClash TUN 负责接管应用流量，Global 负责选择统一代理路径；二者的 UI 状态不能单独证明不存在旁路。
- Windows WFP/可信网络所有者必须在正确层级强制执行：物理接口仅允许已核验 FlClash Core 向当前授权代理端点建立必要外层连接；其他应用、系统服务和未知进程的公网直连全部阻断。
- IPv4、IPv6、TCP、UDP、DNS、DoH、DoT、QUIC 等分别纳入。代理支持的流量经代理；不支持或未知的公网协议阻断，不允许 DIRECT、COMPATIBLE 或其他直连回退。
- 代理节点或端点切换必须更新并重新核验有期限的外层连接授权；端点身份、进程身份、协议、端口和出口属性必须绑定。
- DNS 引导、代理服务器域名解析和本机代理入口属于独立控制路径，必须有明确、最小、可审计的规则；不能以启动代理为由放开系统默认 DNS。
- ARP、DHCP、IPv6 ND/RA、必要的本机回环等链路/控制面通信不是公网代理流量，可按最小必要范围处理；不得把整个局域网、私有地址段、某个进程或 UU 远程设为宽泛直连例外。
- 代理、TUN、节点、WFP、Owner、Watchdog 或状态证据异常时 fail-closed：保留阻断、撤销 Claude 会话网络许可，不自动恢复直连或 IPv6。
- Protection 网络模式未启用时，不得擅自改变用户原有网络配置。用户可以停止 Claude 会话而继续保持全机代理模式；退出全机保护必须由用户明确操作并精确恢复本产品拥有的规则。

### UU 远程兼容性

用户报告目前在 FlClash Global 美国代理开启时 UU 远程能够正常使用。这只证明当前使用场景下的应用功能兼容性，不证明 UU 的控制、画面、键鼠、文件传输、UDP/P2P、中继和重连流量全部经过代理。必须检查 UU 相关进程/服务/子进程、真实远端、协议和物理出口投递；不得为了保持 UU 可用而增加未经验证的公网直连例外。

### 安全边界

全机代理控制的是网络路径，不是内容级 DLP。Claude 仍可能读取本机 SSID、网卡、路由、DNS、设备标识、GPU 信息、FlClash/UU 配置，再通过合法代理上传。因此 P0-HOST、P0-SELF、P0-ASSURANCE 和数据外传审计仍是独立必需项。代理服务提供商也可能看到客户端到代理端点的来源连接；项目不承诺对代理服务商隐身。

### 当前实现状态

**REQUIREMENT_ONLY / DESIGN。** 当前 SessionProxy 固定资格通路、WFP 持久规则、FlClash 身份核验和路由快照是局部基础，不等于全机通用 TUN/WFP 出口控制。完整全机 IPv4/IPv6、DNS/UDP/QUIC、代理端点动态租约、UU 全流量和故障窗口仍须实现与 Windows 实机验收。详细状态机见 [PROTECTED-STARTUP-SHUTDOWN-LIFECYCLE-V1](PROTECTED-STARTUP-SHUTDOWN-LIFECYCLE-V1.md)。


## 2026-11-12 全机 WFP 可行性审查与首个实证切片

现有 `PersistentFence` 的规则绑定单一安装 Package SID，落在双栈 ALE connect 层，继续承担原会话隔离。全机规则由独立所有者管理。可信侧普通权限只读快照观察到 BFE 在运行、FlClash 和 WLAN 均有 IPv4 默认路由、WLAN 有 IPv6 默认路由；FlClash 两个固定回环监听归于同一 Core 进程。此快照记录现场拓扑和监听归属，实际流向、出口属性、既存连接和 UU 路径仍为 UNKNOWN。

| 要证明的能力 | Windows 原语与待验证边界 |
| --- | --- |
| 应用身份和实际出接口 | ALE 应用 ID 表示映像路径。出站 IP 包层有接口、地址和网络 compartment 等条件，缺少 ALE 应用 ID、协议和端口条件。需证明应用/进程实例授权与实际物理出口相交。仅匹配目的地址或 Core 路径无法满足完整授权。先验证原生过滤能表达所需条件，再决定是否需要驱动维护逐流授权。 [WFP 各层条件](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer) · [应用与接口条件定义](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-identifiers) |
| 既存连接与抢占窗口 | ALE 策略变化会在原授权层触发重授权，触发包方向可与连接发起方向不同。实验须分别观察入站发起的应答和出站发起的连接，校对 TCP、UDP 以及启用、撤销两侧的实际投递。WFP 子层权重、硬允许和跨层阻断需纳入同一实测。 [ALE 重授权](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization) · [WFP 仲裁](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration) |
| 崩溃、重启和 BFE 交接 | 持久拒绝是候选基线。动态会话关闭时自动删除对象，可作为短命授权的一环，授权期限、Core 实例退出、Owner 卡住及撤销触发仍需单独保证。启动期过滤与 BFE 加载持久过滤之间的交接需要实测。 [WFP 对象生命周期](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management) |

首个切片先在受控双栈接收端验证最小拒绝机制。使用自研发送端，对固定接收目标先证明实际可达，保持既存 TCP 及 UDP 流，再验证启用前后新建和既存流的发送标记、Windows 分类、物理口观察及接收端记录。纳入入站发起的回包、IPv4/IPv6、TCP/UDP 与原生 DNS，后续再扩至 DoH、DoT、QUIC、转发、虚拟网卡与网络切换。拒绝证据须对应同一策略版本、测试身份、接口和时间窗。先验证准确回读及只恢复本次拥有的规则，再进入 Core 端点正向放行和故障验证。

正向切片须验证 Core 实例身份、TUN、授权远端协议/地址/端口、端点变更、有限 DNS 引导及代理出口属性。UU 的真实控制、传输和重连另采证据。首轮结论按实际覆盖范围记账，原生过滤、受控投递和故障注入当前均为 NOT_RUN。系统实验须先固定候选工件、对象、时限、停止及恢复条件并取得适用许可。

首个源码切片 `MachineEgressProbePolicy` 在双栈出站 IP 包层分别定义“精确接口索引 + 精确接收端地址”的持久拒绝规则，覆盖发往该地址的所有 IP 协议。地址按 WFP 要求使用 IPv4 主机字节序标量或 IPv6 16 字节表示。规则及子层绑定独立对象键与完整双栈方案摘要，回读核对作用域、动作和持久标志。实际子层优先级须独立观测。 [WFP 条件数据类型](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-data-types) · [WFP 地址字节序](https://learn.microsoft.com/windows/win32/fwp/filtering-condition-identifiers-)

`MachineEgressProbeTransaction` 是未接入 Broker 的内部原生对象资格代码，沿用系统测试门。它先核对真实层字段和对象键缺席，在同一写事务中加入双栈规则、核验规则和安全描述符，随后中止并核对三项对象缺席。没有提交写事务的路径。托管测试已通过。本机普通权限只读打开 BFE 成功，首次查询出站包层返回 Win32 5，双栈层字段和实际对象往返仍待原生验证。受控投递阶段还需实现独立恢复记录及在包层与接收端对账。

投递判定按 IP 族、TCP/UDP 和新建/既存连接逐项记录。每项绑定启用前、执行期间和恢复后三个独立发送标记，既存流必须复用已完成启用前控制的原套接字，恢复使用新套接字。只有发送路径已到达实际套接字调用、规则前后回读正确、两侧正向控制均有物理投递及接收、执行期间有精确 WFP 丢弃且两路完整观察均为零时，才记录该项阻断。匹配到一条实际物理投递或接收回执即记录执行期间泄漏；采集不全或缺少丢弃证据时保持 UNKNOWN。物理包和 WFP 丢弃须由可信采集端按精确流归属关联，无负载的 TCP SYN 也计入。

当前 Windows 测试的八组双栈回环正向控制实际收齐所有标记。规则读回、WFP 丢弃与物理口采集用于判定器的合成分支测试。真实采集接线、提交规则、恢复事务和物理接收端均待实测；入站发起的回包和原生 DNS 仍是后续覆盖项。

已有只读 WFP 历史事件选择器按原过滤器运行时 ID、层 ID、双栈 TCP/UDP 五元组、出站方向和最多五秒的 FILETIME 窗口关联丢弃。它只读取已有历史，缺字段、错误规则、错方向或窗口外事件均拒绝。匹配只能佐证该流发生丢弃，既存流仍须独立对账，以区分旧数据重传和本次试验发送。未开放原生枚举命令。本机普通身份读取 BFE 采集配置返回 Win32 5，历史采集状态为 UNKNOWN。 [WFP 事件字段](https://learn.microsoft.com/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_header2) · [WFP 丢弃方向与过滤器标识](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_classify_drop2)

受控投递所需的提交与恢复源码由内部 `MachineEgressProbeLease` 管理。它要求当前安装版本、原状态锁及原 Job 准入已关闭。写事务先确认三项对象键缺席，持久化绑定安装、版本及双栈作用域的意图，再添加并核对三项对象，在提交前记录 BFE 返回的两个过滤器 ID、子层权重及三个对象的 owner/DACL 摘要。提交后单独复读。未闭合意图阻止普通生命周期操作。

恢复在同一写事务中确认三项对象全部缺席，或全部与原规则、owner/DACL 摘要及提交前对象 ID 记录匹配。部分残留、替换或 ID 漂移保留现场。仅按原键删除两个过滤器和所属子层，提交后再确认缺席并写入闭合回执。已有闭合回执的重放只复核缺席。微软将过滤器 ID 定义为运行时标识。BFE 重启后 ID 稳定性仍未知，ID 变化时该资格路径会拒绝自动删除。当前系统测试门仍阻止此路径运行，Broker 尚未提供命令，原生提交、回滚、进程中断与重启恢复均为 NOT_RUN。 [WFP 过滤器运行时标识](https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltergetbyid0)

## 历史实现证据（2026-11-06：最小能力与实际内容比较切片，受限实测 NOT_RUN）

在AFD/TCPIP正向证据收敛到创建检查层、既存WFP历史查询未返回记录后，不再盲改
设备ACL或把空历史解释成无策略。新的固定Broker资格以同一原owner链比较零能力
与精确internetClient SID/属性；不选择私网、服务端、registryRead、身份/加密能力。
普通项目/工具/正式启动不选择新能力。新源码、构建和普通测试不授予安装或新实验。

候选保留原WFP endpoint策略hash与6规则，不把其AC-low-zero历史描述当新cap1身份
证据；独立effective gateway hash及admission绑定精确能力hash。挂起/resume、持有
成员及每次网关peer核验都取实际Token集合，不能仅凭CapabilityCount=1准入。
未绑定endpoint先创建/闭合，随后真实读取适配器及IPv4/IPv6 owner-PID表；任何内容
或UNKNOWN先停止，不发HEAD。只在三明确拒绝及endpoint闭合后继续原固定HTTPS。
原owner仍负责关闭准入、quarantine、Job零和恢复；没有无约束回退或新管理执行器。

可信侧已检查真实原值和跨源关联，只留本机证据区；这不是受限泄露或完整L3。
GetExtendedTcpTable的pdwSize是估计大小，SDK SIZEOF_*_OWNER_PID有ALIGN_SIZE余量，
本机实际两族均返回有效行加8字节。解码器现只接受packed或精确8-byte余量，并保留
全部原始字节，不把余量当记录。其余ABI/任意尾部继续拒绝。参见
[微软API说明](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)
及[表对齐说明](https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcptable_owner_pid)。

本文件保留用户2026-10-25网络专题修订，不能永久覆盖后续正式要求。现行完整目标及优先级见
[SECURITY-REQUIREMENTS](SECURITY-REQUIREMENTS.md)，最新状态/操作边界见[CURRENT-STATE](CURRENT-STATE.md)。
IPv6阻断与必要负向测试继续有效，转发优化不属当前要求；“网络交付主线”不排除并列P0宿主隔离/自我保护。
下文验收顺序和安全事件描述为当时计划，不重新授权任何旧测试或冻结系统操作。

## 已被 2026-11-12 全机公网出口模式取代的历史设计（2026-11-04）

本节原先描述的手动 FlClash、GUI 启停和仅全机 IPv6 临时出站门，是当时的较窄设计。2026-11-12 起，现行正式目标已升级为 Protection 启用期间全机公网出口统一经指定 FlClash 美国住宅代理。原有 IPv6 防旁路、故障保持阻断、用户控制 FlClash 和精确恢复原则继续有效，但不再限制网络保护只覆盖 IPv6 或 Claude 进程。

## 历史交付侧重点（已被全机公网出口目标取代）

早期网络主线聚焦 Claude 专属 WFP 防直连、固定本地代理通道、Kill-Switch、Watchdog 和有限全机 IPv6 门。相关实现与证据仍可作为当前架构的局部基础，但不再代表完整网络交付范围。现行范围见本文件顶部的 2026-11-12 规范性要求。

## IPv6 必须保留的安全要求

- IPv6 公网出站与 IPv4 采用相同强制代理标准：可经指定代理完整转发才允许；否则阻断。
- 不允许物理网卡 IPv6 直连绕过 FlClash；不得以“不使用 IPv6”“没有地址”或一次超时推断安全。
- 必要的链路本地 ND/RA 等控制通信必须与公网 IPv6 出站区分，并按最小范围授权。
- IPv6 代理资格、物理出口阻断、节点变化、代理故障、控制器退出、重启和恢复均须独立验证。
- 不得因用户退出 Claude 会话而自动恢复 IPv6；只在用户明确退出全机 Protection 网络模式后，才按所有权精确撤销本产品规则。

## 验收顺序与状态边界

1. 先证明 FlClash Core、代理端点、Global/TUN、节点和出口属性可被可信侧准确核验。
2. 建立全机公网 IPv4/IPv6 物理出口阻断，只允许 FlClash 到指定代理端点的外层连接。
3. 分别验证 TCP、UDP、QUIC、DNS/DoH/DoT、IPv6、代理引导解析及本机回环路径。
4. 验证代理故障、TUN 丢失、端点变化、WFP/Owner/Watchdog 崩溃和重启期间无直连窗口。
5. 验证 UU 远程及其他必要应用在无直连例外的条件下可用；应用可用与路径通过必须分开记录。
6. 与 Claude 本机资源隔离、真实内容对抗实验、数据外传审计和受保护会话生命周期联合验收。
7. 用户退出网络模式后，验证精确恢复本产品拥有的策略且不改动其他系统/FlClash 配置。

每项保留工件身份、真实投递/阻断证据、FAIL、UNKNOWN、NOT_RUN 和未覆盖范围。当前全机网络模式仍为 REQUIREMENT_ONLY / DESIGN。

## 2026-11-03 原会话网关拒绝宿主单播目的地

原SessionProxy除现有公网/私网/端口/固定域名、解析结果和字面IP隧道检查外，接入GatewayDestinationGuard。可信网关内部读取全部可见接口的UnicastAddresses（含虚拟/关闭接口，不根据默认路由过滤），最多256接口/4096地址；读取为空、超界或失败拒绝。来源API语义见[NetworkInterface.GetAllNetworkInterfaces](https://learn.microsoft.com/en-us/dotnet/api/system.net.networkinformation.networkinterface.getallnetworkinterfaces)和[UnicastAddresses](https://learn.microsoft.com/en-us/dotnet/api/system.net.networkinformation.ipinterfaceproperties.unicastaddresses)。实现未读取MAC/名称字段、未导出地址；私有快照没有公开属性，错误只输出固定种类。

原OpenTunnel在创建socket前、上游CONNECT写入前和200后强制重新核对地址集与目的地；当目的地等于本机已分配地址时拒绝，IPv4映射别名/IPv6scope不能绕过按地址字节比较。转发/健康检查最多一秒间隔重读快照，漂移或未知永久撤销该owner快照，恢复旧地址不自动恢复资格，走原gateway失败/租约停止链；首次采集失败清理原构造资源。没有新执行器、替代代理、通用端点或无保护回退。

网络策略升级NET3，SHA256 77348BD30C3F8006CCE90C582087D19B5B181181917F21B09B3D8C09C98D430C；旧意图/规则不能满足新会话的精确策略比较。旧记录保留可检查，未自动迁移/重写；原migrate/session/qualification hold保持，安装不启用网络。地址guard只覆盖分配在宿主接口上的地址，不能覆盖未知NAT公网别名、上游重写或整个真实物理出口；一秒健康采样不是Windows网络状态的原子持续证明。

SOURCE/BUILD/INTEGRATED；36固定非秘密地址检查及精确前置选择通过。已安装401e5f52 INACTIVE，公开载荷/回执/独立ACL匹配；未运行实际接口采集/网关/Socket/DNS/代理/9090或新受保护任务。实测边界见PROJECT-ACCEPTANCE，最新安装见CURRENT-STATE。


## 固定网关资格与正式会话的权限分离

原安装Broker的`qualify-session-gateway`只创建一个编译固定的LPAC HTTPS根程序。它继续使用原ProtectedSession的挂起Preparation、一次性Admission、SessionProxy、ProtectionRuntimeLease、WFP和原Job停止所有者，不引入通用执行器。资格用途仅在私有构造中选定，纳入Admission绑定摘要；外部不提供用途flag、项目、脚本、目标、证据或序列化permit。

该固定用途最多30秒，网关每次转发仍要求已放行阶段及原runtime两秒健康租期；实际LPAC、零能力、固定安装映像、创建时间、Job、进程/线程seal及持有上游身份仍按原链核对。它不制造环境/系统安全PASS，不借`SystemTestingBlocked`解锁旧入口。新增子入口仅接受会话形状并重新核对实际LPAC令牌，拒绝resource/network/GPU计划；普通令牌与伪造字符串均不能启动访问。

前置必须原所有Job准入已关闭、回环历史已闭合、无待恢复/迁移；旧已知raw7890策略仅经原迁移owner、原SID/七个键/全隔离事务转换到当前17891策略。未知或旧网关policy失败，不能静默采用。执行后沿原owner先撤销转发/准入、隔离、Job停止/零成员，再处理本次profile和精确SID回环例外。失败不授予额外恢复或再次执行权。

固定工作负载只经认证17891和原7890上游请求Microsoft HEAD，DoH仍经同一上游，私有宿主单播地址快照不导出。此用途有独立系统操作审查和一次人类决定；源码接入、普通测试、构建或安装不证明实际传输/全部旁路/物理出口。最新工件、运行与授权见CURRENT-STATE，不以此机制说明自授运行。


挂起创建的运行目录由原profile/workspace所有者提供。网关路径以原profile.WorkspaceRoot()设置TEMP/TMP/LOCALAPPDATA/USERPROFILE，避免遗漏创建所需变量，也不继承宿主用户目录。原资源路径继续把同四项设为原授权workspace。纯映射不是路径/ACL/工具授权，任何实际修正效果仍须指定新工件的native验证。


固定网关根与原成功资源程序相同，只查询自身基本身份；真正LPAC由原Broker在持有进程、放行前及原runtime成员检查时核对，受限根不需要为重复该管理观察取得TOKEN_DUPLICATE。固定资格报告复用原HANDLE_LIST中的唯一匿名管道写端。owner按4096字符/严格UTF-8、单JSON、会话/PID/真实退出码和结果形状绑定，只公开固定阶段、HTTP状态、最多四层错误类别/数值；不公开异常Message/Stack/Data或原始输出。网关首个内存故障与固定阶段原子绑定，公开同样最小化代码，停止行为保持。两种反馈都不授予准入/路径权限/自动重试，不读取旧私有错误文件。


固定HEAD客户端通过原HttpClient.ConnectCallback只连接字面IPv4 127.0.0.1:17891，明确发送当前会话的固定Basic CONNECT并要求原网关精确200回执；共享原Target/Port/有界ReadHeader。内置代理层关闭不代表允许直连：回调校验固定HTTPS目标，原WFP和网关内核peer检查继续限制真实出口。TLS仍用原Offline策略/禁下载/完整校验，不增加registryRead或宽松回退。固定根的Invariant当前/默认线程文化仅作用本进程，隔离宿主语言初始化依赖；不改Windows/GUI/owner设置。现有错误是否由特定本地化分支触发仍UNKNOWN；语言处理及新回调的native资格分别判断。


## 公共时区兼容与历史资源租约

固定TLS策略构造依赖本地时间。当前源码由原 Preparation 的可信 owner 提供真实公开日历，原固定 worker 在同一进程内绑定到固定 CoreLib 的托管缓存；这是功能兼容，不是 OS 隐私边界或运行准入。没有新注册表租约、registryRead capability、宿主权限或系统时区更改，原环境资格及漂移门保持。

V2 用严格且有界的 JSON 整数字段传递偏移、日期和夏令时转换规则，以公开构造 API 恢复；保留真实 ID、规则、摘要和本次会话绑定。16KiB 与128条规则上限、不支持或非规范规则拒绝、固定运行时布局检查仍生效。不使用 `TimeZoneInfo.FromSerializedString`：其[转换时间读取](https://github.com/dotnet/runtime/blob/v8.0.28/src/libraries/System.Private.CoreLib/src/System/TimeZoneInfo.StringSerializer.cs)经日期解析可在绑定之前触发本地时间和注册表初始化。本机固定 CoreLib IL 与冷缓存回归支持这一源码缺陷，新版普通读取确认两缓存未提前初始化。该证据不替代真实 LPAC/HTTPS 测试。

历史 SessionTimeZoneReadAccess 的两键 KEY_READ 租约及原恢复记录继续保留。其当时未修复时区初始化，不能推导零capability永远无法读取精确授权叶子键；后续实际原生叶子读取与标准API根映射的区别见下。旧两键租约不自动重启，历史恢复仍要求原严格归属、原 Job durable closed/zero和逐键检查；未知ACL漂移不擦除、不合并，不自动恢复或重试。

## 预定义根映射与固定Winsock权限候选

实际d9da离线LPAC在普通owner新建的专属键上，直接NtOpenKey取得精确package授权的Marker，
标准RegOpenKeyExW经预定义HKU仍拒绝5。三个根对象的原生打开也拒绝。该结果限定于本机、
本次实际身份和键，纠正此前“所有叶子打开硬性需要registryRead”的过宽解释。
[完整实测](STATUS.md#2026-11-04-区分lpac叶子授权与预定义根映射)包含真实MachineGuid正控制及受限拒绝。

本机KernelBase静态链显示根映射先请求MAXIMUM_ALLOWED；普通只读父句柄试验进一步确认
READ_CONTROL足以按标准API打开合法子键，而自身值查询仍拒绝。新增WinsockRegistryScope
只固定25个x64目标及权限描述符，HKLM根仅READ_CONTROL，无值查询/子键枚举/继承；其余为
当前14协议/5命名空间目录的精确KEY_READ键，不包括32位目录、AppId_Catalog、其他系统树。
列表、ControlSet范围、掩码、既有权限及唯一package ACE检查在内存执行。该候选尚无系统
写入、租约日志、恢复接入或网络实测，不改变现有零capability/LPAC/Job/WFP/owner。
必须完成原owner归属日志、持续持有/漂移检查及closed/zero后精确恢复，再审查具体系统候选。
原时区兼容适配保持，registryRead不是候选权限；公开API的进程内重映射也未采用。

后续SessionWinsockReadAccess已接入上述原owner源链，固定新入口与旧资格分离，目录值/子键
形状及内容摘要保持，原意图与closed/zero归属核对后才恢复。当前本机根无P/AI的旧式控制位
尚未获得适用原生往返资格，新入口在Execute之前拒绝该基线，Prepare/意图验证另有检查。
三组普通新建键参考的准备失败、八条件普通原生矩阵及限制均见
[实测记录](STATUS.md#2026-11-04-原owner-winsock租约接入与根权限资格缺口)。
这些新建对象的P/AI结果不能证明既有HKLM根一定出现相同变化。此轮没有安装候选或写入系统
根，不能将尚未实测的精确恢复算作完成。

最新安装、失败、授权及验证范围只见 CURRENT-STATE。7aa的原单次测试停于 TIMEZONE_PUBLIC_CACHE；后续8aee已安装，固定LPAC根越过V2时区初始化及本地绑定，在HTTPS_CONNECT返回SOCKET10107，尚无HTTP成功或双向写入见证。该错误根因未知，不能直接推断为权限、代理或AV问题。原失败不重写，不自动重跑。系统审查草案及普通回归不是人类操作许可。

## 固定套接字故障阶段

原固定CONNECT路径进一步区分 HTTPS_SOCKET_CREATE、HTTPS_CONNECT、HTTPS_CONNECT_WRITE 和既有回复阶段。979c实际停于套接字创建，原根未进入网关连接/请求写入；这不说明全机没有其他网络活动，也不定位底层API失败。新分类只接受System.Net.Sockets程序集内固定Winsock初始化帧作为SOCKET_STARTUP，消息或10107代码本身不算依据，不能观察时仍为SOCKET。分类信息继续走原有界失败管道，不增加原始栈或私有状态读取，不用于运行准入。

979c内的首版分类器错误地使用SocketException所属的System.Net.Primitives作为程序集门，可能将真实启动帧退回SOCKET；其原始报告保留，不能用该类别排除启动失败。当时源码已改为实际Socket所属程序集，并以本机.NET8真实初始化方法元数据验证，更正尚未安装；后续6800安装及定位见下。不据该通用错误增加registryRead、放宽TLS或重置日常环境。

6800已包含分类修正，并在原固定worker中将同一惰性初始化入口移到独立HTTPS_SOCKET_INITIALIZATION阶段。固定System.Net.Sockets模块MVID和无参void入口，原构造器后续复用该初始化状态；不写内部标记、改计数或新增任意调用接口，未知运行时拒绝。90项普通检查包含该入口的实际普通进程初始化/复用；本次真实LPAC在初始化阶段报告SOCKET_STARTUP10107，未执行Socket创建或连接。因此后续不再重复TLS/代理验证，先审查Winsock依赖。原生失败内部具体对象仍UNKNOWN。

微软[AppContainer说明](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)将LPAC注册表访问与registryRead能力关联。Chromium的[固定版本网络沙箱配置](https://chromium.googlesource.com/chromium/src/+/c203127527d34c24ac12973ba0c91006c7933b0d/sandbox/policy/win/sandbox_win.cc#384)使用registryRead及其他网络能力，范围并非本产品的零能力合同。这些来源支持重新审查平台依赖，不能证明本机具体失败原因，也不能授予本产品放宽权限、回退普通AppContainer或复制其配置的许可。修复须同时满足授权网络可用和P0宿主信息隔离，继续走原Broker/ProtectedSession/可信owner；尚无此修复或新准入资格。

## 附加资源限制原语（未接入运行链）

registryRead在公开Winsock目录与P0机器身份目标上均存在允许查询的ACE，不能仅凭其名称认定
范围足够小。元数据匹配不是有效访问证明；本轮没有读取键值、枚举子键或增加该能力。

Windows [restricted token访问契约](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
要求普通enabled SID检查和restricting SID检查同时允许。内部RestrictingSidToken仅缩减自身
宿主进程令牌，拒绝AppContainer及已有restricting SID来源，避免
[CreateRestrictedToken的交集语义](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
改变预期范围。初版ARP+package组合返回87，未采用；不是自动回退或对全部AppAuthority SID
兼容性的定论。当前显式候选使用
[DeriveCapabilitySidsFromName](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-derivecapabilitysidsfromname)
的NT Authority **group输出**，名称由固定产品域及规范安装ID组成，不使用其AppAuthority capability输出。
派生只生成本进程内SID数据，不创建账户、修改原令牌或授予capability。

创建后检查唯一restricting SID、管理员组deny-only及仅允许SeChangeNotify启用；使用
DISABLE_MAX_PRIVILEGE，不使用WRITE_RESTRICTED或SANDBOX_INERT。令牌句柄不请求
ASSIGN_PRIMARY/IMPERSONATE/ADJUST；对内仅提供QUERY权限的AccessCheck副本。没有进程启动、
模拟身份、RPC入口或资源读取接口。普通原生验证只对内存权限表做正负对照，不是LPAC证据。

该候选不借ARP自动获得公开系统文件读取权。真正接入前必须由原可信owner固定必要依赖、
明确资源的最小权限、持有期及恢复边界，验证实际LPAC组合保留精确restricting/capability SID集合；
在原Job内同时证明合法开发/网络可用和敏感对象的最小访问拒绝，保持原监督与停止所有权。
未知资源、缺身份或合成PASS不能替代这些条件。不扩展成通用Broker执行器，也不以放宽
宿主隐私、关闭GPU或默认拒绝可信维护作为兼容方案。目前未修改原准入、capability或ACL。

后续固定普通用户对照中，ARP单独和ARP+安装专属NT group均被CreateRestrictedToken拒绝87。
这进一步否定了在当前候选中直接复用ARP系统资源ACE的做法；它不是对所有Windows版本或
所有令牌组合的定论。唯一NT SID的16项内存验证仍只说明普通访问限制行为，不能跳过公开
运行库、命名对象及实际LPAC组合的可用性与隐私检查。

微软[MXC原生拒绝捕获契约](https://github.com/microsoft/mxc/blob/bf0dbe519f7c729cf90560240cd6d880e56e410d/docs/logging-access-denied.md)
依赖PSEC及Learning Mode生命周期；其[实际FFI](https://github.com/microsoft/mxc/blob/bf0dbe519f7c729cf90560240cd6d880e56e410d/src/mxc-sdk/src/core/learning_mode_windows/ffi.rs)
指定processmodel.dll。读取本机该固定文件PE导出表未找到所需8个导出，故当前不能使用这份
契约的原生诊断路径。没有执行其创建/追踪接口、增加learning/permissive能力、修改ACL或
引入MXC执行器。此元数据不是其他诊断接口、其他模块或更新后系统的支持结论。
