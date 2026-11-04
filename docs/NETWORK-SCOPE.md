# 网络保护范围与开发优先级

本文件保留用户2026-10-25网络专题修订，不能永久覆盖后续正式要求。现行完整目标及优先级见
[SECURITY-REQUIREMENTS](SECURITY-REQUIREMENTS.md)，最新状态/操作边界见[CURRENT-STATE](CURRENT-STATE.md)。
IPv6阻断与必要负向测试继续有效，转发优化不属当前要求；“网络交付主线”不排除并列P0宿主隔离/自我保护。
下文验收顺序和安全事件描述为当时计划，不重新授权任何旧测试或冻结系统操作。

## 交付主线

主要开发和验收精力投入 IPv4 强制代理、精确绑定受保护身份的 WFP 持久防直连、Kill-Switch、Watchdog、配置漂移处理及安全安装/恢复/卸载。保持原配置、认证、备份和现有 FlClash 全局使用，不开发全机网络接管。

用户日常不使用 IPv6 代理。IPv6 代理转发、出口选择、线路兼容和性能优化不在当前交付要求内，不应为此推迟主线交付。真实 Claude 登录、推理和正式启动仍为 `DEFERRED_BY_USER`。

## IPv6 必须保留的安全要求

- IPv6 是潜在旁路；对受保护父进程及其子进程保持未授权 IPv6 外联阻断。
- 隔离规则必须覆盖 IPv6，不能依据“不使用”“系统无地址”或某次超时就省略规则或判定安全。
- 必要负向测试必须校验父/子身份、执行状态和实际阻断；结合规则生效证据。单凭无响应、不可达、DNS 失败或当前主机缺少 IPv6 连接只能得到 `UNKNOWN`，不能判阻断通过。
- 使用受控 IPv6 本地接收端建立可达对照及阻断后零投递，可以形成该受控范围的证据；它不证明公网 IPv6 全部路径、重启持久性或真实 Claude 工具链已覆盖。
- 规则持久性、控制器退出和恢复/卸载时的所有权边界同样需要覆盖 IPv6 阻断。只删除本工具拥有的规则，不全局禁用系统 IPv6。

## 验收顺序与状态边界

1. 解决当前安全事件并确定适当验证环境；不绕过卡巴斯基在日常电脑上重跑。
2. IPv4 强制代理与 WFP 持久策略：只允许已授权的本地代理通道，代理不可用时拒绝其他出口。
3. Kill-Switch 与 Watchdog：代理故障、守护异常、控制器退出、配置漂移，验证网络屏障先行和精确终止所属进程树。
4. IPv6 必要负向测试与上述策略共同验收；不扩展成 IPv6 使用功能开发。
5. 安装、升级、恢复、卸载的精确所有权和用户原配置保护；补齐 DNS/UDP 归属边界与日志隐私验收。

每项保留历史失败、`UNKNOWN`、工件身份和测试范围。探针通过不能代替真实会话证明，用户延期的真实会话不计通过也不强求现在执行。

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

历史 SessionTimeZoneReadAccess 的两键 KEY_READ 租约及原恢复记录继续保留。LPAC 打开注册表另需 capability，单改两键 DACL 已证明不足，不再作为新修复方案。历史租约仅按原严格归属、原 Job durable closed/zero和逐键恢复门处理；未知 ACL 漂移不擦除、不合并，不自动恢复或重试。

最新安装、失败、授权及验证范围只见 CURRENT-STATE。7aa的原单次测试停于 TIMEZONE_PUBLIC_CACHE；后续8aee已安装，固定LPAC根越过V2时区初始化及本地绑定，在HTTPS_CONNECT返回SOCKET10107，尚无HTTP成功或双向写入见证。该错误根因未知，不能直接推断为权限、代理或AV问题。原失败不重写，不自动重跑。系统审查草案及普通回归不是人类操作许可。

## 固定套接字故障阶段

原固定CONNECT路径进一步区分 HTTPS_SOCKET_CREATE、HTTPS_CONNECT、HTTPS_CONNECT_WRITE 和既有回复阶段。979c实际停于套接字创建，原根未进入网关连接/请求写入；这不说明全机没有其他网络活动，也不定位底层API失败。新分类只接受System.Net.Sockets程序集内固定Winsock初始化帧作为SOCKET_STARTUP，消息或10107代码本身不算依据，不能观察时仍为SOCKET。分类信息继续走原有界失败管道，不增加原始栈或私有状态读取，不用于运行准入。

979c内的首版分类器错误地使用SocketException所属的System.Net.Primitives作为程序集门，可能将真实启动帧退回SOCKET；其原始报告保留，不能用该类别排除启动失败。源码已改为实际Socket所属程序集，并以本机.NET8真实初始化方法元数据验证；此更正尚未安装。下一原生定位须区分初始化与创建，不重复代理/HTTPS检查，不据该通用错误增加registryRead、放宽TLS或重置日常环境。
