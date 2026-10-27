# 首条保护会话主链：源码接线与实际阻碍

2026-10-27；首轮 `04e7419`，后续继续同一所有者。本文件描述当前源码，不表示已安装、已执行或验收通过。
用户已重新授权有界系统验证；当前工件仍待安装/运行资格。尚未打开转发监听、访问解析器或创建Job/AppContainer。

## 同一个入口和所有者

正式 Broker `launch` 与固定 `session-synthetic` 均连接 `InstalledBroker` → `ProtectedSession.Request`。
前者仍直接返回真实会话延期；后者在命令行及公开库入口均要求当前工件资格，尚未解除该工件限制。
没有新增服务、独立项目、任意目标路径/脚本/URL 参数或由日常报告换取许可的入口。

| 阶段 | 已接入的源码 | 拒绝或退出的效果 |
|---|---|---|
| 当前安装 | 原 `ProtectedState` / `VerifiedVersion` / `AssertInstalledHost` | 不采用项目副本、调用者摘要或非当前安装 |
| 启动判断 | `ProtectedSession` 的14项环境证据与独立系统证据 | 必需项仅接受当前所有者的 PASS；UNKNOWN/缺项/重复/过期拒绝，不作隐式不适用 |
| 挂起准备 | `ProtectedSession.Preparation` | 只创建一个固定自有挂起程序；当前安装/明确环境预期/完整隔离必须成立，不授予联网或首条指令执行权限 |
| 正式授权 | `ProtectedSession.Admission` | 全14项及独立安全条件仍须满足；绑定安装、选择摘要、环境预期摘要、SessionId、Job、SID、根PID/创建时间、fence与固定资源；恢复只消费一次 |
| 原子创建 | 原 `AtomicChild` 新 `CreateSession` 接点 | Job和AppContainer在挂起创建时绑定；进程/主线程显式管理侧DACL在创建时提供并回读，失败停止，不用默认对象ACL假定不可外部恢复 |
| 通道开放 | 原 `PersistentFence` 的 `CreateSessionQuarantined` / `OpenSessionGateway` | 六角色复用，仅改变允许端口与策略摘要；旧7890计划不能冒充新通道，不移除历史屏障 |
| 首次恢复 | 原 `ResumeQuarantined` + 同一 Admission | 实时复核令牌、唯一挂起成员、当前WFP及许可后才恢复 |
| 实际转发 | `SessionProxy` | 只接受当前Job/AppContainer的认证连接；解析、地址审查和字面IP CONNECT均位于实际转发代码中 |
| 持续监督 | 原 `ProtectionRuntimeLease` + Preparation/Admission + PR #1成员核验 | 同一租约先监督完整隔离的挂起阶段；全门禁通过后接收正式许可，才转向开放/恢复阶段；异常进入停止 |
| 退出恢复 | 原运行租约/Job/Profile/loopback所有者 | 先撤销许可、关闭转发，再恢复完整隔离、精确停止Job/观察零成员，然后排空与清理；逐项保存失败 |

## 网络执行范围

初始策略只允许固定自有 HTTPS 目标 `www.microsoft.com:443`，不代表一般开发服务白名单已经完成。
受保护侧的新WFP计划只允许TCP4到 `127.0.0.1:17891`；7890是管理侧上游，IPv6仍阻断。
环境变量只是兼容接口，实际限制由WFP与通道实施；不把“设置HTTP_PROXY”当隔离证明。

SessionProxy使用会话随机认证、监听归属、已建立连接的源端口/PID、持有进程句柄、精确Job与
AppContainer/Low/零capability核验。凭据只在本会话进程内生成与传递，不写入意图/报告，
也不复制进上游CONNECT。CONNECT头限8KiB；仅HTTPS CONNECT，拒绝请求体/转发编码/重复头/歧义换行。
通道最多4个并发、32次受理，每方向8MiB/合计64MiB、每连接20秒、会话60秒；不是长期会话续租的最终实现。

解析走固定Cloudflare DoH经同一上游的 `CONNECT 1.1.1.1:443`，TLS名称保留为解析器域名。
没有宿主 `Dns.GetHostAddresses`、系统代理自动发现、自动重定向或直连重试。
当前锁定[Cloudflare JSON接口](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/)；
它不是通用DNS JSON标准。格式变化、截断、错误、失效TTL、重复字段、私网/特殊地址、
不相关回答或CNAME循环均拒绝；每次新隧道重新解析，无跨请求缓存。
审查结果写入上游字面IPv4 CONNECT；这只是请求表示，尚未证明FlClash后续不会映射/嗅探并改变目的地。
客户端TLS仍由客户端终止，保留其原名称与证书验证责任。
已认证且有当前许可的客户端先向网关提交首个TLS握手，再由网关进行该连接的DoH解析/上游连接。
实际RequireTlsClientHelloAsync→ValidateTlsClientHello检查完整ClientHello，限32KiB/8条记录并支持流/记录分片；
唯一可见SNI须匹配授权名，ALPN如出现限http/1.1和h2，缺失名称、明文、重复/畸形扩展及ECH/旧加密名称拒绝。
预读的完整原始记录通过借用端点的流视图交回SessionTunnel，字节仍经原预算和写出许可检查，不重复/遗漏转发。
本地200响应仅让客户端提交握手，不表示远端已连通或获得最终保护验收；错误关闭原连接并撤销。
此策略不作TLS解密/证书替代，ECH暂不支持，未完成一般工具/浏览器兼容，亦不能证明上游保持字面目的地。
格式参考：[SNI](https://www.rfc-editor.org/rfc/rfc6066#section-3)、
[TLS1.3结构](https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2)、
[IANA加密名称扩展](https://www.iana.org/assignments/tls-extensiontype-values)。
TLS采用严格离线吊销与禁止AIA下载；缺证书/吊销缓存会失败，未关闭验证。
实际隧道复制器SessionTunnel由SessionProxy直接调用：一方正常EOF只关闭对应Socket的发送方向，
允许另一方向继续排空；出现错误/截止/撤销则取消两方向并观察两个任务后释放端点。
双向字节在写出前检查每方向及会话总预算，原20秒连接期限仍包含排空时间，没有新增无限等待。
固定canary使用精确HTTP/1.1 HEAD检测响应头，不再用GET后丢弃未读正文而中止自己的连接。
这些变化进入网络策略摘要；已有预期配置不能自动转授新策略证据。
网关一次绑定同一所有者签发的Admission；仅有Job/token身份或知道会话认证值不能取得转发权限。
屏障开放需要该许可仍处于已签发阶段，真正转发必须已消费首次恢复许可，环境/独立安全证据有效，
且运行租约完整健康检查后签发的内存健康期有效。健康期最多2秒且不超过运行租约剩余时间；
过期/撤销后迟到心跳不能恢复。读取前和每次写出前检查，阻塞读返回后也复核。
健康期检查无WFP/进程扫描；实际内核/身份复核仍由原运行租约完成，只有全套成功才续期。
该机制不能撤回已写入OS/代理的字节，不承诺瞬时零在途字节，也不替代独立进程监督或CPU/文件权限撤销。
参考：[Socket发送方向关闭](https://learn.microsoft.com/dotnet/api/system.net.sockets.socket.shutdown)。
参考：[连接回调](https://learn.microsoft.com/dotnet/api/system.net.http.socketshttphandler.connectcallback)、
[禁止证书下载](https://learn.microsoft.com/dotnet/api/system.security.cryptography.x509certificates.x509chainpolicy.disablecertificatedownloads)、
[TCP连接所有者字段](https://learn.microsoft.com/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid)。

## 可信环境预期与当前观察

Broker新增 `inspect-session-environment` 与固定四参数 `configure-session-environment` 管理接点。
它们只适用于当前核验安装、现有人工提升权限和操作锁，不自动UAC，不进入日常CLI/GUI普通维护白名单。
配置参数是旧摘要（初次为none）、Windows时区ID、用户Locale、系统Locale；没有网络目标、脚本、状态、
许可或豁免参数。固定私有叶 `session-environment-policy.json` 绑定安装、当前网络策略及实际人类Owner SID；
严格拒绝重复/额外字段、服务SID、非规范值。保留修改前字节/回执，比较旧摘要后原子替换并回读。
网络策略升级后旧预期仍可由维护入口检查和明确重新配置，但启动采集继续拒绝旧策略绑定，不自动迁移为当前证据。
配置仅代表选择，不改时区、Locale或网络；它不能产生任何观察PASS。当前未执行或写入配置。

实际采集在当前工件具备运行资格之后才进行。时区刷新当前Broker进程的缓存，用户/系统Locale调用Windows读取API，
只比较明确预期，不从当前机器值补默认。默认每10秒刷新这类低成本观察；挂起创建与首次恢复前强制刷新。
配置摘要与安装选择每次健康检查核对，缺失/变化/错误立即拒绝。某项读取失败不抹掉同批另一项已确认的FAIL。
参考：[时区缓存刷新](https://learn.microsoft.com/dotnet/api/system.timezoneinfo.clearcacheddata)、
[用户Locale读取](https://learn.microsoft.com/windows/win32/api/winnls/nf-winnls-getuserdefaultlocalename)、
[系统Locale读取](https://learn.microsoft.com/windows/win32/api/winnls/nf-winnls-getsystemdefaultlocalename)。

准备阶段只创建固定挂起根进程、核对实际Job/映像/token并启动原租约的封闭监督；因此不再要求先拿到
尚不存在的根对象证据才能创建该对象。全部环境及安全判断不通过时，根进程仍不执行，沿同一租约
停止/零成员/清理。准备权限无法代替首次恢复许可，不能授权legacy canary或任意Claude/工具。
新进程/主线程对象只授予SYSTEM/Administrators管理访问；创建后及恢复前独立回读。普通用户句柄拒绝、
CLR/工具/GPU兼容性均NOT_RUN；管理员和内核不在此对象ACL防御范围。
依据：[创建时对象描述符](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)、
[描述符回读](https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-getkernelobjectsecurity)。

## 当前仍然拒绝的原因

目前已接入时区/Locale采集、分阶段WFP结构观察与当前启动监督观察；当前会话路径尚未运行，不能标成实际PASS。
其余环境采集（包括出口、DNS服务归属、IPv6行为、WebRTC、ASN及客户端语言/可达性等）仍缺。
独立安全证据仅当前持有安装资产能建立源码中的正向观察；新通道/WFP实机资格、宿主敏感资源拒绝、
工作区/工具/设备授权均UNKNOWN。因此单独取得运行资格也不会使当前源码签发会话许可。
没有从日常报告、历史PASS、原网络/GPU收据或合成成功读取授权的代码。
证据使用本所有者内的单调时钟；环境观察10秒，独立安全证据至多120秒，固定有限会话；跨会话复用和续租尚未实现。
功能性联网/DNS证据仍需专用受审查控制探针与相应可信采集；不能让挂起准备权限变成任意代码执行或一般启动旁路。

现有安装的7890 fence通过安装Broker `migrate-session-network` 的独立维护事务迁移；
该入口仍需当前工件资格，不从启动路径隐式调用。实际源码接点为InstalledBroker →
RegisteredJobSet/InstallationLoopbackLease → PersistentFence/FencePlan，复用原安装锁、身份、WFP事务与计划读取。
每个历史Job必须有不可复用准入关闭/零成员回执，旧回环豁免必须已回收；未知/活跃任务拒绝，不为迁移杀任务。
先恢复旧完整封闭，冻结新旧完整计划，再在一个WFP事务内替换同7个键、同安装SID的完整封闭策略。
提交后独立回读，再原子比较旧摘要选择新计划，最后再次回读并记完成；原计划字节保留在不可变迁移记录。
中断重试只接受这份固定前后像与内核新旧标记：事务前用旧像，事务后/选择前用新内核像完成选择，
选择后/完成前重新回读再完成；未知对象/缺失封闭拒绝。未完成迁移阻断启动及安装生命周期。
完成回执只是维护事实，运行仍要逐次读取实际屏障及全部门禁；没有运行测试证明其崩溃恢复。
已完成的Schema1迁移记录按其固定17891端口与新旧完整映像读取，不要求历史策略等于当前策略摘要；
实际迁移/恢复仍绑定当前工件和当前策略，启动继续拒绝非当前策略。历史可检查不等于许可可复用。
FlClash是否真正按字面地址转发、系统服务代发DNS、端口重用/崩溃时序、物理出口均尚无新证据。
此方案依赖已审核上游诚实执行字面CONNECT，不证明能抵御被篡改的FlClash或恶意上游。
更准确地说，上游还须证明其正常配置不会重写目标、选择DIRECT或回退到宿主出口；仅“软件诚实”不足。
审阅时的上游Meta源码：[HTTP CONNECT接收](https://github.com/MetaCubeX/mihomo/blob/Meta/listener/http/proxy.go)、
[模式与目的地处理](https://github.com/MetaCubeX/mihomo/blob/Meta/tunnel/tunnel.go)。它们不是当前安装Core的版本/行为资格。
本机只读观察到global/Selector→Vless，未见当时选中DIRECT；控制器GET没有锁定此后连接的路由。
没有更改日常配置，当前不从此观察签发任何启动或网络权限。

阻止出口与阻止读取宿主信息是两项独立条件。当前未实现对FlClash配置/订阅、敏感文件/注册表、
进程对象/管理接口及宿主接口信息的完整资源拒绝，也未证明所有相关Windows服务可被归属限制。
新固定子程序不继承宿主USERPROFILE/LOCALAPPDATA/TEMP/TMP，但系统目录、架构等元数据仍可见；
不能称匿名或完整宿主保密。当前范围没有授权工作区、常规工具、MCP或GPU；这只是第一条自有负载接线，
不是缩减最终产品目标，也不是CPU-only替代。原GPU/工具源码保留，尚需同一资源授权链集成。

## 验证与后续集中验收

用户重新授权后，b204c979的Broker/Lifecycle实际离线编译通过；PolicySmoke八源纯托管用例执行退出0。
Broker布局诊断通过，普通用户WFP内置层读取错误5，不能记为WFP资格成功。
后续48f9293c迁移源码及九源纯测试也已离线编译0错误/0警告，实际恢复阶段决策用例通过。
新Broker三个系统入口的未获资格拒绝路径实际退出125，未创建Job或执行迁移/转发。
六项目语义分析零错误/警告；迁移尚未安装、内核替换/断电恢复未验证。
后续7543cb1修复双向传输，Broker/Lifecycle和11源纯测试离线编译通过，内存端点测试实际退出0；
最终c9cd81a历史读取修正后Broker/Lifecycle独立构建也通过，0错误/0警告。
纯测试12个输入字节未变并逐一核对，历史解析修正不借用其测试执行证据。
实际Socket半关闭、TLS/HEAD互操作、网关端口、WFP/Job/Watchdog仍未在本轮执行。
后续c0bc917/3a3c1c5将网关转发直接绑定Admission及原运行租约健康续期；
3a3c1c5的Broker/Lifecycle与11源纯测试离线编译0错误/0警告，实际复制器和健康期对象的
内存撤销/过期/排空/迟到续期拒绝用例通过。这不是安装后绑定或2秒实机时序的证明，仍不签发正式许可。
精确工件及后续构建状态以STATUS顶部为准；原PR CI不覆盖本机后续源码。

接下来按具体工件资格集中验收：门禁/旧证据/直接库调用拒绝，认证与异Job/SID拒绝，
原7890及其他IPv4/IPv6/DNS旁路，代理回绕管理资源与DNS服务归属，解析重绑定/上游字面目标，
正常TLS关闭与故障停止、规则漂移、精确零成员/隧道排空/恢复，以及授权工具/工作区/GPU同时可用。
上述功能验收仍NOT_RUN；用户的有界验证授权有效，但工件资格不能由授权代替。
