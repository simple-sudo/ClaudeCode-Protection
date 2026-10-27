# 首条保护会话主链：源码接线与实际阻碍

2026-10-27；接续 `b18d5cc`。本文件描述当前源码，不表示已安装、已执行或验收通过。
蓝屏事故的系统测试阻断有效；本轮没有打开监听、访问解析器、创建 Job/AppContainer 或运行工作负载。

## 同一个入口和所有者

正式 Broker `launch` 与固定 `session-synthetic` 均连接 `InstalledBroker` → `ProtectedSession.Request`。
前者仍直接返回真实会话延期；后者在命令行及公开库入口均受事故阻断。
没有新增服务、独立项目、任意目标路径/脚本/URL 参数或由日常报告换取许可的入口。

| 阶段 | 已接入的源码 | 拒绝或退出的效果 |
|---|---|---|
| 当前安装 | 原 `ProtectedState` / `VerifiedVersion` / `AssertInstalledHost` | 不采用项目副本、调用者摘要或非当前安装 |
| 启动判断 | `ProtectedSession` 的14项环境证据与独立系统证据 | 必需项仅接受当前所有者的 PASS；UNKNOWN/缺项/重复/过期拒绝，不作隐式不适用 |
| 一次授权 | `ProtectedSession.Admission` | 绑定安装、选择摘要、策略、SessionId、Job、SID、fence意图与固定资源范围；创建/恢复各消费一次，撤销不可复用 |
| 原子创建 | 原 `AtomicChild` 新 `CreateSession` 接点 | 仍是安装Broker的固定自有程序；Job和AppContainer在挂起创建时绑定，没有任意工具/Claude路径 |
| 通道开放 | 原 `PersistentFence` 的 `CreateSessionQuarantined` / `OpenSessionGateway` | 六角色复用，仅改变允许端口与策略摘要；旧7890计划不能冒充新通道，不移除历史屏障 |
| 首次恢复 | 原 `ResumeQuarantined` + 同一 Admission | 实时复核令牌、唯一挂起成员、当前WFP及许可后才恢复 |
| 实际转发 | `SessionProxy` | 只接受当前Job/AppContainer的认证连接；解析、地址审查和字面IP CONNECT均位于实际转发代码中 |
| 持续监督 | 原 `ProtectionRuntimeLease` + Admission + PR #1 成员核验 | 同一SessionId，期限/安装/规则/通道/成员/证据异常进入停止，不签发新的旧许可 |
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
审查结果直接用于上游字面IPv4 CONNECT，不再交给FlClash解析原始域名；客户端TLS保留原目标名称。
TLS采用严格离线吊销与禁止AIA下载；缺证书/吊销缓存会失败，未关闭验证。
参考：[连接回调](https://learn.microsoft.com/dotnet/api/system.net.http.socketshttphandler.connectcallback)、
[禁止证书下载](https://learn.microsoft.com/dotnet/api/system.security.cryptography.x509certificates.x509chainpolicy.disablecertificatedownloads)、
[TCP连接所有者字段](https://learn.microsoft.com/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid)。

## 当前仍然拒绝的原因

14项可信采集器与明确用户环境策略仍缺失，当前14项保持UNKNOWN。
独立安全证据仅当前持有安装资产能建立源码中的正向观察；新通道/WFP实机资格、宿主敏感资源拒绝、
工作区/工具/设备授权均UNKNOWN。因此即使将来单独清除事故停止，当前源码仍不会签发会话许可。
没有从日常报告、历史PASS、原网络/GPU收据或合成成功读取授权的代码。
证据的当前生命周期是本所有者内的单调时钟、至多120秒、固定有限会话；跨会话复用和续租尚未实现。

现有安装的7890 fence需要后续受审查的封闭迁移/恢复事务；当前主动拒绝，不静默替换计划或删除旧屏障。
FlClash是否真正按字面地址转发、系统服务代发DNS、端口重用/崩溃时序、物理出口均尚无新证据。
此方案依赖已审核上游诚实执行字面CONNECT，不证明能抵御被篡改的FlClash或恶意上游。

阻止出口与阻止读取宿主信息是两项独立条件。当前未实现对FlClash配置/订阅、敏感文件/注册表、
进程对象/管理接口及宿主接口信息的完整资源拒绝，也未证明所有相关Windows服务可被归属限制。
新固定子程序不继承宿主USERPROFILE/LOCALAPPDATA/TEMP/TMP，但系统目录、架构等元数据仍可见；
不能称匿名或完整宿主保密。当前范围没有授权工作区、常规工具、MCP或GPU；这只是第一条自有负载接线，
不是缩减最终产品目标，也不是CPU-only替代。原GPU/工具源码保留，尚需同一资源授权链集成。

## 验证与后续集中验收

本轮仅非生成语义分析；全六产品项目零错误/警告，生命周期32个源输入。
PolicySmoke新增实际转发消费的共享CONNECT/DoH解析器负向用例；仅核对测试源码，无测试执行结果。
没有新BUILD、安装、端口、DNS请求、native调用或运行证明；原PR CI不覆盖这些源码。

系统操作获准后仍须对具体工件集中验收：门禁/旧证据/直接库调用拒绝，认证与异Job/SID拒绝，
原7890及其他IPv4/IPv6/DNS旁路，代理回绕管理资源与DNS服务归属，解析重绑定/上游字面目标，
正常TLS关闭与故障停止、规则漂移、精确零成员/隧道排空/恢复，以及授权工具/工作区/GPU同时可用。
上述项目当前全部 NOT_RUN/BLOCKED；本文件不是恢复测试的授权。
