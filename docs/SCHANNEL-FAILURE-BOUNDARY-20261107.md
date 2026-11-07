# 固定网关 Schannel 失败定位

41fb 的受限固定探针完成 CONNECT 后以 `0x80090305` 失败，网关在等待
ClientHello 时收到 EOF。已记录的失败没有标明 SSPI 的具体调用点。

.NET 8.0.28 中，Schannel 的包枚举和取得客户端凭据句柄都可抛出带原生状态的
Win32Exception。完成枚举但找不到指定包的路径另抛 NotSupportedException。
初始化上下文和后续控制调用也可能经较外层转换为错误，栈没有明确调用点时
继续保留通用分类。[.NET 8.0.28 SSPI 实现](https://github.com/dotnet/runtime/blob/v8.0.28/src/libraries/Common/src/Interop/Windows/SspiCli/SSPIWrapper.cs)
[.NET 8.0.28 Schannel 客户端实现](https://github.com/dotnet/runtime/blob/v8.0.28/src/libraries/System.Net.Security/src/System/Net/Security/SslStreamPal.Windows.cs)

固定子进程 TLS 失败回报只在 .NET 安全库的对应帧可验证时产生
`TLS_SCHANNEL_ENUMERATE`、`TLS_SCHANNEL_PACKAGE_MISSING` 或
`TLS_SCHANNEL_ACQUIRE`。同一状态码、消息文本或外部程序集的方法名不能
生成该分类。最多检查 64 个栈帧，回报仅保留原数值和有限类别，原版回报仍可解析。
原 owner 仅接受在 `HTTPS_TLS_HANDSHAKE`、退出 125 时出现的负值分类，
分类不给予准入、重试、权限或网络放行。

普通 Windows 对照按 SDK x64 ABI 使用真实 Schannel。枚举、定向查询、空证书
的出站句柄取得均返回 0。首个上下文调用返回 `SEC_I_CONTINUE_NEEDED`，产生
444 字节、类型 2 的待发送数据。缓冲区、上下文及凭据句柄释放均返回 0。
对照不读取或输出该数据，也没有传输或第二次上下文调用。对照随后以刻意不存在的包
获得真实 .NET 异常，生产报告和原 owner 解析均给出包缺失分类。另一次普通
`SslStream` 内存传输首段经生产 ClientHello 解析及重放通过。[Schannel 取得凭据句柄](https://learn.microsoft.com/en-us/windows/win32/secauthn/acquirecredentialshandle--schannel)
[Schannel 初始化上下文](https://learn.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--schannel)

候选 `70e148574a4345d1a01078c61af01ed2` / `868BD3C5…` 仅做未激活包准备。
精确 41fb 前驱允许进入原安装 owner 的 live 检查，所有闭合、隔离、恢复和私有状态
检查保持适用。候选若进入一次新的受限复测，需要独立固定更新及原 owner 调用、
时限、输出和停止条件。新的受限诊断、完整 TLS、HTTP、L3 与正式产品为待验证。

## 精确安装迁移

复核发现旧安装白名单只判断当前包是否属于已审查的前驱集合。外层在更新后
再核对 `PriorRelease`，无法阻止误从另一个已审查版本迁移。因此保留
`70e14857…` 作为未执行的构建证据。本次改由安装器在原安装锁内读取内嵌的
前驱与目标版本、清单摘要，并在打开前驱包及写入前校验四项完全相符。
资格白名单、前驱持有验证、历史 Job 关闭和恢复检查继续参与原安装事务。

新候选 `34543d3518ae46d8a1452738b8c4ce85` / `6975AF49…` 只允许
`41fb` / `1B092FE1…` 迁移。五个产品项目构建通过，清单、迁移绑定及管理
程序集双份已核对，76 项普通夹具覆盖其他已列前驱、目标漂移及异常元数据。

## 2026-11-07 实际受限复测

本人批准 `4029A8C7…` 后，原 owner 完成 `41fb` → `34543d35` 的一次
未激活更新。安装回执为 INACTIVE。原自研 worker 恢复执行，实际创建和关闭
IPv4/TCP 端点。适配器和 TCP4/TCP6 读取为 `1702/5/5`，均无返回内容，
适配器仍 UNKNOWN。

客户端走到 `HTTPS_TLS_HANDSHAKE` 并以 `TLS_SCHANNEL_ACQUIRE` /
`0x80090305` 失败，子进程退出 125。网关停在 `CLIENT_TLS` 并报告
`0x80070026`，原记录保留 `SessionGatewayStoppedExpiredOrFailed`。
没有 HTTP 状态或双向转发证据。本次已定位到凭据句柄获取调用，SSPI 内部
拒绝原因仍 UNKNOWN。[Microsoft Schannel 获取凭据接口](https://learn.microsoft.com/en-us/windows/win32/secauthn/acquirecredentialshandle--schannel)

原 owner 撤销准入，先确认隔离再确认 Job 为零，停止错误为零，31 项 Winsock
租约已恢复。操作器十个自身 Token 检查点与初始原始权限摘要一致，最终安全检查
通过，外层退出 0 表示观测和关闭已核验。TLS 工作负荷仍 FAIL。只读核对三份
获批回执，同一安装、会话、Job、worker 和状态绑定一致。13:16:21–13:16:35Z
公开 Application 窗口零项，BFE/AV Running，完整厂商覆盖 UNKNOWN。
实际许可已消耗。证据在本机 `work/schannel-boundary-20261107-01/operation-exact-predecessor-once`，
派生核验 SHA-256 `EA2C9EC8…`。L3、HTTP、正式 CLI 和整机验收仍待完成。

## 全隔离获取凭据对照

同一 13:16:21–13:16:35Z 窗口的公开 System 日志没有匹配的 Schannel 事件。
SSPI 内部拒绝仍 UNKNOWN。新对照由原安装 owner 持有当前版本与状态锁，要求既有
准入、原 Job 和回环记录闭合、全部原有 fence 已全隔离。创建及恢复使用原 Job 与
LPAC profile，挂起时查原句柄、实际令牌和隔离。停止时发现原 fence 漂移可由原
owner 重申隔离，之后核验 Job 归零。子进程只接受固定的低完整性 LPAC 身份和
internetClient 单能力，使用私有运行目录。活动时限为 12 秒。仅继承有界回报管道。

固定调用为查询 Unified Security Protocol 包、按网关参数的 v5、去掉附加标志的 v5、
指定 TLS 1.2 的 v5 和同样指定 TLS 1.2 的 v4。无客户端证书、目标、握手、网关、
回环例外或 Winsock 租约。报告按会话、进程 ID 和原句柄创建时间绑定，保存原始
状态、释放状态和调用时间。原生返回失败且未产生对象时可以形成完整对照观测；
有对象时必须确认释放。网关参数取自本机 .NET 8.0.28 所用的 Windows 客户端路径。
旧 v4 路径仅用来区分参数代际。任何结果均不改变生产 TLS 策略或扩大权限。
[Schannel 获取凭据接口](https://learn.microsoft.com/en-us/windows/win32/secauthn/acquirecredentialshandle--schannel)
[.NET 8.0.28 客户端实现](https://github.com/dotnet/runtime/blob/v8.0.28/src/libraries/System.Net.Security/src/System/Net/Security/SslStreamPal.Windows.cs)

普通 Windows 实际五项调用与五项释放均为 0。以候选管理库原样执行 9 个普通
回归入口，含 18 项新对照、83 项迁移、136 项网关回报、27 项网关资格、89 项
网关能力、LPAC 资格与固定 GPU 相关回报。五产品 Release BUILD0/0。候选
`68a0d109ae244dc298c1482d7aa0b432` / `7011F015638626416B00B222C817AE1749A258C9C7EA5EDB3D91DFCC6104DCF2`
只允许 `34543d35` / `6975AF49…` 迁移，20 文件、内嵌清单、内嵌迁移和管理库双份
核验通过。证据位于本机 `work/schannel-acquisition-20261107-01`。
本阶段没有安装或执行新受限对照。实测需要一份新的精确操作审查。

## 全隔离实测

2026-11-07 13:42:25–13:42:39Z，本人批准 `D0E68D2C…`，按锁定的 56 项输入
运行一次。原 owner 完成 `34543d35` → `68a0d109` 未激活更新，回执 INACTIVE。
真实低完整性 LPAC 的 `QUERY_UNISP`、`ACQUIRE_GATEWAY_V5`、`ACQUIRE_MINIMAL_V5`、
`ACQUIRE_TLS12_V5` 和 `ACQUIRE_TLS12_V4` 均返回 `0x80090305`。所有调用都没有返回
对象。子进程 0 表示对照记录完整。最早失败出现在凭据配置应用前的包查询阶段，
修改 v4/v5、附加标志或 TLS 1.2 参数在此对照中均未改变结果。此证据没有区分
Windows 内部的包可见性、初始化或身份拒绝机制。
[Microsoft 包查询接口](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querysecuritypackageinfow)

原 owner 确认准入关闭、隔离、原 Job 零成员，停止错误 0。隔离与 Job 停止刻度均
为 178 ms，原 owner 顺序按同一停止回报核对。操作器十个原始权限观察一致，最终
安全检查通过。无网关、Winsock 租约、TLS 握手、HTTP 或官方 CLI。只读核对三份获批
回执，派生记录 SHA-256 `88F9F97C1A112B4E6771C444FD1EEB5124EFB8FE3E383FC08890DD4C3EEC65B4`。
同一公开日志窗 Application 一条，无匹配 AV 事件，System 无 Schannel 事件，BFE/AV
Running，完整厂商覆盖 UNKNOWN。许可已消耗，证据留本机
`work/schannel-acquisition-20261107-01/operation-offline-acquisition-once`。

随后普通身份实测 UNISP 和 `Schannel` 两个名称均返回 `0x004107B3`，含
`APPCONTAINER_PASSTHROUGH`，不含 `RESTRICTED_TOKENS`。`Negotiate` 普通对照
为 `0x00883BB3`。三个包查询及释放均返回 0。标志是普通进程可见元数据，不能据此
确定 LPAC 的内部拒绝原因或授予认证能力。先用固定自研对照验证独立于 Schannel 的
TLS 路径，保持同一身份、原认证网关及原网络规则。官方 CLI 使用哪条实际 TLS 路径
仍需阶段性原生资格。[Microsoft 包属性](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkginfoa)

普通对照以本机 OpenSSL 3.5.7 在内存中生成实际 ClientHello。使用候选包中原样管理库
的生产网关解析器，含 TLS 1.3 提议的 1539 字节及仅 TLS 1.2 的 206 字节均被接受并
逐字节重放。错误 SNI 的 1535 字节被拒绝。该对照没有创建 socket 或完成握手。
证据在同一工作目录的 `ordinary-openssl-clienthello`。应用 TLS 在受限身份的首次
真实握手还需要固定资产、原 owner 监督及独立操作审查。
