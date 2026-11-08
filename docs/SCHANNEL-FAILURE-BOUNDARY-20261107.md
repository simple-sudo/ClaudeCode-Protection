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

## 独立应用 TLS 对照

保护库增加有界的 OpenSSL x64 内存 BIO 传输。客户端显式持有单一 DER 信任锚，
核验 SAN，禁止通配符、CN 回退和重新协商。最低 TLS 1.2，最高 TLS 1.3。传输只使用
调用方持有的模块和字节流，既不打开 socket，也不加载默认信任文件或 OpenSSL 配置。
接收与发送各限制 128 KiB，失败后不能继续发送应用数据。暂未接入实际网关连接，
正式 TLS 的离线吊销、信任链与认证策略未变。
[OpenSSL 信任验证](https://docs.openssl.org/3.5/man3/SSL_CTX_set_verify/)
[OpenSSL 主机名验证](https://docs.openssl.org/3.5/man3/SSL_set1_host/)

普通对照只在内存中生成临时 CA 和服务端证书，固定的 3.5.7 运行库逐一核对长度及
SHA-256。客户端实际握手首段先走生产网关解析和重放，两端才完成 TLS 握手及加密的
请求和响应。错 SAN 返回验证错误 62，未知信任锚返回 20，提前 EOF 也未放行应用数据。
早期 Schannel 服务端夹具超时，补观测得到 `0x8009030E` 和不支持临时密钥，换成
OpenSSL 内存对端后通过。初次超时和诊断保留。Git 所带 3.2 已结束公开支持，本阶段
采用本机 3.5.7 仅作普通离线输入。真实 LPAC 前须由原 owner 持有固定、受支持、
不可替换的运行库，尚未把普通用户目录中的 DLL 纳入产品安装包。
[OpenSSL 支持周期](https://mirror.openssl-library.org/roadmap/index.html)

Lifecycle、Broker、Bootstrap 和 OwnedToolLaunch Release BUILD0/0。七个已有普通
回归入口通过，涵盖网关回报与资格、Schannel 原生及首段对照、未激活迁移、GPU 回报
和离线证书策略。证据留在本机 `work/openssl-transport-20261107-01`。
真实 LPAC、真实代理转发、真实上游、官方 CLI 与 L3 均未在本阶段执行。

## 固定运行库和全隔离对照

候选从 [Python 3.14.10 x64 发布包](https://www.python.org/downloads/release/python-31410/)
提取 OpenSSL 3.5.9 的两份 DLL。下载包 SHA-256 与发布页及
[发布清单](https://www.python.org/ftp/python/3.14.10/python-3.14.10-embed-amd64.zip.spdx.json)
相同，两份 Authenticode 签名均为 Valid，签名者是 Python Software Foundation。
不安装或运行 Python。3.5.7 的先前候选和普通离线证据原样保留。3.5.9 包含
[OpenSSL 3.5 系列安全修复](https://mirror.openssl-library.org/news/openssl-3.5-notes/)。
本阶段资产只用于固定的内存对照。

包 v1 仍只认原 14 项。v2 精确接纳额外两份 DLL 的角色、路径、长度和摘要。
安装前、安装后和恢复按各版本的资产清单核验。恢复清单仍以原所有者的安装记录、
日志和创建标记为依据。原 owner 持有两份 DLL 和安装目录的锁，子进程再次核验
字节，只能从固定 Broker 目录装载，对系统依赖只搜索 System32。没有新增注册表、
用户目录或网络权限。

OpenSSL 对照与 Schannel 对照共用原 Job、全隔离、挂起时验证和退出顺序。原
owner 必须核验旧准入和回环记录闭合，使用同一低完整性 LPAC 单一能力身份。
子进程不接收目标或证书参数，使用临时内存证书及单一受信根，无网关、回环例外、
Winsock 租约、socket 或外部对端。回报绑定会话、原进程 PID、创建时间和退出码。
离线交换完成与原所有者关闭分别记录，故障回报不得视作交换通过。

五产品 Release BUILD0/0。候选
`d8be9fe79b8a40cfb812b7304c5d857d` /
`9A8B7310B33E1DC3CF81CC75D0E460B9C9DB8ED0FD8B74C9B34E74F403E487CB`
只接受 `68a0d109` 及其 `7011F015…` 清单为前驱。22 项候选工件和 145 项构建
输入在回归前后一致，包含内嵌清单、精确迁移和双份管理库。原样管理库和 DLL
通过 29 项 OpenSSL 与清单检查、90 项迁移及其他普通回归。内存握手、双向交换、
错名 62、未知根 20、握手提前 EOF 拒绝已实测。另有普通恢复和 103 项生命周期
夹具，未调用原生受保护后端。证据位于本机 `work/openssl-owner-20261107-01`。
候选安装、低完整性 LPAC 装载及关闭仍 NOT_RUN，需要单独的固定操作审查。
本阶段没有执行官方 CLI 或真实网络对照。

## 首次全隔离装载实测

2026-11-07 14:25:37–14:25:52Z，本人批准 `A8EE4F1E…`，按冻结的 60 项输入
执行一次。原安装所有者完成 `68a0d109` → `d8be9fe7` 更新，回执 INACTIVE。
受限子进程恢复执行后在 `MODULES` 报 `0x80131501` 并退出 3，内存握手未发生。
该回报无法区分子进程映像定位、文件校验、已有模块、加载或映射检查。

原所有者确认撤销准入、全隔离及原 Job 归零，隔离和 Job 停止刻度均为 187 ms，
停止错误为 0。操作器十处自身权限观测一致，最终检查通过。外层退出 0 反映原
操作闭合，TLS 工作负荷保留 FAIL。三份获批回执独立核验，派生 SHA-256
`E1E8DB29052F195383F298044265E04B85612F5E31A9835C3F9ED6F393F3E117`。
同一公开 Application 时间窗零项，BFE 和 AV 服务 Running，厂商完整覆盖 UNKNOWN。
许可已消耗。证据留在本机 `work/openssl-owner-20261107-01/operation-offline-openssl-once`。
无外部连接、Winsock 租约或官方 CLI 执行。

后续候选使用原所有者已锁定的发布版本及原生进程映像验证。子进程将版本号与自身
可执行文件及管理程序集位置核对，从同一固定角色目录加载两份经摘要验证的 DLL。
子进程去掉了 Shell 的 Program Files 查询，避免引入一次受限身份下的目录探测。
根据微软文档，默认的已知文件夹查询可在路径不可访问时失败。它是否导致首次实测
失败仍 UNKNOWN。[Windows 已知文件夹查询](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/ne-shlobj_core-known_folder_flag)

子进程报告 v2 区分映像、预装载、文件读取、摘要、装载、映射和释放。原会话的
版本、PID、进程创建时间、进展顺序及退出码仍必须匹配。旧报告保留原 v1 语义。

候选 `d7fc0bbf264a44bc8d68752669a8742e` /
`EB3181E3C655524E8A1A03562D82D8B0ABF4DA463912C629FA2089869393CB4D`
只接纳 `d8be9fe7` / `9A8B7310…`。五产品 Release BUILD0/0，22 项工件及
145 项构建输入核验一致。候选原样管理库通过五个普通入口，包括 40 项 OpenSSL
和清单验证、97 项迁移验证。普通身份已实测内存握手和三类拒绝，路径绑定及回报
验证由夹具覆盖。候选安装和低完整性 LPAC 装载尚未执行。证据留在本机同一工作
目录的 `module-binding-exact-candidate` 及 `module-binding-exact-tests`。

## 第二次全隔离实测

2026-11-08 00:38:47–00:39:18Z，本人批准 `8F30C4FF…`，按冻结的 62 项输入执行
一次。安装回执确认 `d8be9fe7` → `d7fc0bbf` 为 INACTIVE。低完整性 LPAC 子进程
恢复后通过两份固定 DLL 的读取、摘要及映射校验，在 `FIXTURE / 0x8007000E` 停止。
子进程退出 3，没有 TLS 握手。返回值在 Windows 中定义为 E_OUTOFMEMORY。
实际失败调用及内部原因 UNKNOWN。[Microsoft HRESULT 表](https://learn.microsoft.com/windows/win32/seccrypto/common-hresult-values)

隔离和 Job 停止刻度均为 219 ms，原所有者确认准入关闭、原 Job 归零和停止错误 0。
操作器十处权限观测一致，三份获批回执独立核验 SHA-256
`36EB187DD50A4494E929B0EA1C02F21AEC7A8D5585A9F567BB658B251F8FD943`。
公共 Application 时间窗零项，BFE 和 AV Running，完整厂商覆盖 UNKNOWN。
许可已消耗。证据在 `work/openssl-owner-20261107-01/operation-module-binding-once`。
没有外部连接、Winsock 租约或官方 CLI 执行。

## 内存证书候选

固定 OpenSSL 3.5.9 在子进程内生成 Ed25519 密钥、两个独立根和一份叶证书。
私钥通过同进程原生对象交给内存 TLS 对端，根证书以有界 DER 交给客户端。
不调用 .NET 的 Windows 证书准备链，不注册系统证书或密钥，不加载配置或证书
路径。客户端验证原规则仍适用，回报 v3 分辨密钥、证书、扩展、签名及编码错误，
保留 v1/v2 读取。[OpenSSL 证书签名](https://docs.openssl.org/3.5/man3/X509_sign/)

候选 `8ad9a646a9f846a397c6c677def87e90` /
`F5AE7357F63A1D1D77F35F8975A02EEAE3693179F76A341EACF0BCCCFE1186DC`
只接纳 `d7fc0bbf` / `EB3181E3…`。五产品 Release BUILD0/0，22 项工件及
146 项构建输入前后复核一致。候选原样管理库和 DLL 通过七个普通入口。42 项
OpenSSL 检查包含真实内存握手、加密请求与响应、生产网关首段重放、错名 62、
未知根 20、提前 EOF；另有 104 项精确迁移夹具。证据在本机同一工作目录的
`native-fixture-exact-candidate` 及 `native-fixture-exact-tests`。
候选安装与受限执行 NOT_RUN，需按当前工件重新审查一次。

## 受限随机数初始化实测

2026-11-08 00:47:00–00:47:15Z，本人批准 `3F0B2E88…`，按冻结的 62 项输入
执行一次。原所有者完成 `d7fc0bbf` → `8ad9a646` 未激活更新。全隔离低完整性
LPAC 进入固定 OpenSSL 密钥生成，在 `FIXTURE_KEY / 0x1200006C` 退出 3。
对应 OpenSSL 3.5.9 的 `RAND_R_ERROR_INSTANTIATING_DRBG`。握手及其负对照
未执行。[OpenSSL 3.5.9 随机数错误定义](https://raw.githubusercontent.com/openssl/openssl/openssl-3.5.9/include/openssl/randerr.h)

原所有者确认撤销准入、全隔离及原 Job 归零，隔离和 Job 停止刻度均为 174 ms。
停止错误为 0，操作器十处权限观测一致。三份回执独立核对，派生 SHA-256
`B71E580E6BA1564106016E50D95D0AE1396D079F3597BB3ECF11F5AD359881EA`。
公开 Application 时间窗零项，BFE 和 AV Running，完整厂商覆盖 UNKNOWN。
许可已消耗。证据位于本机 `work/openssl-owner-20261107-01/operation-native-fixture-once`。

静态读取同一 PSF libcrypto 的 PE 导入，发现 `CryptAcquireContextW` 和
`CryptGenRandom`，无 `BCryptGenRandom` 导入。上游 3.5.9 对 MSVC 和
`_WIN32_WINNT >= 0x0600` 的配置使用 `BCryptGenRandom`。这是下一次有针对性
构建的依据，旧接口在该受限进程内的原始状态仍 UNKNOWN。后续须维持操作系统熵源
和全隔离，并用新的字节执行原所有者实测。
[OpenSSL 3.5.9 Windows 熵源实现](https://raw.githubusercontent.com/openssl/openssl/openssl-3.5.9/providers/implementations/rands/seeding/rand_win.c)

## Windows 系统熵源候选

核验上游 OpenSSL 3.5.9 发布源码 SHA-256
`603F5602E2EEF00D77FBD429D34DCD5822BB301757A1BC9CDB24C670F1EB859A`。
使用本机 MSVC 19.44.35227、Windows SDK 10.0.26100.0 和工作区便携 Perl 5.42.3。
按 `VC-WIN64A-HYBRIDCRT`、`_WIN32_WINNT=0x0A00`、`--with-rand-seed=os`
构建。固定对照禁用配置自动加载、外部 provider 模块和 legacy provider。构建
没有修改系统安装或向系统安装 DLL。编译报告存在上游警告，未运行上游全套测试。
原源码、工具包、命令、配置、导入和编译记录保留于本机 `openssl-cng-build-20261107`。
[OpenSSL 3.5 发布入口](https://www.openssl-library.org/source/)

PE 导入复核确认新 libcrypto 导入 `BCryptGenRandom`，未导入旧版
`CryptGenRandom` 或 `CryptAcquireContextW`。新 libssl 指向固定的新 libcrypto
文件名。包 v3 固定新 DLL 的角色、长度与哈希，旧包 v1/v2 和原创建及恢复角色
继续可读。新受限入口只接受 v3 的运行库，仍不搜索可写目录。
[Windows 系统随机接口](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom)

候选 `afb95ad171c4476e9adb8eb610987625` /
`EEE8E79F82E09C405911523E935DA3537E137446433590D835B55FB8C47F3B2D`
只接纳 `8ad9a646` / `F5AE7357…`。五产品 Release BUILD0/0，22 项工件、
146 项构建输入核验一致。原样管理库和 DLL 通过七个普通入口，含 47 项 OpenSSL
及清单验证和 111 项未激活迁移。普通身份内存握手、双向交换、生产网关首段重放
和三项拒绝均通过。真实低完整性 LPAC 对 Windows 系统熵源的验证仍 NOT_RUN。
证据位于本机同一工作目录的 `windows-entropy-exact-candidate` 及
`windows-entropy-exact-tests`。
