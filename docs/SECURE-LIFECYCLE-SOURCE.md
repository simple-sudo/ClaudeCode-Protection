# 管理员边界与生命周期源码内核

日期：2026-10-25（America/New_York）。状态：SOURCE_IMPLEMENTED_NOT_COMPILED。本轮只新增源码、协议数据和纯文本检查；未创建系统安装目录、提升、安装或运行项目程序。完整项目仍未完成。

## 新模块的实际边界

`src/ProtectionLifecycle` 是独立 .NET 8 Windows Library，无 Main、无提权、自启或服务注册逻辑，未接入现有日常/工程构建链和 GUI。没有新增可执行入口或构建解锁参数。原构建/运行停止条件保持。

| 文件 | 已写入的源码职责 | 尚未证明 |
|---|---|---|
| FixedLayout.cs | Windows ProgramFiles 下固定代码根及独立私有状态兄弟目录；严格 ID/hash/叶名约束 | 当前机器根、ACL 兼容性未调用验证 |
| PackagePolicy.cs | 内嵌审查摘要授权、私有构造的 ReviewedPackage、严格 JSON 字段/重复检测、14 个固定组件、体积上限 | 无已批准包；bootstrap 自身与全部依赖的可信来源未实现 |
| WindowsPathSeal.cs | 所有祖先句柄、最终路径/对象属性/硬链接计数/NTFS、句柄读取 owner/DACL；原子带受保护 ACL 创建新目录/文件 | Windows API、共享行为、实际拒绝矩阵和并发安全未运行验证 |
| ProtectedState.cs | 管理员 token 要求、独立受保护状态、操作锁、CREATE_NEW 回执、flush 与原子指针替换回读 | 断电持久性、完整异常/恢复闭环未验收 |
| Lifecycle.cs | 安装/更新/回滚/卸载的阶段账本、绑定 installation/operation/target、前序哈希；冻结数据复制暂存 | 无完整 handlers、恢复阅读器、真实 runtime barrier/资源清理 owner 实现 |
| BrokerProtocol.cs | 2 KiB 严格请求、固定操作和 ID、绑定安装身份、CREATE_NEW 防重复请求 | 无已认证传输/生产 broker 可执行程序或调用链 |

## 包授权与源文件替换

ApprovedManifestSHA256 当前固定为 null，授权必然拒绝。摘要不能来自命令行、环境变量或旁边的 manifest/hash 文件。ReviewedPackage 的私有构造仅在固定摘要校验和严格清单解析后创建；哈希和解析使用同一份私有字节快照。

清单不能指定路径或任意组件，只能引用固定 Asset ID；包括日常后端、GUI、未来生产 broker 及生命周期库。不包含工程程序、selftest、ProbeFence 或可自由扩展的脚本列表。每组件限制 128 MiB，总计 256 MiB，清单 64 KiB。当前生产 broker 尚未实现，也没有完整包。

源目录只是数据来源，不能直接提升或执行。暂存通过同一个禁止共享写入/删除的文件句柄先哈希再复制，目的文件 CREATE_NEW、受保护 ACL、flush 后按同一句柄核对长度和哈希。祖先路径句柄持有期间核对最终路径、非重解析、类型及文件硬链接计数，目的目录独立验证 owner/DACL。

这些检查不认证最初启动的 bootstrap。后续必须先实现并审查一次性 bootstrap 的来源、全部 EXE/DLL/依赖身份与 UAC 绑定；不能只是设置摘要再从用户可写目录提升执行。签名或本地冻结引导的具体方案仍待实现，不把证书/VM 当作用户新前提。不配置发布摘要、不生成包、不触发运行来绕过本轮静态阶段。

## 管理员目录与状态

代码根固定为 Windows ProgramFiles 下 ClaudeCodeProtection，管理员状态根为同级 ClaudeCodeProtection-State；状态根不在代码卸载范围。原 CommonApplicationData 初始化提议已被后续父目录创建权限审查替代，没有移动既有数据。版本为代码根 versions/<32位release>。不接受任意目标目录。目录新建时即带受保护 DACL，普通用户不能获得代码/状态写权限；代码可读执行，管理员状态默认仅 SYSTEM/Administrators 可访问。owner 和祖先危险权限采用保守白名单，包含 OS TrustedInstaller 身份；未审阅 ACE 类型、空 DACL、可变祖先、非 NTFS 或重解析均拒绝。

句柄共享不保护所有安全元数据，因此源码另外通过 GetSecurityInfo 检查 owner/DACL，并在变更前重核；不声称 FileShare 单独阻止 ACL 改写。不对既有目录自动改 ACL 或接管缺失所有权标记的目录。目录已存在却 marker 缺失/不匹配时失败并保留现场。

状态操作锁序列化本工具合作的管理员动作；不是对恶意管理员、内核或已受控 bootstrap 的隔离。新日志 CREATE_NEW，指针核验旧哈希后在受保护父目录内替换并回读。回执与历史证据不自动删除。初次目录创建到 marker 的中断、部分暂存、指针提交中断仍须专用恢复 owner 实现；当前保留失败，不补写 PASS。

## 阶段与证明

实际嵌入 LifecycleProtocol.json 固定 16 条转换。安装/更新必须 staged→verified→switched→completed-inactive；回滚必须核验拥有的旧 payload 后切换，仍 completed-inactive。卸载必须依次证实 owned-processes-zero、owned-resources-absent、pointer-absent、exact-owned-files-absent、removal-readback，才 completed-removed。

每步读取的管理员证明回执必须匹配 installation ID、operation ID、目标 release（卸载为 null）、证明类型、VERIFIED 和 SHA-256；阶段账本仅在落盘成功后前进。运行期 admission barrier 和真实所属进程/资源 owner 只有接口，尚无实际实现；不能用状态文件、布尔值或旧测试冒充实时观测。阶段账本也不代替实际安装、切换、恢复、回滚或卸载 handlers。

BrokerProtocol.json 仅允许 inspect、recover(操作 ID)、update(已暂存 release ID)、rollback(拥有的 release ID)、uninstall。请求不能传命令、脚本、DLL、路径、SID、PID、WFP GUID/编号、URL、代理端点或 activate。install 属于未来已验证的一次性 bootstrap；现有真实 Claude 仍延期。生产 broker 尚不存在，旧工程 helper 未被升级为生产组件。

## 本轮证据与后续验收

10 组纯 PowerShell 协议图检查通过：枚举实际嵌入数据的全部完成路径与证明顺序；对捷径、激活终点、重复边、循环、缺证据、丢失配置/证据保留、任意管理能力的变异输入均拒绝。范围仅为声明的 JSON 图/表面；未加载 C# 或调用 Windows 安全 API，不能证明 C# 执行器行为与协议相符。

新增 C# 仅做 Roslyn ParseText，不生成程序集、不做类型/互操作验证。后续仍须：可信 bootstrap 与发布身份、实际受保护目录负向矩阵、源目录替换/硬链接/重解析/继承权限对照、句柄并发、真实 admission/Job/WFP owner、完整阶段恢复与卸载、用户态数据目录适配、日志权限和版本启动器。日常后端目前仍按开发布局写日志/配置备份，不能打包即宣布安装版可用。

继续本机验证，不要求 VM；AV 保持开启，再次告警立即停止。不停止 FlClash/TUN/BFE，不改全局网络、不启用真实 Claude 规则、不读取认证内容、不重复原 selftest。用户已有管理员操作授权不因新模块失效，UAC 仍须本人确认；本轮没有发起 UAC。

依据：[CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)、[GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)、[GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew)。官方 API 语义不替代源码运行/安全软件兼容性或整机安全鉴定。

## 后续版本/恢复源码更新

新增 VersionStore.cs 与 LifecycleRecovery.cs、RecoveryProtocol.json，已写入具体的安装/更新/回滚未激活切换、拥有版本核验与选择历史、切换前精确指针快照、连续哈希/证明/工件绑定阅读器和非破坏性恢复处置。新操作拒绝未解决的旧账本；原账本及失败保留。上一节“完整handlers/恢复阅读器未实现”是本模块初版状态；目前仍缺完整卸载/其精确恢复、首次初始化窗口、真实runtime/broker和bootstrap，不计运行验收。当前边界详见 LIFECYCLE-RECOVERY-SOURCE.md。

## 后续精确卸载源码更新

ExactUninstall.cs 与 RemovalPolicy.cs/RemovalProtocol.json 已补入卸载与指定账本续接，固定组件分页快照、目录/文件身份核验、同句柄删除及独立失败记录。原“卸载owner未实现”更新为“具体文件卸载/续接已写入，实际runtime/资源owner仍未实现”。首marker和截断文件身份、真实API/AV/故障验收仍未完成。详见 EXACT-UNINSTALL-SOURCE.md。

## 后续创建身份源码更新

新增CreationIdentity.cs，初始安全描述符中的非继承RC标记绑定固定角色及安装/操作ID；它是元数据，不注册账户/服务，不授予写权限，也不构成WFP身份或包批准。状态初始化修复、字节完成回执和目录卸载消费已写入，未编译/运行；截断payload消费、实际标记权限/持久性与runtime/broker/bootstrap资格仍未完成。见 CREATION-IDENTITY-SOURCE.md。

## 后续创建身份与读取异常源码更新

CreationIdentity.cs 已接入创建时SD标记、固定角色/路径/管理员计划核对、实际句柄字节完成回执；管理员状态改为ProgramFiles私有兄弟目录，父目录CreationParent策略拒绝普通主体创建/写入。初始化修复只处理具有正确归属标记的固定身份元数据，目录卸载快照schema 2存储标记；旧schema不回填。缺失仅接受OPEN_EXISTING返回且落在工具范围内，后续查询同数值错误保持UNKNOWN。均未编译/运行；截断payload消费仍待完成，见 CREATION-IDENTITY-SOURCE.md。

## 2026-10-26部分写入源码更新

PendingFileAuthority.cs补入部分写入清理资格，卸载快照schema 3保存创建标记和ByteState；只有原操作planned、完成回执不存在、未发布且来源/身份/实际字节均锁定，才可按原快照精确清理。完成或发布后漂移仍拒绝，旧schema不回填。没有执行/类型/安全API验证；私有账本损坏的专用恢复、真实runtime/资源owner、broker/bootstrap和用户态状态仍未完成，见 PENDING-WRITE-CLEANUP-SOURCE.md。

## 2026-10-26完成回执恢复源码更新

新状态记录采用完整私有暂存后不覆盖发布并回读对象ID/摘要。完成回执缺失/语法损坏可从实际完整源文件重新观察，原始回执先保留，schema 2明确记录新时刻与before来源；有效冲突拒绝，不复原旧成功或推进阶段。其他坏账本及实际运行期边界仍未闭合，未编译/执行，见 COMPLETION-RECOVERY-SOURCE.md。

## 2026-10-26Job成员控制源码更新

Job子组件已有具体Win32所有权/查询/停止源码，使用管理员boundary加显式namespace DACL与内核Job标记，避免普通全局命名碰撞。namespace失联不推导进程不存在；集合只报告登记Job成员，不实现完整ILifecycleRuntimeLease，也不授予WFP或启动资格。原子创建绑定/用户token、真实准入/网络owner及崩溃范围核验仍缺失，未编译/执行，见 OWNED-JOB-SOURCE.md。
## 2026-10-26安装身份WFP源码更新

WFP子组件已有实际原生API声明和事务/精确对象所有权/初始隔离/重建实现，私有计划摘要绑定对象providerData；无provider服务绑定假设，无外部SID/编号/端点入口。只报告安装package的ALE_CONNECT范围，不组成完整runtime lease，不授予代理、启动、即时全流量断网或跨重启资格；最终屏障卸载尚无接口。未编译/执行，见 PERSISTENT-FENCE-SOURCE.md。