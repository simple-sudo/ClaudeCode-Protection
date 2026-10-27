# 当前开发状态

更新时间：2026-10-27，最新实际运行窗口06:53Z（America/New_York）。当前状态以本页为准；旧版本、原失败、各轮源码/构建描述完整保存在[历史状态快照](STATUS-HISTORY-20261027.md)和[历史验收账本](PROJECT-ACCEPTANCE.md)，其中“当前”“待执行”均指各自当时，不代表今天的选择。

## 结论与统一目标

**隔离内小型CUDA计算已经实际通过；严格代理HTTPS仍被证书吊销检查阻断；完整产品尚非DELIVERABLE。**

[2026-10-27完整产品指导](PRODUCT-DIRECTION-20261027.md)统一要求网络、严格十四项可信门禁、独立系统安全准入、宿主敏感资源隔离、可用开发工具/子进程及本机GPU。不得以局部成功宣布整体完成。真实Claude登录/推理/正式会话继续DEFERRED_BY_USER。

目标运行工具目前返回usageLimited，不能写成active、完成或后台继续；目标本身未完成。后续接续使用本页的实际选择、原始记录和剩余工作，不重复索取已有范围的常规授权。

## 当前安装与运行证据

- 当前release：ebd633c55ccb4357b26c0daa008790ba；manifest SHA256 B832A15F4A52CEE50B09707C032BB9199296A69A79A735BC84BAFA56A142A94B；operation 884f0e2bf88f4e56a6edd2a5122d03e4，INACTIVE。
- 当前生命周期DLL SHA256 2788A266C1F0B658E8E4F643C099E65EF5C7AEF6238A1974E3DD361CAF5E3DBC；正式代码C:\Program Files\ClaudeCodeProtection\versions\上述release，私有状态C:\Program Files\ClaudeCodeProtection-State。旧版、原bootstrap及全部失败保留。
- 本轮管理图33输入BUILD0、bootstrap34输入BUILD0；限定离线、SDK8.0.422/ref8.0.28、无第三方包/分析器/生成器。非生成检查6项目0错误/警告；无module initializer。
- 6项TLS拒绝判据、7项GPU结果判据、8项UDP/TCP候选判据通过；是限定验证，非完整保护证明。普通用户inspect-runtime0，其余受限管理/子进程入口125拒绝。
- 已安装更新20项来源/嵌入批准及14资产哈希/权限/普通写拒绝核对成功。原9项GUI/daily字节复用，当前目录GUI未重新打开；没有常驻产品进程、服务或自启动。

| 能力 | 证据等级与实际结果 | 尚不能据此得出 |
| --- | --- | --- |
| 原子进程准入 | INTEGRATED、限定VERIFIED：安装AppContainer SID、Low4096、capability0、Job绑定均在创建时完成，挂起核对后首次恢复 | 任意Claude/工具可运行、所有子进程完整归属 |
| 持久网络隔离 | INTEGRATED、限定VERIFIED：最终独立只读回读6角色完整，最新filterId102770–102775、子层weight65533 | 重启/全机外网、系统DNS服务流量全部归属 |
| 本地网络负向 | 限定VERIFIED：对照6路各1收据；完整隔离及代理开放阶段TCP4其他端口/地址、TCP6均10013，UDP4/6/原始UDP53发送调用可能成功但独立nonce收据均0，负向窗口2秒，collector健康 | UDP发送API被拒绝、物理出口无泄漏、系统解析器已覆盖 |
| 指定代理 | TCP连接127.0.0.1:7890实际成功；既有FlClash进程/创建时间/磁盘映像/监听身份受持有核对 | TLS/Claude服务/真实出口成功；映射内存与磁盘逐字节相同 |
| 严格HTTPS | BLOCKED：SecureConnectionError/AuthenticationException；实际TLS PolicyErrors4，ChainStatus64和16777216，仍拒绝 | 证书已吊销、根证书不可信或一般代理故障；不能关闭吊销检查补绿 |
| NVIDIA GPU | c9e823版本限定VERIFIED：宿主及隔离内RTX4060均完成16项Driver API、1KiB显存、256整数加7内核、同步/全量回读/同摘要、释放成功 | PyTorch、代表性大型工作负载、其他进程GPU内存隔离；新ebd库不继承旧包运行证据 |
| 精确生命周期 | 本轮14个登记Job均有绑定一次性准入摘要的关闭/零成员回执；每次精确豁免已移除、原其他项保持，profile Delete API0 | profile独立不存在、进程崩溃/断电/重启、活动更新/卸载已验收 |
| 严格十四项与系统门禁 | 统一要求已SOURCE记录；当前正式Claude启动仍关闭，未有完整可信体检准入链 | 十四项已实现/全绿或CLI可绕过启动 |
| 文件/注册表/进程敏感资源与开发工具 | 已有安装状态/资产权限验证；面向开发侧的完整资源拒绝+授权工作区/工具/子进程纵向评估尚缺 | 完整宿主保密、Git/Python/Node/PowerShell等开发兼容已通过 |
| 完整交付 | 未完成；真实ClaudeDEFERRED_BY_USER | 可交付完整产品或持续后台保护 |

## 本轮关键原始记录

**GPU成功**：c9e8231060b14950a878ad56a4e05260，manifest49B57CE036DBE8391D9967875BE1A7CB4505EB0F92407040DB88EE4CF7CB6CBE，request93054db03fd842dbb0c9be331e8abebb，Job e655fd78177b4a65a29c92616f95eb3c，child40508。结果SHA256 4ADEB88C463E46506A15EF3743B8E106C7554A7CE7427BE97E291713B95A4034，宿主/子进程一致；网络未开放。ProgramFiles/ClaudeCodeProtection-Gpu-20261027-r1、work/gpu-run-r1-control及私有回执保留。GPU仅搜索System32 nvcuda.dll，实际签名Valid、驱动32.0.16.1047、CUDA Driver版本13030；固定驱动摘要/只读租约，不下载/运行模型、不改设备/驱动设置、不CPU替代。

**当前TLS失败**：request21720be4982541ca9543e0ba8835e12b，代理阶段Job d501d256092e41feb43ec85784d9c64a，child41488。ProgramFiles/ClaudeCodeProtection-Network-20261027-r6与work/network-run-r6-control及私有记录保留。64=RevocationStatusUnknown、16777216=OfflineRevocation，已用本机枚举与[微软定义](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509chainstatusflags)核对。观测确认吊销依赖无法完成；具体CRL/OCSP请求与流量归属尚未抓取，因此“受限系统验证路径”是待核实原因，不是已经证明全机吊销服务停机。此轮未执行第四阶段，最终完整隔离回读成功。不得将前几轮信息较少的FAIL改写为通过。

TLS诊断callback仍要求certificate/chain存在、PolicyErrors0、所有ChainStatus0，吊销检查开启；没有接受任意证书。UDP send完成不等于投递，见[微软sendto契约](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-sendto)。这些条件与当前有限证据明确分开。

## 下一步工程判断与剩余缺口

1. 停止重复相同代理HTTPS资格；先定位Windows吊销验证的具体依赖、缓存/进程归属及受控访问方案，复用当前Broker/代理审核。不得放行任意外部或本地管理目的地、关闭证书检查、放宽AppContainer作为修复。每个方案必须重新做端到端与负向验证。
2. 代理HTTPS通过后补完整“开放→再阻断”及代理失效、控制器崩溃、Watchdog/规则漂移恢复。系统DNS经服务代理、物理出口、真实代理崩溃、重启仍UNKNOWN；不要只重复已明确的GPU微负载或本地基线。
3. 尽早做自有敏感文件/注册表/进程对象拒绝与授权工作区读写、代表性工具/子进程同时可用的纵向切片；明确管理侧和开发侧权限。GPU已证明当前边界可计算，无须为此撤销边界；随后按需要补PyTorch/代表工作负载。
4. 将十四项环境信息与独立系统安全条件接入同一可信Broker/原子准入/实际会话绑定、时效与失效撤销；接通GUI状态。不存在用旧PASS或GUI绿色代替当前安全授权的捷径。
5. 完成恢复、维护冲突/中断、活动更新、精确卸载与普通用户日常流程；当前固定INACTIVE迁移不当作通用生命周期完成。

## 保留边界

Kaspersky事件未解决；有限Application观察无新告警，完整厂商告警覆盖UNKNOWN。AVP/BFE运行、FlClash/Core20944/14268保持；没有重配Global/系统代理/TUN，没有全机DNS/IPv6/时区更改，没有退休样本/旧聚合自测/AV排除或规避。UAC本人控制。真实Claude规则仍禁用、未启动Claude。最后检查没有本轮产品测试进程存活。

原有origin及Git历史保留，已安全合并用户README的ddb9d9c到49ac5c1，未推送；后续本地提交仍只包含可审查源码/文档，状态、日志、备份、PID、二进制和私人数据不入Git。当前页面整理只移动历史文本，保留[历史快照](STATUS-HISTORY-20261027.md)原字节；历史快照和账本不具有新的运行授权。
