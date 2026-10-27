# 当前开发状态

更新时间：2026-10-27，最新实际运行窗口07:10Z（America/New_York）。当前状态以本页为准；旧版本、原失败、各轮源码/构建描述完整保存在[历史状态快照](STATUS-HISTORY-20261027.md)和[历史验收账本](PROJECT-ACCEPTANCE.md)，其中“当前”“待执行”均指各自当时，不代表今天的选择。

## 当前系统事件：停止运行验证

**BLOCKED（运行验证）：测试窗口发生系统蓝屏0x1E，因果关系UNKNOWN。** 已停止新增产品构建/安装/执行和故障注入，先做只读故障定位。未发重启命令并不证明测试无关；在查明原因前重复诊断的操作已停止。当前无本轮产品测试进程，真实Claude继续延期。当前安装实际为814cf4331fcb4fd6a95fee2973b734a6/3EB4F1A88CAC2B3CFB6A561B357E65600745F6B989D8D9A7916A7FA0537FC7BD，operation81960efc780d462395c796056a4e0861，INACTIVE；下方版本/通过范围为历史。详见[系统蓝屏事件](INCIDENT-20261027-SYSTEM-CRASH.md)。
## 结论与统一目标

**四阶段限定网络矩阵已实际通过，隔离内小型CUDA计算亦有原c9包成功证据；完整产品尚非DELIVERABLE。** 当前网络结果/范围见[四阶段网络资格](NETWORK-QUALIFICATION-20261027.md)。

[2026-10-27完整产品指导](PRODUCT-DIRECTION-20261027.md)统一要求网络、严格十四项可信门禁、独立系统安全准入、宿主敏感资源隔离、可用开发工具/子进程及本机GPU。不得以局部成功宣布整体完成。真实Claude登录/推理/正式会话继续DEFERRED_BY_USER。

目标运行已恢复active；上一轮usageLimited是当时终态记录，不是功能完成。上一轮分类为progress：严格CRL依赖修正及四阶段限定网络矩阵通过。当前继续原目标及完整2026-10-27要求，不声称会话停止后后台继续。

## 当前安装与运行证据

- 当前release：fd4f9f85655342cebc46aab4d19982d8；manifest SHA256 7EC62DE8F572CBED678616FF2E1F1A815C520463BD172E998A546CA975A7593C；operation 3f63a9da217f47fdada03d298146cfce，INACTIVE。
- 当前生命周期DLL SHA256 A8C9ACF27EC9BF1CEDAD03F9ACBBBA6C4E07C84DFC8AFE412AC0578318D1F8C1；正式代码C:\Program Files\ClaudeCodeProtection\versions\上述release，私有状态C:\Program Files\ClaudeCodeProtection-State。旧版、原bootstrap及全部失败保留。
- 本轮管理图34输入BUILD0、bootstrap35输入BUILD0；限定离线、SDK8.0.422/ref8.0.28、无第三方包/分析器/生成器。非生成检查6项目0错误/警告；无module initializer。
- 28项既有TLS/GPU/UDP/ASN判据、6项吊销候选拒绝和6项内存native原语通过；是限定验证，非完整保护证明。普通用户inspect-runtime0，其余受限管理/子进程入口125拒绝。
- 已安装更新20项来源/嵌入批准及14资产哈希/权限/普通写拒绝核对成功。原9项GUI/daily字节复用，当前目录GUI未重新打开；没有常驻产品进程、服务或自启动。

| 能力 | 证据等级与实际结果 | 尚不能据此得出 |
| --- | --- | --- |
| 原子进程准入 | INTEGRATED、限定VERIFIED：安装AppContainer SID、Low4096、capability0、Job绑定均在创建时完成，挂起核对后首次恢复 | 任意Claude/工具可运行、所有子进程完整归属 |
| 持久网络隔离 | INTEGRATED、限定VERIFIED：最终独立只读回读6角色完整，最新filterId103002–103007、子层weight65533 | 重启/全机外网、系统DNS服务流量全部归属 |
| 本地网络负向 | 限定VERIFIED：对照6路各1收据；完整隔离及代理开放阶段TCP4其他端口/地址、TCP6均10013，UDP4/6/原始UDP53发送调用可能成功但独立nonce收据均0，负向窗口2秒，collector健康 | UDP发送API被拒绝、物理出口无泄漏、系统解析器已覆盖 |
| 指定代理 | TCP连接127.0.0.1:7890实际成功；既有FlClash进程/创建时间/磁盘映像/监听身份受持有核对 | TLS/Claude服务/真实出口成功；映射内存与磁盘逐字节相同 |
| 严格HTTPS | 限定INTEGRATED/VERIFIED：原OS离线错误保留；3份经代理取得的固定CRL在进程内严格检查均通过，最终HTTPS200 | 其他TLS栈/CA/网站已兼容；不能关闭吊销检查或泛化放行 |
| NVIDIA GPU | c9e823版本限定VERIFIED：宿主及隔离内RTX4060均完成16项Driver API、1KiB显存、256整数加7内核、同步/全量回读/同摘要、释放成功 | PyTorch、代表性大型工作负载、其他进程GPU内存隔离；新ebd库不继承旧包运行证据 |
| 精确生命周期 | 累计21个登记Job均有绑定一次性准入摘要的关闭/零成员回执；每次精确豁免已移除、原其他项保持，profile Delete API0 | profile独立不存在、进程崩溃/断电/重启、活动更新/卸载已验收 |
| 严格十四项与系统门禁 | 统一要求已SOURCE记录；当前正式Claude启动仍关闭，未有完整可信体检准入链 | 十四项已实现/全绿或CLI可绕过启动 |
| 文件/注册表/进程敏感资源与开发工具 | 已有安装状态/资产权限验证；面向开发侧的完整资源拒绝+授权工作区/工具/子进程纵向评估尚缺 | 完整宿主保密、Git/Python/Node/PowerShell等开发兼容已通过 |
| 完整交付 | 未完成；真实ClaudeDEFERRED_BY_USER | 可交付完整产品或持续后台保护 |

## 本轮关键原始记录

**GPU成功**：c9e8231060b14950a878ad56a4e05260，manifest49B57CE036DBE8391D9967875BE1A7CB4505EB0F92407040DB88EE4CF7CB6CBE，request93054db03fd842dbb0c9be331e8abebb，Job e655fd78177b4a65a29c92616f95eb3c，child40508。结果SHA256 4ADEB88C463E46506A15EF3743B8E106C7554A7CE7427BE97E291713B95A4034，宿主/子进程一致；网络未开放。ProgramFiles/ClaudeCodeProtection-Gpu-20261027-r1、work/gpu-run-r1-control及私有回执保留。GPU仅搜索System32 nvcuda.dll，实际签名Valid、驱动32.0.16.1047、CUDA Driver版本13030；固定驱动摘要/只读租约，不下载/运行模型、不改设备/驱动设置、不CPU替代。

**历史TLS失败（r6，原样保留）**：request21720be4982541ca9543e0ba8835e12b，代理阶段Job d501d256092e41feb43ec85784d9c64a，child41488。ProgramFiles/ClaudeCodeProtection-Network-20261027-r6与work/network-run-r6-control及私有记录保留。64=RevocationStatusUnknown、16777216=OfflineRevocation，已用本机枚举与[微软定义](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509chainstatusflags)核对。观测确认吊销依赖无法完成；具体CRL/OCSP请求与流量归属尚未抓取，因此“受限系统验证路径”是待核实原因，不是已经证明全机吊销服务停机。此轮未执行第四阶段，最终完整隔离回读成功。不得将前几轮信息较少的FAIL改写为通过。

TLS诊断callback仍要求certificate/chain存在、PolicyErrors0、所有ChainStatus0，吊销检查开启；没有接受任意证书。UDP send完成不等于投递，见[微软sendto契约](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-sendto)。这些条件与当前有限证据明确分开。

## 下一步工程判断与剩余缺口

1. 固定Microsoft资格的吊销路径已修复且四阶段通过，停止重复相同成功矩阵。接续生产运行租约/Watchdog及工具自有代理、控制器崩溃/规则漂移注入，保持FlClash日常组件不动；先明确持久屏障/Job句柄所有权、精确故障信号、恢复/封闭证明，避免把名字消失当零成员。
2. 系统DNS经服务代理、物理出口、真实代理/控制器崩溃、重启仍UNKNOWN。当前TLS修正限固定CA/分区，第三方TLS依赖及受限代理防本地管理转向仍需产品集成；不把自有HTTPS成功当完整工具网络保护。
3. 尽早做自有敏感文件/注册表/进程对象拒绝与授权工作区读写、代表性工具/子进程同时可用的纵向切片；明确管理侧和开发侧权限。GPU已证明当前边界可计算，无须为此撤销边界；随后按需要补PyTorch/代表工作负载。
4. 将十四项环境信息与独立系统安全条件接入同一可信Broker/原子准入/实际会话绑定、时效与失效撤销；接通GUI状态。不存在用旧PASS或GUI绿色代替当前安全授权的捷径。
5. 完成恢复、维护冲突/中断、活动更新、精确卸载与普通用户日常流程；当前固定INACTIVE迁移不当作通用生命周期完成。

## 保留边界

Kaspersky事件未解决；有限Application观察无新告警，完整厂商告警覆盖UNKNOWN。AVP/BFE运行、FlClash/Core20944/14268保持；没有重配Global/系统代理/TUN，没有全机DNS/IPv6/时区更改，没有退休样本/旧聚合自测/AV排除或规避。UAC本人控制。真实Claude规则仍禁用、未启动Claude。最后检查没有本轮产品测试进程存活。

原有origin及Git历史保留，已安全合并用户README的ddb9d9c到49ac5c1，未推送；后续本地提交仍只包含可审查源码/文档，状态、日志、备份、PID、二进制和私人数据不入Git。当前页面整理只移动历史文本，保留[历史快照](STATUS-HISTORY-20261027.md)原字节；历史快照和账本不具有新的运行授权。

## 吊销定位与修正的阶段历史（以下“当前”“待”指当时）

当前实际安装仍ebd633；新SOURCE只扩展固定Microsoft HTTPS诊断：宿主/子进程同样记录每张证书SHA256、逐项链状态及CRL Distribution Points，限8层链/16KiB扩展/8级ASN深度/16地址/每项1024字符，解析错误明确保留。证书地址是不可信观察，未新增任何目标访问/信任库/缓存写入，不放行任意CA地址，不放宽TLS。6项目非生成0错误/警告。fa755f8管理图33输入离线BUILD0，无module initializer；7项ASN解析容量/畸形负向通过，原21项判据与普通命令拒绝通过，无新网络调用。批准26719a907d0a4863b68c6e46d24d4dfb，manifest A31A246BFE3A021B3E443138906119BDAFD8518EBDC0B8CB349D87E0BFFBE2BD；待独立bootstrap及实际观察。

普通用户CAPI2只读查询返回权限拒绝，保留UNKNOWN，不启用日志。通过系统curl读取公开链的进程启动被自动审批审查拒绝（仅blocked by policy、无细分原因），该启动没有执行，不换壳重试。改为已安装Broker原有资格入口内的受审查观察，沿用具体工件构建/资格/人类UAC边界。
26719a固定bootstrap34输入BUILD0/安装更新0；网络request24ea1a4ee5f24e27a2dd69aada09319b实际3。host/child同一4证书链，leaf均无链错误，隔离中间证书64/16777216，实际观察到Microsoft两类CRL及DigiCert GlobalRootG2分发点。没有自动请求这些URL，原严格FAIL保留；ProgramFiles/ClaudeCodeProtection-Network-20261027-r7和私有回执保留，完整隔离/Job/精确豁免清理、AV/BFE/FlClash保持。

下一修正SOURCE见[TLS进程内吊销补充](TLS-REVOCATION-SOURCE.md)：只对固定Microsoft资格目标及精确issuer/地址补充3份通过指定代理取得的CRL，以签名/时间/范围/直接吊销查询+Windows显式memory store CACHE_ONLY原生检查证明状态，不忽略其他TLS错误，不导入全局信任。当前managed非生成6项目0错误/警告（生命周期27源），0a93899管理图34输入BUILD0；无module initializer，6个内存native原语案例全部符合：valid接受、revoked/expired/bad-signature/wrong-issuer/malformed拒绝，6项TLS候选拒绝资格通过。未访问网络或系统信任库；原其他28项资格及普通入口拒绝通过。批准fd4f9f85655342cebc46aab4d19982d8，manifest7EC62DE8F572CBED678616FF2E1F1A815C520463BD172E998A546CA975A7593C；尚待bootstrap/真实TLS，不覆盖原失败或第三方工具TLS资格。

## 当前运行收尾

request ce160d0fddd4471c977c2c36080fceec实际0，四阶段匹配、最终主机正向6项/受保护迟到收据0；21 Job绑定关闭与19豁免精确清理回读完成，6持久角色完整、无存活本轮产品进程。原始路径与详细范围见四阶段网络资格文档。目标保持active，不标完整交付。

## 本轮进行中：运行租约与故障响应

新SOURCE把原代理阶段轮询接入共用ProtectionRuntimeLease，绑定选择摘要/核验版/一次性Job/代理身份/fence与有界期限；停止先回读隔离，再精确Job终止/零成员及关闭回执，记录时序。新增已安装固定qualify-watchdog，用自有长活canary验证1000ms期限到期和本工具收窄隔离漂移，不停止FlClash、不移除守卫、不把两例冒充代理/控制器崩溃。源契约/缺口见[RUNTIME-WATCHDOG-SOURCE](RUNTIME-WATCHDOG-SOURCE.md)。生命周期28源；首次非生成检查因漏传Enable的control参数1错，原报告保留，修正后6项目0错0警告。4fcd3ec管理图35输入BUILD0、无module initializer；40项既有判据/native资格通过，普通qualify-watchdog等入口125拒绝。批准7a235d0d3395432b97b114f8b57fee22，manifest3B2DBEDD06AF0B8230E3527CEC2790159CCEA9A36F8A2E3CF4213BC0CC25D9B3；待独立bootstrap及真实Watchdog。新库不继承fd4f网络或c9 GPU运行证据。
## Watchdog首次运行与成员诊断

5635752独立bootstrap36输入BUILD0，7a235d0d3395432b97b114f8b57fee22/3B2DBEDD06AF0B8230E3527CEC2790159CCEA9A36F8A2E3CF4213BC0CC25D9B3已INACTIVE更新0，operation448bc1a84ff34e048cad02ecad5c3460。首次Watchdog requestddb0939b095643119aa04c2f28a60505退出3：ready HTTPS200，但Job3a7ddf9f7c934b55a6b3ef6ea219bf96由首次恢复前唯一PID13696变为13696+34780，严格唯一目标核对拒绝，未做期限/漂移注入。失败后共用Stop已观察完整隔离先于Job停止、真实零成员/关闭回执，精确豁免/profile清理，AV/BFE/FlClash保持。原ProgramFiles/ClaudeCodeProtection-Watchdog-20261027及私有记录保留；多出成员身份仍UNKNOWN，不能忽略或按名字放行。

当前SOURCE新增仅对同一Job已枚举成员的只读身份诊断，先持有句柄并IsProcessInJob确认归属再读映像/创建时间/令牌，失败逐项保留；无终止权限/外部PID接口，目标唯一检查不放宽。前后Job快照与成员诊断先记录再拒绝，帮助判断下一实际修正。6项目非生成0错0警告；2bc326f管理图35输入BUILD0、40项资格与普通入口拒绝通过，批准814cf4331fcb4fd6a95fee2973b734a6/3EB4F1A88CAC2B3CFB6A561B357E65600745F6B989D8D9A7916A7FA0537FC7BD；待bootstrap/安装及成员诊断运行。新版本不继承旧网络/GPU证据。