# 当前开发状态

## 2026-10-27 受控网关正常结束与故障排空修复（本轮）

接续8611fd2，工作区干净。发现SessionProxy任一方向正常EOF会取消两个方向，可能截断仍在返回的数据；
其余方向的并发错误也可能被当作取消清理而吞掉。修复直接进入ProtectedSession使用的同一SessionProxy：
正常EOF仅对对应目的Socket发送FIN，另一方向继续传输；错误/超时/撤销取消并观察两个复制任务后才释放端点。
原每方向8MiB、会话64MiB、连接20秒/会话60秒上限保持，字节在写出前计入预算；不存在直连回退。
固定会话canary改为精确HTTP/1.1 HEAD，避免GET只取头后丢弃未读正文自行中止隧道；未改目标或证书验证。
网络策略摘要包含新传输语义，旧环境预期/屏障不会自动继承新策略。

SOURCE / INTEGRATED：六产品项目语义检查0错误/0警告（Lifecycle35源），11源纯托管测试语义无诊断。
原始报告为outputs/session-duplex-source-types-final.json、session-duplex-policy-source-types-final.json。
新增内存双向端点用例覆盖两个方向延迟回复、后发错误、写失败、方向/会话预算及截止撤销、排空；
测试调用实际SessionTunnel复制器，不开端口/文件或调用native。
随后7543cb1的Broker/Lifecycle（42固定输入）与11源纯测试分别离线还原/编译成功，均0错误/0警告；
纯测试实际退出0，含上述双向延迟响应、错误/预算/截止的排空验证。
测试程序集SHA256 6274B63D189D25D62C3217517EAB0D610F27739243044B42687BD4363A195C19，
保留work/session-duplex-broker-7543cb1-build、session-duplex-policy-7543cb1-build及固定控制脚本/结果。
历史迁移读取另补一个更新兼容修正：完成的旧网关策略记录不再要求等于当前策略摘要，仍核对完整前后像、
固定端口/对象键/安装归属；实际迁移/恢复及启动仍要求当前策略，不从历史回执签发许可。
这避免本次传输策略摘要升级后把已完成的维护历史误判为不合法；该后续源码语义检查六项目0错误/0警告，
outputs/session-duplex-history-source-types.json。
最终源码c9cd81a的Broker/Lifecycle已再次独立离线构建通过，0错误/0警告，
work/session-duplex-final-c9cd81a-build保留42输入、导入、产物摘要及前后观察；未执行/安装产品。
此前7543cb1纯测试的12个输入SHA256逐一与c9cd81a核对一致，复用的是相同测试输入的执行结果，
不是新会话或系统资格；policy-duplex-input-reuse.json保留逐范围说明。历史迁移读取修正仍无实机执行证据。
Socket半关闭与真实TLS/HEAD互操作均NOT_RUN，内存排空成功不能冒充内核/网络验收。
有限前后观察AVP/BFE运行、FlClash/Core PID保持，Application新增AV事件0，完整覆盖UNKNOWN。
本轮未恢复WFP/Job/Watchdog实验、故障注入或真实Claude，未改AV、FlClash或系统网络。
完整会话的可信证据、资源/工具/GPU授权和系统资格缺口未被此修复补位，完整产品仍非DELIVERABLE。

## 2026-10-27 用户重新授权：本机验证与封闭网络迁移

用户已明确允许有界构建/系统验证继续，并接受可能再次蓝屏；历史停止不是永久禁令。
不自动重现、不绕过AV/UAC、不改日常FlClash/全机网络，先固定证据与具体工件范围。
真实Claude仍延期，十四项与系统门禁不能从这份授权推导PASS。

- BUILD：当前源码提交48f9293c的9源纯托管测试、Broker/Lifecycle（35源+2项目+4资源）分别离线还原/编译成功，
  0错误/0警告。固定SDK8.0.422/ref8.0.28、空包源、导入审计、独立输出与前后快照。
  前序b204c979的两次独立构建同样保留，不覆盖其回执。
- VERIFIED（有限）：48f9293c纯策略用例实际退出0，包含实际消费的迁移阶段决策，
  程序集SHA256 0986B48CB1C2F196124E1CF44835538691F1DC3AF3FD011B943155C5E0B2152D。
  新工件migrate-session-network/session-synthetic/admission-child均退出125，三个进程确认退出；
  前两者明确返回SYSTEM_ARTIFACT_NOT_QUALIFIED，后者经公开库保护拒绝；没有系统操作。
  前序b204c979 Broker `inspect-runtime` 退出0，x64结构布局符合声明。
  `inspect-wfp` 实际退出2，ReadBuiltinConnectLayer错误5（访问被拒绝），保留原FAIL/UNKNOWN，不改权限。
  两个普通用户诊断均退出；未安装、未创建Job/进程隔离、未变更WFP规则。
- SOURCE / INTEGRATED：安装Broker新增 `migrate-session-network`，只接受固定7890旧策略与当前17891策略。
  所有历史单次准入关闭、回环豁免关闭后，先完整封闭，再一事务替换同安装SID/同7个对象键；
  保留新旧完整字节和摘要，内核独立回读后比较旧摘要原子选择新计划。中断只由同入口按新旧标记恢复；
  未完成迁移阻断正常启动/安装生命周期。不会杀任务来使迁移通过，也不授予启动许可。
  六项目语义分析0错误/0警告：`outputs/session-network-migration-final-source-types.json`（Lifecycle34源）；
  同一实际迁移阶段决策进入PolicySmoke的事务前/提交后/选择后及反向/未知/未封闭拒绝用例，九源语义检查无诊断。
  `outputs/session-network-migration-policy-source-types.json`保留源码证据；执行结果另见上项。
  此迁移实现已编译，但尚未安装/执行；纯决策通过不证明WFP事务/崩溃恢复通过。
- 事故诊断：核验了既有10:34Z日志。`!analyze` 未找到扩展导出，内核符号缺失；退出0不代表分析成功。
  显式扩展+微软公开符号的修正分析在启动前被自动审批拒绝，仅返回blocked by policy；不换入口绕过。
  尚未取得可归因的故障栈，无新蓝屏/故障注入；详见事故记录。

复现资料均保留在忽略的 `work/session-validation-reopened-control`、
`work/session-validation-policy-b204c97-build`、`work/session-validation-broker-b204c97-build`；
当前源码构建分别位于 `work/session-gateway-migration-48f9293-build`、
`work/session-migration-policy-48f9293-build`，固定控制脚本/输入/导入/工件摘要/测试及拒绝结果均保留。
原失败和受保护分析日志不覆盖。有限前后观察AVP/BFE运行、FlClash28088/Core16112未变、
Application新AV事件0，完整AV覆盖UNKNOWN，Kaspersky事件未结案。

正式许可仍不能签发：当前工件的安装/系统资格、功能性网络/DNS可信证据、宿主资源隔离与工具/GPU授权仍缺。
源码入口的限制现明确为当前工件未获资格，不把用户已重开的授权继续解释为永久蓝屏禁令。
完整产品仍非DELIVERABLE；没有推送、AV/系统网络/FlClash改动或真实Claude执行。
下文是各轮原窗口记录，其“停止/未编译”只适用于当时。

## 2026-10-27 挂起准备与实时环境证据接线：当前结论

上一轮progress为 `04e7419`。本轮修正“需要根Job/SID证据才能创建根对象”的准备依赖：
同一所有者以一次Preparation只创建固定挂起程序、完整隔离和原租约监督；实际Job/映像/token核对后，
仍须全14项和独立安全条件满足，才签发另一个不可替代的首次执行许可。失败走原封闭/零成员/清理。
新建进程/主线程对象在创建时提供管理侧DACL并回读，避免仅凭默认ACL假定外部不能提前恢复。

环境预期的检查/配置进入当前安装Broker管理接口，固定私有状态、实际人类Owner SID、旧摘要比较与前后回执；
没有PASS、豁免或启动参数，不更改OS设置。时区/用户与系统Locale、分阶段路由及启动监督已接入当前采集源码，
环境观察10秒刷新、创建/恢复前强制刷新，策略摘要改变即失效；没有配置或读失败仍拒绝。
本轮没有运行配置、采集器、进程创建、对象ACL或网络代码；事故停止与Claude延期不变。

SOURCE：六产品项目0错误/0警告（生命周期33输入）；八个测试源输入仅语义核对。
报告 `outputs/session-preparation-delivery-source-types.json`、
`outputs/session-preparation-maintenance-policy-source-types.json` 不入Git。新增用例没有执行结果。
BUILD/VERIFIED没有本轮新增，完整产品非DELIVERABLE。当前系统安全与其余环境采集、受审查控制探针、
旧屏障迁移、宿主资源/工作区/工具/GPU授权及实机集中验收仍缺，不能签发正向正式会话许可。
详细调用链与边界见[主链说明](PROTECTED-SESSION-CHAIN.md)。

## 上一轮主链接线记录（历史窗口）

上一轮属于progress，提交 `b18d5cc`；本轮继续同一分支，不改变完整产品目标。
SOURCE / INTEGRATED：正式Broker launch和受阻断的session-synthetic进入同一ProtectedSession所有者；
一次性创建/首次恢复许可、安装/策略/SessionId/Job/SID/fence/固定资源绑定，复用原AtomicChild、
PersistentFence、ProtectionRuntimeLease和成员核验，连接到撤销、封闭、零成员与资源清理。

实际SessionProxy转发源码已接线：仅固定自有HTTPS目标，受保护侧新WFP允许17891而非原始7890，
每会话认证+精确Job/token/监听核验，经固定DoH解析并审查A/CNAME回答后发送字面IP上游CONNECT；
无宿主DNS解析或直连回退。详情与实际调用接点见[主链说明](PROTECTED-SESSION-CHAIN.md)。

**正向会话仍不能运行**：14项可信采集当前均UNKNOWN，独立宿主资源/通道实机/资源授权也UNKNOWN；
旧7890 fence需要封闭迁移，当前拒绝复用。真实Claude继续DEFERRED_BY_USER，系统测试停止有效。
公开库入口的系统资格、安装和admission-child也补上同一事故阻断；未运行这些代码。

验证仅SOURCE：六项目非生成语义检查0错误/0警告；共享转发解析负向用例未执行。
原始报告为 `outputs/session-chain-closure-source-types.json` 和
`outputs/session-chain-final-policy-source-types.json`（不入Git；后者仅测试源码分析）。
BUILD / VERIFIED无本轮新增；新代码未安装，完整产品非DELIVERABLE，未改AV/日常网络/FlClash。
后续缺口是实际可信采集/环境策略、当前工件安全资格、旧屏障迁移、宿主敏感资源及授权工具/GPU，
以及在事故调查和具体安全条件满足后的集中实机验收。不能把源码接线或单个合成负载当全产品完成。

## 上一轮PR接收记录（历史窗口）

**本轮完成源码接收和限定修复，完整产品仍非 DELIVERABLE；系统测试继续 BLOCKED。**
用户本次第五节明确保留 0x1E 后的系统测试阻断，替代历史重新授权描述。本轮未构建、安装、
运行新产品或离线调试器，未做 WFP/Job/Watchdog 测试、故障注入、UAC 或网络/AV 修改。

当前分支 `codex/integrate-privacy-admission-20261027`，接续起点 `587ef08`、工作区干净。
重新 fetch 后 origin/main=`8e5b4ee`；两个 PR 仍 draft/open/unmerged，头分别
`eb2300e` / `950836b`。原始开发提交及本地修复均在当前分支；未推送、未修改远端 README/origin。

SOURCE / 调用链已接入：本地整合 PR #1 的固定 canary 成员检查并持有进程对象直至第二次快照/判定，
拒绝重复 PID、主进程创建时间不符；整合 PR #2 的日常十四项报告及诊断目标限制，补工程项目引用、
GUI preflight 调用、严格时间与目的地拒绝。Broker 新 `launch` 仅核验安装并返回十四项当前可信采集缺失，
不接收日常报告/旧 PASS、创建进程或转用 qualification；这是启动拒绝路径，尚不是完整可用许可链。
原始 FlClash 仍仅资格通道，目的地候选策略未构成正式转发边界。

本轮后续修复已进入既有 GUI / Broker / Bootstrap 源码入口：

- GUI 显示十四项中文状态和处理建议，报告缺失/重复/格式异常/伪造授权时不显示正向结果；
  两分钟时效独立核对，每15秒仅重绘失效状态，不反复运行检查；FAIL 保留，原始报告仍可保存。
- 五个 Broker 系统 `qualify-*` 入口在权限/安装读取和原生调用前返回125；Bootstrap 安装/更新同样拒绝。
  只读诊断和精确 quarantine 恢复分开保留。本轮未执行它们，已有安装包不会自动获得源码新限制。

| 证据等级 | 本次实际状态 |
| --- | --- |
| SOURCE | 六产品项目非生成语义检查0错误/0警告；PolicySmoke七个源输入同样仅语义检查，无诊断 |
| BUILD | 实时核实原PR #1 Windows Broker/Lifecycle编译、原PR #2 Windows daily编译成功；本机整合后未构建 |
| INTEGRATED | 成员核验进入原Watchdog资格链；十四项进入daily/GUI；Broker正式启动仅拒绝；新入口阻断是SOURCE接入 |
| VERIFIED | 原PR #2纯托管CI成功限其提交；新增GUI负向用例未执行；没有本次新实机功能验收 |
| DELIVERABLE | 完整保护产品未完成，当前补丁也未安装；不能当作可用保护版本 |
| DEFERRED | 真实Claude登录、推理与正式会话DEFERRED_BY_USER |
| BLOCKED | 蓝屏归因/故障栈仍UNKNOWN；整合工件的本机构建、安装、系统运行及故障注入保持停止 |

原始报告（不入Git）：`outputs/pr-intake-closure-source-types.json`、
`outputs/pr-intake-test-source-analysis-final.json`；均未Emit/MSBuild/restore或加载/执行产品程序集。
只读进程检查未见四个产品名称的进程，AVP21.26/BFE运行；这是有限快照，不是完整AV或主机安全证明。

下一条网络生产缺口是可信转发实际执行目的地限制、可信解析与字面IP连接，并拒绝受保护侧绕过到原始7890；
还缺代理中继访问宿主管理接口、DNS服务代发、工具子进程与敏感资源隔离的实际拒绝证据。
十四项仍缺Broker当前可信采集、明确用户策略、安装/策略/目标/工作区/工具/设备及会话绑定、
创建与首次恢复前实时复核、证据失效及运行撤销。当前并无完整正向许可签发链，不能以报告/UI修复代替。

完整差异与接收决定见 [本轮整合记录](INTEGRATION-20261027.md)。本次无需例行审批；
恢复系统测试须先取得事故调查和具体工件的安全条件，不从CI推导授权。

## 以下为此前安装、运行及接续窗口的历史记录

下文“当前”“下一步”“目标恢复”等均指各自当时，不覆盖上方本次结论。
前次测试重新授权曾存在，已由本次保留系统测试阻断的明确要求收紧；不删除其历史。

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
## 蓝屏只读定位接续（08:12Z）

原转储SHA已取得：C38F6F02C3CEEBC6FD2A9628C76E2D671D0C8D855E6AAD5997291989D3A1FC92，7030648字节；WER确认BlueScreen/0x1E参数，无驱动栈。已有成员诊断确认额外conhost同Job/同AppContainer，不证明它导致蓝屏，未放宽准入或恢复测试。

WER目录读取辅助进程曾异常增长；首次停止UAC取消后，经用户明确允许重显UAC，仅精确终止PID18080/创建时刻匹配的helper，停止回执08:06:15.580Z，当前不存在。单个WER的有界读取替代路径已退出0；原失败/取消/资源异常保留，原因未猜测。

微软官方WinDbg工具已下载/签名核验，未系统安装/执行；离线分析调试器的启动被自动审批拒绝（仅blocked by policy），没有换入口绕过。故障模块、内核栈及测试因果仍UNKNOWN，产品构建/安装/运行/故障注入保持BLOCKED。完整事件/工具来源/证据及手动离线诊断步骤见INCIDENT-20261027-SYSTEM-CRASH.md。无产品测试进程，AV/BFE/日常FlClash保持；目标未完成。
