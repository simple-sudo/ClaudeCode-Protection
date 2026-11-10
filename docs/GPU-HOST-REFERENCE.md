# 原 owner 的有限宿主 GPU 参考

2026-11-05：SOURCE / BUILD / INTEGRATED(原 GPU 资格源码链及后续源码hold)，
VERIFIED(普通只读/fixture、9bbbb与4588安装及失败Job闭合)，GPU运行仍未通过。
安装、运行与授权以 [CURRENT-STATE](CURRENT-STATE.md) 为准。

## 独立链的固定 CUDA 计算与退出取证

2026-11-09，schema 19 的 `qualify-independent-cuda` 沿用原 Broker、独立
LocalService、私有桌面、零能力 LPAC、Job 和完整网络隔离。固定 `CCU1` 请求只启动
安装内的自研 Broker 载荷。工作进程先核对实际私有桌面、受限身份、工作区环境和标准流，
再复用原 CUDA Driver API 的 1 KiB、256 元素固定 kernel。无外部 PTX、模型、CPU 回退、
设备权限变更或正式 Claude。活动时限为十秒，原 owner 先关准入并在隔离下停止原 Job，
再按原链关闭私有窗口、profile、工作区与临时服务。

原输出的 32 帧进度加最终回执在本机普通 CUDA 实测为 5,185 字节，原 4 KiB 会截断。
新 `CCO2` 回执只对固定 CUDA stdout 提供 8 KiB 上限，stderr 和其他负载仍为 4 KiB。
停止后只接受绑定 Job、PID、顺序且完整的帧。终止时可保留最后进入的调用和首次错误；
缺最终行、截断、非零退出、错误流或回收未确认都不能成为成功。公开摘要不含 GPU 型号。
这记录子进程调用边界，不是内核调用栈、设备身份隔离或任意 CUDA 应用资格。

普通实测完成计算、回读结果和模块、显存、context 清理，16 个调用均返回 0。
`work/session-zero-gpu-capture-20261109-01/schema19-r2-host-compute.log`，SHA-256
`CBD87984D82365681EDC8509E8D400DF4CBF7CDB244B309EE0C165552AB6468E`。
同目录保留 39 项协议用例、普通身份拒绝进入 CUDA 载荷，以及两种输出限额的真实
Windows 管道试验。早期构建缺编译项、测试变量重名和普通测试反射遇到重载歧义的日志均保留。

## 受限 CUDA 首次初始化故障

2026-11-09，本人批准 `BF4574F17772…` 并确认一次 UAC。67 个审查输入及 20 项
回执检查通过。`beab4874` 更新为 `2d759b660b2b4a7aacdc90a9021134ae` 并保持
INACTIVE，安装清单 SHA-256 `97AAB25AEB74A7B3E8898647D86C4DF86534DFBB2E6160F5DBB0203A501D5990`。
恢复前 LPAC 与原映像绑定，实际私有桌面等前置检查已越过，才会写出 CUDA 首帧。
最后完整帧为 `cuInit` 即将进入，无返回，无最终计算回执。退出 `0xC0000005`，
没有超时。该帧位于 P/Invoke 前，不能区分 DLL 加载、导出解析和驱动函数体。
原有界 stderr 为 1,229 字节，只保留长度及摘要。限定时窗的公开 Windows 应用程序
错误事件未返回匹配，故障模块、异常地址及访问类型仍未知。

原 Job 停止前隔离且最终归零，私有窗口、profile、工作区均闭合。普通 SCM 复核
两个原服务均缺席，Broker 和控制器退出 3。`work/session-zero-gpu-capture-20261109-01/receipt.json`
SHA-256 `02031F7B77353787B5024A389E790C9FABAF8F967B52D59CA4881959188E99ED`。
同目录 `windows-fault-events.json` SHA-256 `9F63270CAA1AAB50FA546DF0BDD47C989D7299FE9B36A73D841AC64AAC92AC6E`。
未重试，未改驱动、AV、外网或正式 Claude。正常受限 CUDA、GPU 标识跨来源及 PyTorch 仍未验收。

### 拆分 DLL 加载、导出与调用

原帧从托管 P/Invoke 包装前发出。新增固定 System32 `nvcuda.dll` 加载、`cuInit`
导出解析、地址归属校验和一次 `cuInit(0)` 调用，各阶段分别报告进入与返回，不公开
指针。普通 Windows 的两个独立进程分别在默认设置和仅进程内显式关闭 JIT 库预加载
设置下通过；未测此设置是否改变了实际加载的模块。调用返回均为 0，第二次调用被
同一控制器拒绝。依据：[NVIDIA CUDA 初始化接口](https://docs.nvidia.com/cuda/cuda-driver-api/cuda_driver_api/group__CUDA__INITIALIZE.html)。

`work/session-zero-gpu-capture-20261109-01/ordinary-loader-split/` 的
`product-loader-default.jsonl` SHA-256 `0CB2CEB3D195DCBEC30C8CC8F2F7D8725B701EEEAC11FCB5A607E00CE5A5F479`，
`product-loader-deferred-jit.jsonl` SHA-256 `EC685B5FB6C49C4AEA13A907E05A88A88BEABA3F2257960B51EE24E793E3A0C8`。
SOURCE / BUILD / VERIFIED(普通固定拆分观察)。尚未接入受限载荷，无法推断受限
故障位置或修复。后续通过原 Job 回收后的有界回执带回三个阶段，必要时复用仅原根
进程的 Windows 调试观察以定位异常模块；不改变驱动权限。

### 原受限链的三阶段观察

schema 20 沿用原私有桌面、LocalService 零能力 LPAC、继承管道、Job 与回收。
首个 CUDA 调用内增加六个绑定 PID 与 Job nonce 的阶段帧，分别记录加载、导出解析和
首次调用的进入及返回。正常计算要求首次调用的内外层返回码一致。终止时仅使用上一条
完整且已绑定的帧。原非独立 CUDA 路径保持原帧格式。

普通 NVIDIA 对照完成 1 KiB、256 元素的结果校验和清理，真实回执 6,139 字节。
`work/session-zero-cuda-split-20261109-01/host-split-compute.log` SHA-256
`F18F2619D5755F119F95486AA83919BD9D7352CA3C20B9D1FC0F5F19423A9234`。
普通负向覆盖缺失、跨进程、错序、错误归属、返回码不一致及撕裂回执。
SOURCE / BUILD / INTEGRATED / VERIFIED(普通原生和协议范围)。受限实机结果待测。

### 受限调用阶段的实机结果

本人批准 `E58068E09FCB…` 并确认一次 UAC。`2d759b66` 更新到 `2643fc0e`，
保持 INACTIVE。受限回执 916 字节，最后一个完整阶段为 `Invoke` 已进入，
尚未返回。前序协议只有在 DLL 加载成功并确认导出属于该映像后才允许该帧。
原 Job 先隔离再归零，私有窗口、profile、工作区闭合，普通 SCM 复核原两项服务缺席。
载荷退出 `0xC0000005`，计算仍 FAIL。此回执不含故障指令地址或操作类型。

`work/session-zero-cuda-split-20261109-01/receipt.json` SHA-256
`1530A08F50A9080AF9FFCEDCB124D39DEE5ACB7715AEDBD004A351EE73D7169B`。

### CUDA 访问异常的原根进程观察

schema 21 沿用现有 Windows 调试事件机制。原 Broker 只在恢复后确认根进程仍属于
本次 Job，再附加到该进程。固定载荷在首次驱动调用前最多等待观察器两秒。观察器记录
首个和末次机会的访问异常、读写执行分类、目标地址类别。只有事件映射的文件身份与固定
System32 驱动相符，且指令位于映像范围内时，才给出 `nvcuda.dll` 相对偏移。
它不读取子进程内存，不保留绝对地址，也不代替子进程处理访问异常。
[Windows 异常记录](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)。

普通自有软件触发的异常实测读低地址，进程原退出码 `0xC0000005`，调试退出事件正常继续。
另一普通原生对照用同一观察器核验固定 NVIDIA 驱动映射并完成原 CUDA 计算和清理。
证据 `work/session-zero-cuda-access-trace-20261109-01/host-access-trace-final.log` SHA-256
`98FE6C5BCA9E2C733909AEBDDBF0AE25ACD42994B2D72BEFAD546F6A66956F61`，同目录
`host-access-cuda-final.log` SHA-256 `79E6FE382322EB1E78A2C20BFAF17A996FC2EE6E8CF8FF0C1F8D6323F1B1E136`。
受限原根进程的附加、异常指令和实际回收待测。

### 受限访问异常实机结果

本人批准 `D6A4667E2D14…` 并确认一次 UAC。`2643fc0e` 更新到 `f03ee10c`，
保持 INACTIVE。Broker 成功附加到原根进程并核对 System32 `nvcuda.dll` 映射。
`cuInit` 调用进入后未返回，首次异常为低地址写入，故障指令超出该已核验映像范围。
观察器未收到末次机会访问异常事件，原进程退出 `0xC0000005`，调试退出事件正常继续。
具体故障模块、指令偏移及导致低地址写入的上游条件仍 UNKNOWN。

原 Job 停止前隔离且最终归零，私有窗口、profile、工作区闭合，普通 SCM 复核两项
服务缺席。`work/session-zero-cuda-access-trace-20261109-01/receipt.json` SHA-256
`BC8EA54736072A3570E8B3112E19AAB1D2C299C2A876F3ECF3A7A766074E9BC5`。

### 受限故障的映射模块取证

schema 22 在异常事件期间使用 Windows 已交付的原进程句柄。核对 PID 后只查询
故障指令所在虚拟页的映像类型、分配基址和映射文件名。公开回执只保留有限的
Windows、运行时和 NVIDIA 模块文件名及相对偏移。无法查询或不在名单内的映像
仍记录为 `UNATTRIBUTED`。完整路径、绝对地址和进程内存不进入回执。
[Windows 映射区域查询](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)。

普通自有进程触发的异常正确识别为 `kernelbase.dll` 相对偏移 `793306`。
同构建的普通 NVIDIA 固定计算及退出通过。`work/session-zero-cuda-mapped-fault-20261109-01/host-access-trace-final.log`
SHA-256 `F3BAFCF764A172D6BFC2BA2134E6EECE97B1DE8B7D332EF7E43F0B644373646A`。
受限实机的真实模块和指令偏移尚未观察。

### 映射模块实机结果

本人批准 `09FE66A3E780…` 并确认一次 UAC。`f03ee10c` 更新为 `363bf089`
并保持 INACTIVE。受限 `cuInit` 中首次低地址写入定位为 `nvcuda64.dll+0x3A062E`，
进程退出 `0xC0000005`。调试退出继续，原 Job、工作区、profile、窗口和服务均回收。
`work/session-zero-cuda-mapped-fault-20261109-01/receipt.json` SHA-256
`0DCB2859F6967A4657046D9AE45346B6B75E71D74CC3D4EE2A4D72FC26407A22`。

本机唯一发现的同名 NVIDIA DriverStore 文件版本为 `32.0.16.1047`，与已配置
显示驱动版本一致，SHA-256 `8AE9D817499BF3BF7DF7A91A3F57574335DCDE42AFF130F46C86C68F38B27521`。
本次受限映射只记录模块文件名和 RVA，未对映射文件取同一摘要。候选本机文件
对应指令先从 `[rsi+0x20]` 取指针，再向 `[rax+0x293c]` 写零。低地址与
空基址假设吻合，实际访问地址是否正好为 `0x293c` 仍未知。反汇编保存在同目录
`driver-fault-function.log`，SHA-256 `7D2C8AD02CE340E4A2D94D7F6092927E8A4FD8955B847440DB0E0FD3D2316600`。

### WDDM 适配器对照

schema 23 让原受限根进程在 CUDA 前调用固定的 Windows WDDM 适配器枚举，并关闭
取得的适配器句柄。原 Broker 采集可信对照，等原 Job 关闭后校验 Job、PID 和进程
创建时间，再封存双方原值。外层只得到原生状态、计数、交集和关闭结果。适配器 LUID
用于本次跨 API 对照，其生命周期有限。观察器对同一模块及指令仅增加一项布尔比较，
确认写入目标是否恰为指令位移。
[Windows 适配器枚举](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d3dkmthk/nf-d3dkmthk-d3dkmtenumadapters2)。

普通实机四项原值与同次 CUDA 原值交叉比对，唯一匹配一项，所有句柄已关闭。
错误 PID 被拒绝。原始真实值保存在本机限定目录。摘要
`work/session-zero-cuda-wddm-reference-20261109-01/host-wddm-final.log` SHA-256
`923AB6F2BA6E23E6BFB1837CE6045ECF5C922075CEF765B3B511226C116272C5`。
受限 WDDM 对照及对 CUDA 故障的解释尚待实测。

## 2026-11-06 610b正常真实参考已验证

经本人批准73AC9CC7…，安装/原daily/原资格owner/指定新记录reader全终态0。现装
610b/INACTIVE，15公开资产核验一致；真实原普通用户/session的primary medium limited
非管理员Token，由父属性在原Job内suspended创建，原seal/句柄/身份门通过。新管道
LABEL-only设定回读及跨权限peer/nonce确认完成；实际新Token与原创建记录一致，
管理owner前后Token事实相同，没有显式Token复制/分配/调整或权限启用。详尽原值已由可信研发核对，保留
在新受控目录，不进入公开库或Claude工作区。

RTX4060 Laptop / driver13030完成固定1KiB/256计算，16调用0、32帧、正确结果哈希，
原模块/显存/context清理成功。原runtime会话时钟447ms观察quarantine后关闭原Job，
Stop与原耐久零成员记录同快照，无失败。447ms不表示纯GPU时长；context总显存、
驱动缓存、硬件挂起、异常终止/对端丢失故障均未实测，不能扩大本次证据范围。

CAPABILITY_DELIVERED(固定可信普通宿主GPU参考与正常原Job闭合)，其用户入口为当前
安装daily的`gpu-host-reference`，本人UAC，非正式Claude准入。原无caller资格、聚合
GPU系统hold仍闭锁；该参考不获得LPAC或隐私证据。后续应在原owner复用此创建方，
开展同身份受限CUDA及真实GPU标识路径对抗，而非直接给Claude普通GPU Token。
独立核验F53CAE27…及详情hash/路径见[账本](STATUS.md#2026-11-06-610b真实普通父身份gpu参考正常闭合)。

## 2026-11-06 初始SACL与仅读标签的实际差异

fa8d固定原生资格安装成功，但原daily/owner终态125、0x80070522/1314，没有请求编号/
具体阶段或Job回执，计算/创建未确认、Job闭合UNKNOWN。后读条件未满足，不读取私有
历史或推断清理。普通新管道实际对照：DACL-only成功，初始SACL含medium标签失败，
与错误吻合但不能唯一追认提升原失败位置。

修复仅对本次新建报告管道调用SetSecurityInfo的LABEL_SECURITY_INFORMATION，句柄仅
另请求WRITE_OWNER；不设置整份SACL或启用SeSecurity。GetSecurityInfo仅读标签，
回读与固定medium/no-write-up ACL逐字节一致，同时原owner/DACL必须不变；新管道
不合格则关闭原句柄并拒绝，发生在Job/子进程创建前。普通新建自有管道已经实测成功。
提升身份跨权限尚未实测，不据普通结果推导通过。原APP/RAP拒绝、实际peer/nonce和
Job/身份/停止门均保留。

新schema2支持摘要附加最多32条、仅白名单阶段码，与uint32错误码长度一致；未知阶段
固定OTHER_STAGE_OR_NOT_REPORTED。新管道创建/设标签/读标签异常在原捕获点附加有限
阶段，未有RequestId也能返回，避免只报错误码。原值继续留可信侧，不透传任意文本。
610b候选SOURCE/BUILD，78普通策略及原IPC回归通过，普通新管道/标签VERIFIED；未安装。
机制依据：[LABEL只需WRITE_OWNER，SACL需ACCESS_SYSTEM_SECURITY](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information)、
[SetSecurityInfo的标签与SACL区别](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo)。

## 2026-11-06 当前安装普通调用方的父进程属性适配

新增 `GpuReferenceCaller`、`GpuCallerCreation`、`GpuReferenceChannel`，接入原安装与
普通 daily 的固定 `gpu-host-reference` 支持命令。SOURCE / BUILD / INTEGRATED(原
ordinary daily→显式UAC→当前安装owner→原Job/runtime)，尚未安装或原生创建/GPU实测。
旧无调用方的 `qualify-host-gpu-reference` 和整体 GPU 资格 hold 保持关闭。

普通 daily 先持有并核验安装的兄弟 Broker 文件，建立自己的独占本机管道，再请求本人
UAC；持有 Windows 返回的 Broker 原句柄，双向核对实际管道 PID。提升 owner 在原
WithCurrentInstallation 内，只打开该已连接的当前安装 daily，权限仅 SYNCHRONIZE /
QUERY_LIMITED_INFORMATION / CREATE_PROCESS（0x00101080）；核验映像、原创建时间、
用户SID、Windows session、primary/medium/limited/非提升/非AC及完整权限摘要。
没有 Explorer 查找、外部 Token、任意父PID/目标/命令、令牌复制或权限启用。

创建由提升 owner 执行，父属性只引用持有的真实普通 daily，内核据此继承普通 Token；
原Job通过JOB_LIST在创建时绑定，固定映像/命令/环境，suspended、无窗口、BA/SYSTEM
进程/线程seal。inherit=false且无HANDLE_LIST，不继承原owner或普通父的控制/标准流
句柄；不用CreateProcessAsUser。真正创建的Token必须精确匹配普通调用方已读事实，
提升owner当前Token前后也必须相同。原句柄、单Job成员、映像、seal及全quarantine
核验完毕才resume。普通调用方的身份、原时间/句柄/映像/管道在runtime健康检查继续核验。
若调用方在创建前退出，先登记一次原Job准入，失败仍可闭合原Job；不认领未知树。

子进程仅连接原owner的固定独占报告管道，双向核验PID、nonce和有界确认帧后才调用CUDA。
新管道显式拒绝全部AppContainer和受限AppContainer；提升报告端点仅给该用户ACL，创建
时设medium mandatory label供普通子进程写入，不改已有对象权限。原协议仍为16API /
32帧/1KiB/256元素，原30秒runtime/先quarantine再关原Job保持。owner另从本次原
intent/admission/completion复核耐久闭合；成功必须同时满足计算、进度和停止门。

普通界面收到的HostGpuReferenceReply最多4096字节，仅有固定状态/数值码/请求引用/
子PID及闭合摘要。严格字段/重复字段/nonce/权限false/结果一致性；不能把摘要升级为
启动权、隐私或受保护GPU。真实Token/GPU/调用及停止报告留protected state。普通daily
观察超时或收到坏回复后仍持有原Broker句柄等待终态，不强停、不重启、不假定清理。

75项普通策略检查包含原角色/停止绑定、父身份/最小句柄权限和摘要伪造拒绝；普通1001
实际独占管道fixture7项通过（同一进程客户端/服务端，不是跨权限验证），核验真实
peer、APP/RAP拒绝ACL、帧内容及普通身份不能创建提升报告端点。该fixture无UAC/
父属性/Token调整/Job/GPU。8个payload/测试项目及Bootstrap构建0/0，35前驱、28进度
及40失败摘要fixture通过，6src非生成0/0。候选8ca1…未安装，实际父属性Token继承、
新管道跨权限/mandatory label、Job闭合/CUDA与故障仍NOT_RUN；不存在新GPU交付声明。

Windows机制依据：[父进程属性与JOB_LIST](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)、
[句柄继承](https://learn.microsoft.com/en-us/windows/win32/sysinfo/handle-inheritance)、
[mandatory integrity](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)。

最终执行前scope已改为 `TRUSTED_ORDINARY_HOST_GPU_REFERENCE_NOT_LPAC`，删除旧LINKED
命名，避免误写身份来源；该字段本身始终不是Token事实或准入证据。未执行8ca1包保留，
最终fa8d候选及单次资格准备见candidate-final目录，尚未安装/原生验证。

## 关联 Token 原型的历史结果

4588实际资格仍拒绝HostGpuNormalTokenRoleMismatch，未得到创建身份/CUDA帧，新原Job
已闭合/零成员。普通自身linked读取实际是Type2/Identification1的full Token，只有
查询/关闭；这是limited→full方向，不能追认失败owner实际拒绝的字段。
[ZwDuplicateToken](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicatetoken)
规定转primary需要Impersonation或Delegation。当前路线不放宽primary要求或增加TCB，
源码在新Job前hold，尚未安装；停止继续生成同路线候选。原普通GUI/Broker创建方必须
绑定真实普通身份和持有句柄，通过原owner的固定目标/原Job/suspended/seal验证后运行；
该时刻适配仍DESIGN；后续源码见上，没有Explorer脱离Job的启动或通用Token/PID/命令入口。

9bbbb实际固定资格安装成功，但宿主参考失败，原新Job闭合/零成员已核验；未取得
创建身份、CUDA或owner返回属性证据。普通查询发现TokenLinkedToken的零buffer请求
实际返回ERROR_BAD_LENGTH(24)、长度8；旧通用读取器要求122，会提前拒绝。现已用
固定8字节结构直接读取并精确接管成功返回的句柄，不扩大Token访问权或接受任意长度。
SOURCE/BUILD及普通当前Token Capture通过；该修正随后在4588提升资格中仍被角色门拒绝，见上。原泛化
失败阶段不能唯一回溯到具体分支，新代码区分source/normal/link/created等阶段。

原 `GpuQualification.Run` 在管理 owner 线程同步执行 `HOST_CONTROL` CUDA；其后的受限子进程
限时不能约束这段宿主调用。新实现把固定宿主参考交给同一安装 owner 持有的专用普通子进程，
全部 CUDA 留在子进程；这是原资格链的宿主正控制，不是 Claude 执行器。

`GpuHostToken` 只从当前提升 owner 自身查询 Windows 关联普通 Token，复制为 primary，
请求 QUERY / DUPLICATE / ASSIGN_PRIMARY，无 ADJUST、凭据、外部 Token 或管理员回退。
要求同一用户 SID 和 Windows session、medium、非提升、非 AppContainer、无 restricted SID/UIAccess。
UAC full/limited 可以属于不同的关联 LSA 登录会话，不能要求它们的 AuthenticationId 相同；
普通 Token 的完整事实、权限摘要及其 AuthenticationId 必须在复制和实际创建后保持一致。
调用 CreateProcessAsUser 前后核对 owner 当前有效身份及原始权限字节；Windows API 可能
临时启用 owner 已有的必要权限，返回后属性漂移即拒绝，不修复或重试。

`AtomicChild.HostGpuReferenceChild` 是区别于 LPAC 的类型：原 `OwnedKernelJob` 先登记一次
原子准入，固定已安装 Broker 映像、命令、环境、匿名输出句柄与 JOB_LIST，在 suspended 创建时
归入原 Job；进程/线程采用原有 BA/SYSTEM seal。原句柄核验 Token、映像、单成员 Job、seal，
并绑定 PID/nonce 后才 resume。既有安装、无 pending 恢复、历史 Job 闭合和全部注册 fence
处于 quarantine 的门禁仍适用；不能把普通参考报告当作 LPAC、网络隔离或隐私通过。

新安装命令 `qualify-host-gpu-reference` 无调用者目标或参数，只执行固定 1KiB / 256 元素
CUDA 计算及原 16 API / 32 帧协议。普通子命令只能做相同固定计算，不能访问管理功能。
管理 owner 使用原 `ProtectionRuntimeLease` 的 30 秒有效期，终止只处置原 Job；先确认/恢复
自有 fence 的 quarantine，再闭合准入并核验零成员。失败保留原始状态；没有 PID kill、
强停提升 owner、额外恢复、故障注入或重试。驱动或内核操作自身仍可能阻塞，因此外层
观察超时只报告 UNKNOWN 并保留原句柄，不能承诺硬件挂起时的绝对墙钟返回期限。

原 `qualify-gpu` 的系统资格 hold 保持关闭。源码中它先要求这份宿主参考完整闭合，再进入原
LPAC 阶段；本次固定资格只考虑宿主参考，不运行 LPAC、AFD、网络或官方 Claude。

53 项普通策略断言覆盖 full/limited/created 角色、关联登录语义、权限漂移、普通调用者拒绝、
报告与原停止绑定，以及 host/LPAC 证据不能交叉授信。另复用 28 项协议/真实普通管道 fixture、
21 项前驱选择和 40 项失败摘要检查。它们不证明 Windows 实际创建成功或真实故障恢复。
首个关联Token候选 `9bbbb71f91ee4423bbb53fb96bb64479` 的完整构建和固定清单保留于
`work/gpu-host-owner-d1f927e-20261105/candidate-auth-model`；之前错误要求同一 LSA 登录标识的
未执行候选 `9b8d062318ee49f98993830be68a2f03` 原字节保留，已被替代，不准据其运行。

关联 Token 的 Windows 定义见 [TOKEN_LINKED_TOKEN](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_linked_token)；
关联登录会话语义见 [Microsoft UAC 说明](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command)；
创建 API 的权限行为见 [CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)。
