# 原 owner 的有限宿主 GPU 参考

2026-11-05：SOURCE / BUILD / INTEGRATED(原 GPU 资格源码链及后续源码hold)，
VERIFIED(普通只读/fixture、9bbbb与4588安装及失败Job闭合)，GPU运行仍未通过。
安装、运行与授权以 [CURRENT-STATE](CURRENT-STATE.md) 为准。

4588实际资格仍拒绝HostGpuNormalTokenRoleMismatch，未得到创建身份/CUDA帧，新原Job
已闭合/零成员。普通自身linked读取实际是Type2/Identification1的full Token，只有
查询/关闭；这是limited→full方向，不能追认失败owner实际拒绝的字段。
[ZwDuplicateToken](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicatetoken)
规定转primary需要Impersonation或Delegation。当前路线不放宽primary要求或增加TCB，
源码在新Job前hold，尚未安装；停止继续生成同路线候选。原普通GUI/Broker创建方必须
绑定真实普通身份和持有句柄，通过原owner的固定目标/原Job/suspended/seal验证后运行；
此适配仍DESIGN，没有Explorer脱离Job的启动或通用Token/PID/命令入口。

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
