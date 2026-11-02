# 受保护Job成员控制源码

> 文档效力（2026-11-02）：Job/进程归属专题。按原版本和场景解释实测，不把树状名称或进程缺席作为权限/闭合证明。自我保护覆盖派生工具与控制面，仍须实际对象权限及鉴权依据。
> 最新状态/授权只见[CURRENT-STATE](CURRENT-STATE.md)，正式目标与术语见[SECURITY-REQUIREMENTS](SECURITY-REQUIREMENTS.md)。以下旧状态与操作许可不自动延续。

2026-10-26接续：固定quarantine入口已在SOURCE消费本owner，非完整runtime lease。停止集合现保留各Job失败并继续其余已核验对象，最终观察schema 2必须核对预期数量/缺失/失败/零成员；全局锁或清单丢失仍停止。实际构建及故障验收尚未进行。下文原始实现阶段的缺口描述保留为历史，当前状态见STATUS。

日期：2026-10-26（America/New_York）。状态：SOURCE_IMPLEMENTED_NOT_COMPILED。新增KernelJobSeal.cs、PrivateJobNamespace.cs、OwnedJobs.cs；没有调用Job/namespace API、启动/停止进程、编译或安装。

## 实际实现范围

新增具体内核对象实现：创建受保护空Job，按私有计划打开既有Job，通过实际句柄查询限制/活跃数/成员列表，按同一句柄TerminateJobObject并最多5秒轮询零成员。RegisteredJobSet先核验并持有全部登记Job再逐个停止，之后重新读取各Job。

它没有实现ILifecycleRuntimeLease。Job成员控制只是完整进程所有权的一部分；当前尚无受保护进程创建、原子Job绑定、低权限用户token/终端适配、启动准入屏障、WFP资源owner或可信broker入口。空Job查询为零不是父/子进程控制验收，集合为空也不是安装已无所属进程。

## 来源、命名与内核安全

CreateEmpty只接受已持有的管理员状态与VerifiedVersion，核对当前指针/清单匹配且无未处置生命周期操作。先保存私有job-intent，再创建内核对象。intent的schema 2固定绑定安装ID、随机JobId、release/清单摘要、ATOMIC_JOB_LIST_REQUIRED和JOB_MEMBERS_ONLY；名称由代码重建，不接受JSON/CLI提供PID、SID、对象名或目标路径。schema 1的早期全局命名草稿不被接管；草稿从未编译或执行。

初稿采用Global名字。源码审查发现Create/Open返回的句柄自身会改变引用计数，随后关闭可能触发既有Job的KILL_ON_JOB_CLOSE；因此不能靠“先打开、核对失败再关闭”保证对外来对象没有影响。当前改用每Job私有命名空间，boundary要求Administrators SID，并明确设置只允许SYSTEM/Administrators的namespace DACL；边界本身不能代替打开权限。没有Global或Local命名回退。普通/过滤令牌的占位、创建和打开拒绝仍须实际负向验收。

Job本身使用非继承句柄及受保护owner/DACL，SYSTEM/Administrators获得READ_CONTROL、ASSIGN、SET、QUERY、TERMINATE的固定掩码0x2000F；归属标记仅READ_CONTROL。打开后按SE_KERNEL_OBJECT=6读取安全描述符，不能误用文件对象类型。只接受两条固定主体ACE和一条无继承/无回调的角色27创建标记；不同owner、额外/扩大权限、重复标记或未知ACE拒绝。标记是应用元数据，不是Windows服务身份、AppContainer身份或WFP身份；不防恶意管理员/内核或受控bootstrap。

恢复仅请求READ_CONTROL/QUERY/TERMINATE，不取得ASSIGN/SET，不按PID杀进程。存在创建碰撞记录则拒绝接管；不会调整外来对象的ACL或限制。创建失败时按Job→namespace顺序释放取得的句柄，未返回可用对象前没有进程启动能力。

## 观察、停止与失败

创建时设置且回读限制恰为KILL_ON_JOB_CLOSE，不启用breakaway。成员列表容量从32逐步扩大到4096；ERROR_MORE_DATA、assigned/returned数量差异或超过上限不会截断成空列表。查询错误保持错误；PID只用作观察记录，不作为停止依据，也不读取命令参数/认证。

观察保存前后ActiveProcesses、完整成员ID列表、限制flags和时间。停止前保存BEFORE_TERMINATE，核对所有权后TerminateJobObject，实际回读前后活跃数及成员列表都为零才记录JOB_MEMBERS_ZERO_OBSERVED。限制漂移不授予健康资格；只要内核所有权仍可信，可以停止同一Job中的成员。超时、访问拒绝、数据不完整等保留失败类型和NativeErrorCode/HResult；失败记录也写失败时保留两个异常。

RegisteredJobSet最多读取1024个完整私有intent，超限不跳过。集合记录明确CompleteProcessOwnershipQualified=false、AdmissionOrNetworkQualified=false。关闭句柄不是“已观察进程为零”，打开/持有句柄也不能称为没有生命周期影响的只读查询。

## 命名空间失联与未闭合范围

微软说明：创建者关闭namespace句柄或退出后，后续OpenPrivateNamespace可能失败，即使既有对象句柄仍能操作。因此namespace打不开不能推导为Job已不存在、全部进程已退出或恢复成功；源码保留失败/UNKNOWN，不重建一个新namespace再查询成空。

只有已持有原namespace时，对固定Job名字的OpenJobObject自身返回ERROR_FILE_NOT_FOUND才表示那个名字当时不存在。这仍是Job范围观察；其他查询错误不当缺失，且不扩展为无未归属/逃逸进程。

创建者崩溃后的最终进程核验、原子JOB_LIST创建绑定、服务/管理员工作进程生命周期、未归属进程窗口与完整启动准入仍须继续实现。未来启动器必须在创建时把Job列表作为属性提交，不能恢复为“创建进程后再Assign”的中间窗口，也不能把Binding字段当实际绑定证明。

Job继承不覆盖所有外部代理创建路径；WMI/共享服务及工具链等不能由普通子进程继承推导安全。实际token/包身份和WFP/DNS/UDP边界仍须对应owner证明。namespace关闭未使用DESTROY标志，本轮没有做对象残留清理或全资源不存在声明。

## 验证边界

32份维护C#仅Roslyn ParseText，15份PowerShell仅语法解析，显式项目引用/资源核对；没有编译、类型/布局/互操作验证、项目程序集加载或功能测试。需要受控本机验证namespace边界/ACL与过滤令牌、对象碰撞、权限/标记往返、同Job父/子与嵌套、成员列表增长、限制漂移、终止后零成员、持有句柄对崩溃的影响、创建者退出及所有创建/记录窗口。

实际完整runtime lease、网络资源owner、broker/bootstrap、用户态状态和本机功能/故障验收仍未完成。原编译/运行停止条件、空批准包pin、真实Claude延期及禁用规则保持；AV开启，新告警立即停止，不通过排除/改名/重包装/关闭防护绕过；不停止日常FlClash/TUN/BFE、不改全局网络，不要求VM或重启。完整目标active。

依据：[Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)、[Job访问权限](https://learn.microsoft.com/en-us/windows/win32/procthread/job-object-security-and-access-rights)、[成员列表](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_process_id_list)、[TerminateJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject)、[Object Namespaces](https://learn.microsoft.com/en-us/windows/win32/sync/object-namespaces)、[CreatePrivateNamespace](https://learn.microsoft.com/en-us/windows/win32/api/namespaceapi/nf-namespaceapi-createprivatenamespacew)。API依据不等于本设计已在本机合格。
