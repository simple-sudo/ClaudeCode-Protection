# 单次原子Job运行租约与Watchdog

2026-10-27，当前SOURCE，待独立构建/资格/真实运行。复用已安装Broker、原子AppContainer/Job、既有持久fence与代理身份租约，不新增常驻服务或通用执行命令，不构成整体安装更新/卸载authority。

## 已接入的运行路径

ProtectionRuntimeLease绑定当前pointer SHA、已核验版本、同一一次性Job、完整持有的fence列表及代理进程/监听身份。25秒启动期限内持续检查版本/选择、代理健康、5角色指定代理状态、Job限制；资格程序可一次切换到有界active期限，不能重复激活或续期。原qualify-network的代理阶段已调用同一个租约和Stop流程，不是孤立的测试模型。

停止时先在内存关闭该租约准入并写先行记录，恢复/回读本安装SID全部隔离，再终止精确Job并观察零、记录绑定原准入的关闭回执及新session-stopped。恢复失败也继续精确Job终止，失败明确保留，不冒充“已先行隔离”。Stop回执可重复读取，不能重复写关闭证明或重新开放。profile/精确回环豁免在Job零后按现有lease释放。

## 固定已安装qualify-watchdog

不接收路径/PID/SID/规则GUID/命令参数。必须既有管理员、当前安装完整资产核验、所有历史准入已关闭、回环历史闭合和完整隔离。只启动当前Broker自身有限canary，创建时绑定安装AppContainer Low4096/零capability及Job。先通过同一固定Microsoft HTTPS资格，再保持自有回环旁路探针，最长60秒自退；该自退不算Watchdog成功。

两个实际场景：active期限1000ms到期，以及在active期限内由工具精确恢复自身完整隔离造成收窄漂移。后者只增加拒绝，不移除守卫或改全机策略。要求检测原因精确匹配、隔离回读先于Job停止、子进程125退出、Job零和自有接收端无nonce投递。记录检测耗时作为本次观察，不承诺调度/规则操作零延迟。案例结果与session回执保留原始失败。

## 明确未通过的整体范围

本切片没有已认证客户端心跳续期、任意真实Claude/开发工具启动、一般多会话/更新/卸载runtime适配器。真实FlClash进程不停止、不重配；本轮不把期限模拟当代理崩溃，也不把收窄漂移当缺失/篡改守卫或故障中物理出口证明。ProxyProcessCrashQualified、ControllerCrashQualified、UnsafeRuleRemovalQualified及AuthenticatedControllerRenewalQualified保持false。

[微软Job契约](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)说明最后一个Job句柄关闭会终止关联进程；这是崩溃设计依据，不是本轮独立崩溃验收。若真实owner意外退出、没有可回读完成回执，不得因Job/namespace名称缺失就认定零成员。仍需接入独立存活/退出观察或可信内核完成证据与恢复，不能留下不可核验的遗留状态后继续一般维护。
