# 安装身份WFP隔离屏障源码

> 文档效力（2026-11-02）：持久网络屏障专题。历史规则/有限矩阵不等于今天完整网络验收；控制器退出后的拒绝边界是P0要求，须与精确停止/恢复分别验证。
> 最新状态/授权只见[CURRENT-STATE](CURRENT-STATE.md)，正式目标与术语见[SECURITY-REQUIREMENTS](SECURITY-REQUIREMENTS.md)。以下旧状态与操作许可不自动延续。

日期：2026-10-26（America/New_York）。状态：SOURCE_IMPLEMENTED_NOT_COMPILED。新增WfpNative.cs、FencePlan.cs、PersistentFence.cs；没有加载项目库、编译、调用WFP/安全API、创建AppContainer profile或修改规则。

## 具体实现与当前状态

新增本地非dynamic WFP engine、显式读/写事务、按GUID读取/添加/删除、对象安全描述符读取和原生数据释放实现。PersistentFence可从VerifiedVersion建立初始隔离，读取完整语义，并在同一写事务中对已验证归属的对象重建双栈隔离。

它还不能开放代理通路、启动进程或在卸载时移除最终屏障，也没有实现完整ILifecycleRuntimeLease。所有观察明确LaunchQualified=false、ProxyQualified=false、RebootQualified=false；当前隔离不是最终IPv4强制代理产品。下一步仍需代理身份/监听/路径实证、原子进程绑定和真实准入、监测/漂移与安全清理组合。

## 先保存计划，再变更内核

CreateQuarantined只接受受保护管理员状态与已持有的VerifiedVersion，要求当前指针/release/清单匹配且无未处置生命周期操作。私有fence-intent先保存全部非空/唯一GUID：一个sublayer及六条固定角色；记录安装ID、FenceId、release/清单摘要、编译策略摘要和端口。读取严格校验schema、字段、固定顺序、名字与跨计划GUID冲突；最多64份完整计划，超限不跳过。

包SID只从固定ClaudeCodeProtection.<InstallationId>名称通过Windows派生，不接受外部SID/路径/过滤器编号/端点。派生SID不创建profile、不证明运行进程具有该身份，也不把Job角色27的元数据SID用于网络。

每个内核对象的providerData包含产品标记、安装/Fence ID、原始私有计划SHA和角色，另核对精确GUID、名字、sublayer和package条件。修改私有计划字节会使标记不再匹配。数字FilterId只作观察证据，不作恢复或删除选择器；没有旧编号回退或按名字通配删除。

编译策略限定IPv4 TCP 127.0.0.1:7890，仍须实际代理审核，不能据端口号认证FlClash。此策略属于未来被审查的ProtectionLifecycle.dll字节，不是用户可写配置或管理请求覆盖。旧私有计划可以按其保存端口检查/恢复隔离，但不因此取得新版本启动资格。

## 六角色与隔离恢复

全部过滤器为精确package SID的BLOCK，配置PERSISTENT、最大uint64权重及最高sublayer权重；没有全机过滤器。

| 角色 | ALE层与额外条件 |
|---|---|
| ipv4-address | CONNECT_V4，远端地址 != 127.0.0.1 |
| ipv4-port | CONNECT_V4，远端端口 != 私有计划端口 |
| ipv4-protocol | CONNECT_V4，协议 != TCP |
| ipv6-deny | CONNECT_V6，无额外放行条件 |
| quarantine-v4 | CONNECT_V4，整个该package范围 |
| quarantine-v6 | CONNECT_V6，整个该package范围 |

初始六条均存在，因此IPv4代理通路也处于隔离；当前没有解除隔离函数。基础IPv6阻断始终保留，不开发IPv6转发。

健康要求精确类型/比较符/值、条件数、package唯一性、层、flags恰为PERSISTENT、BLOCK动作、权重、空context/reserved等。DISABLED或其他flags不计匹配；只数Present/Persistent不授予健康。

ReinstateQuarantine先在同一写事务核验全部归属，才按保存GUID移除已拥有对象并重建全部六角色；事务内读取确认，再提交、独立只读事务回读。它不在两个已提交事务间故意开放范围。语义漂移但归属仍可信可恢复隔离；SID、计划标记、owner/DACL或归属不符则拒绝。sublayer被额外过滤器引用导致删除失败时整个写事务失败，不清理未知对象或部分报成功。

该替换是恢复屏障的内部事务，不是公开卸载接口。关闭engine不删除persistent对象，不当清理成功。最终卸载移除屏障仍须完整进程/准入所有者提供实时证据后实现。

## 安全描述符与持久性边界

添加对象时使用显式受保护SYSTEM/Administrators DACL；读取对象安全描述符，保守拒绝外来owner、额外主体、继承/回调/未知ACE。WFP返回内存用FwpmFreeMemory释放，SID与本地描述符各用其API要求的释放方式；事务失败与abort失败同时保留，日志也记录各原始错误代码/阶段。

本实现不关联provider。微软说明关联provider若没有合适的自动启动服务，过滤器在BFE重启后可能返回DISABLED；因此没有创建一个缺少实际服务绑定的provider并把PERSISTENT标志当重启验收。无provider方案仍须本机验证，不能由文档或源码推导BFE/系统重启后保护有效。

当前范围为INSTALLATION_PACKAGE_SID_ALE_CONNECT_ONLY。既有连接/已缓存授权的重新授权时序、已排队数据、DNS/系统服务代理归属、外部服务创建进程、入站与其他WFP层、竞争规则及BFE失联的效果都未证明；不得将本组件叫作完整即时断网或无泄漏。Boot-time过滤器未实现，也没有停止BFE或改日常网络来测试。

## 检查与未完成

35份维护C#仅Roslyn ParseText，15份PowerShell仅语法解析及项目显式引用核对。对本机SDK 10.0.26100.0与10.0.28000.0的六个GUID数值做12项源码文本对照；不是编译、native ABI或实际策略验收。结构大小/偏移只是源码中待运行的保护断言，尚未执行或证明。

最初文本比较将SDK大写注释与小写GUID判为两项不同，原结果保留；随后改为提取DEFINE_GUID的数值并比较GUID值，数值均一致。没有通过修改源码GUID来掩盖差异，也不将比较器修正当WFP运行通过。

实际代理身份/路径审核、开放通路的受限权限、Job创建时原子绑定、完整准入/生命周期适配器、最终屏障清理、Watchdog/漂移、可信bootstrap/broker、其他坏账本恢复、用户态状态和本机功能/故障验收仍未完成。原空批准包pin和编译/运行停止条件保持；真实Claude延期、禁用规则不变；AV开启，新告警即停，不恢复原EXE或重跑旧selftest，不通过排除/改名/重包装/关闭防护绕过；不停止FlClash/TUN/BFE、不重设全局网络，不要求VM或重启。完整目标active。

依据：[FWPM_FILTER0 flags/provider行为](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0)、[WFP对象管理](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)、[事务](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionbegin0)、[安全描述符读取/释放](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltergetsecurityinfobykey0)。API文档不授予本机保护资格。
