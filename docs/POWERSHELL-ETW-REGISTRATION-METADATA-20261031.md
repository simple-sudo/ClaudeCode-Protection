# PowerShell 提供者注册元数据：普通只读实测

2026-10-31，工具源码 `ce7d54f`；不改变产品安装、ETW权限或控制会话，不读取事件内容。

新增范围仅为固定 GUID `F90714A8-5509-434A-BF6D-B1624C8A19A2` 的 `EnumerateTraceGuidsEx(TraceGuidQueryInfo)`。不能选择其他GUID、枚举提供者列表、读取/控制会话或注册/启用提供者。新入口只接受普通权限；旧EventAccessQuery入口保持原范围，不因此取得新UAC授权。输出只有PID、Flags、EnableCount等注册元数据，没有事件载荷、会话名称、LoggerId或关键字。

微软将该API的数据定义为运行中提供者的注册信息；`TRACE_PROVIDER_FLAG_PRE_ENABLE` 明确表示提供者尚未注册，但已有会话启用它。[API](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enumeratetraceguidsex)、[实例结构和标志](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-trace_provider_instance_info)。

## 实测结果

1. 普通PowerShell监督器下运行查询：API返回0/152字节；一个实际注册的PID恰好等于监督器自身PID15504，另有两个预启用条目。查询工具自身不在注册实例中。
2. 第一监督器结束后，直接使用原生cmd启动同一哈希工具及.NET8.0.28，无PowerShell启动壳。API返回0/104字节；实际注册实例数为0，仍有两个Pid=0、Flags分别为2和3的预启用条目，各自EnableCount=1。退出0、无stderr。

这证明本次PowerShell启动壳贡献了一个注册实例，也证明移除该启动壳后仍有预启用元数据。**不能由此证明某个实际安全描述符的内容、其更新机制或旧0800试验的根因。** 不把第二次观察当作“提供者完全不存在”，不据此重跑旧权限试验、结束其他应用、禁用现有控制器/日志、改AV或要求重启。

因此，单纯更换启动壳不足以建立“下一次注册一定从新权限初始化”的证据。后续先比较实际受限令牌对已观察WMI描述符与仅在内存中增加精确包SID/0800的描述符的Windows AccessCheck结果；该比较不授予权限，也不等于观察ETW内核描述符。

## 资格与原始记录

新3输入普通离线构建通过，生产产品未重建。工具程序集SHA-256 `1D7748C3D648520EB693EE94F08F05B85C2384E40327665EE966FF974D2F8EF5`；只含System32绑定的EventAccessQuery及EnumerateTraceGuidsEx两个原生入口，无module initializer。64KiB/256实例/每实例64个enable记录上限、相对NextOffset、预启用项及截断/溢出/非法Flags/填充拒绝的内存解析资格通过；未知命令125拒绝。

`work/etw-registration-metadata-build-20261031` 保存receipt、qualification、每项运行结果及native-shell-query输出。两次查询是启动壳这一变量不同的只读比较，不是产品或失败工作负载重跑。无UAC/产品/Job、权限修改、事件读写或会话控制。查询后的工具摘要仍匹配；AV/BFE/FlClash/UU与boot保持，无产品进程。全部厂商告警覆盖仍UNKNOWN。
