# 自有受限进程未来对象默认 DACL 候选

SOURCE / BUILD，普通组件范围 VERIFIED；尚未接入任何创建/资格路径，未安装、未调整真实
LPAC token，不能证明 endpoint 或网络已修复。最新运行/授权只见 CURRENT-STATE。

## 依据与候选范围

现装3e2原owner实际LPAC固定endpoint创建拒绝C0000022。后续只读查询确认AFD设备
SecureOpen=false、AppContainerTraversal=true；实际LPAC有启用的SeChangeNotifyPrivilege。
因此没有补遍历特权或修改全机设备DACL的依据。实际token默认DACL为四项：BA GA、
SYSTEM GA、当前登录SID GXGR、本安装package GA，没有当前用户SID的GA。

这是一个新建对象访问失败的具体候选解释：AppContainer访问同时受到普通用户与package
检查约束，已有package条目不能单独补齐普通用户写权限。该解释仍未由实际endpoint成功
验证；不能把内存描述符测试当成驱动内部调用跟踪。

## 精确规则

`OwnedObjectDefaultDaclPolicy.AddExactOwnerAce` 只接受上述规范化四ACE模板、真实域账户
形态的用户SID及确切单packageSID。拒绝宽泛package SID、其他条目/权限/继承/回调/重复
归一化或未知形态。只增加当前用户的一项无继承GA，原四项字节及顺序保持，原package
权限不变。这里操作的是未来对象的通用权限模板，不是现有文件/注册表/设备的ACL。

普通组件测试使用当前普通token，在内存中先将通用ACE权限映射为文件对象权限，再做
AccessCheck；访问检查不替ACE做这种映射。候选增加用户条目后，普通用户一侧的文件
读写由拒绝变为允许。该模型不是实际LPAC双重检查或AFD endpoint实测。

## 原owner候选原语

`AtomicChild.PrepareOwnDefaultDaclBeforeResume` 当前只有定义，没有运行调用点：

- 先原管理员身份门、state/version持有及原gateway preparation；仅当前实例已持有的、
  尚未Resume且属于原atomic Job的唯一LPAC子进程，不收PID、路径、token或外部ACL参数。
- 核对package、low、cap0、LPAC AccessCheck2及实际TokenUser等于当前可信owner用户。
- 只开该token的QUERY|ADJUST_DEFAULT，保存原模板与精确新模板的私有意图。
  `SetTokenInformation`固定class6，仅修改该进程未来对象的默认DACL。
- 原token身份、package/cap/low/LPAC语义必须不变，原sealed process/thread对象必须不变；
  精确回读后写绑定原Job/PID/创建时间/版本的完成记录。
- 不调整privilege、group、integrity或capability，不实际impersonation，不修改现有宿主ACL。
  任何中途失败仍由原owner保持隔离并停止原Job；没有自动恢复/重试或认领其他进程。

这不是通用维护入口，也不是可复用的执行许可。新建对象的权限变化仍须审查跨进程、
跨会话和真实宿主内容暴露；不能从“只改token”推导安全。

## 已有验证与下一资格

22项普通规则/真实普通token用户侧检查通过，覆盖保留原条目、仅一项增加、未知模板、
宽泛/异包、继承/deny/权限漂移、重复修改拒绝及普通访问正反控制。初版测试错误地从
WindowsIdentity.Groups挑登录SID，以及未映射generic模板即AccessCheck，两次失败单列保留，
修正模型后才取得上述结果。不是把失败结果计为成功。

新增原语后的当前ProtectionLifecycle以SDK8.0.422持有84个源/资源输入构建0错误0警告。
普通身份反射调用零参数原语，第一管理员门拒绝，未构造owner/创建进程或执行setter。
证据 `work/owned-default-dacl-8878bf2/verified-candidate-source.json`；这些不证明真实
token写入、异常闭合、全产品构建、安装、网络或隐私资格。

后续优先在原链固定一次进程内验证候选是否使原生endpoint可创建，并同时做实际网卡、
地址/DNS、IPv4/IPv6连接表等内容获取尝试与可信宿主原值对照。必要原值留在受控研究
证据区；不得进入正式Claude/Anthropic通道。单项P0真实暴露阻断候选，不能以联网成功
抵消。实际token修改、安装或新的受保护运行均另需固定工件和具体本人决定；旧许可消耗。
