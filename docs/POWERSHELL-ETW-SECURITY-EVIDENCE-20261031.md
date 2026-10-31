# PowerShell ETW：读回权限与实际注册判定的证据边界

2026-10-31，checkout `F:\ClaudeCode-Protection`，检查起点 `235a914`。

本记录只补足旧 0800 试验的解释边界，不修改安装或授权，不把静态分析当作运行结果。新冻结数值跟踪仍须具体人工决定，未运行。

## 当前机器公开映像的实际静态调用链

固定系统映像 `C:\Windows\System32\ntoskrnl.exe`，SHA-256 `41CDCA29AD3C9E3EFA1912DCCD04757EBCB3553AC515A279E5DD8D9290E7E030`；固定微软 CDB `A9E81C90...BB039`。只将公开 PE 作为离线目标，没有内核/用户进程附加、产品运行、寄存器改写、权限操作或日志消费。以下是该映像的静态事实，不是跨 Windows 版本的 API 契约。

- `EtwpAllocGuidEntry` 在该映像地址 `0x140836ac9` 调用 `EtwpGetSecurityDescriptorByGuid`，随后在 `0x140836ad3` 取注册条目的 `+0x48` 槽位，交给 `ObLogSecurityDescriptor` 保存描述符引用。
- `EtwpGetSecurityDescriptorByGuid` 调用 `EtwpGetGuidSecurityDescriptor`；后者从固定的 mutable/security key handle 经 `ZwQueryValueKey` 读取描述符。没有对应值时使用默认描述符。
- 旧已保存的 `EtwpRegisterUMProvider` 反汇编在 `0x140838ed4` 读取条目 `+0x48`，在 `0x140838efd` 准备请求掩码 `0x800`，随后调用 `SeAccessCheck`。因此注册访问判定使用注册条目持有的描述符；不能仅凭用户态当前读回值替代它。
- 旧固定 `sechost` 反汇编显示 `EventAccessControl` -> `EtwpSetOrAddAce` -> `EtwpSetWmiGuidSecurity`，后者取得 WMI GUID 对象并调用 `SetKernelObjectSecurity`。
- 新检查的 `WmipSecurityMethod` 更新 WMI 对象描述符后，经 `ObQuerySecurityDescriptorInfo` 和 `WmipSaveGuidSecurityDescriptor` 持久化；该保存函数调用 `RtlWriteRegistryValue`。本次检查的这条直接调用链没有显示对 ETW 注册条目 `+0x48` 的更新。

原始输出均保留在 `work/etw-access-diagnosis-20261031`：`kernel-guid-security-source.txt`、`kernel-wmi-security-method.txt`、`kernel-security-setters-symbols.txt`。旧注册路径和 `sechost` 输出保持在 `work/etw-registration-r3-control` 原文件中。新离线调用均正常退出0；不覆盖前轮符号别名/不存在函数/不完整跳转表分析的失败输出。

## 对下一步的约束

由上述静态链可以提出“已存在 ETW 注册条目仍持有旧描述符”的缓存假设。**尚未证明该假设是实机失败原因**：未观察注册表通知、其他更新路径、条目生命周期、当时内存内容或实际失败分支。本记录不声称描述符永远不更新，也不归因 AV、驱动或某个 Windows 缺陷。

之前通过 EventAccessQuery 和持久值读回验证的精确新增/撤销及值缺席，仍是其实际观察范围内的有效结果；但它不单独证明失败中的注册访问检查已看见新增 ACE。后续即使对受限令牌和用户态读回 SD 执行 AccessCheck，也只能证明该输入描述符的判定，不能推成 ETW 内核当时的实际判定。

因此保持下一次**唯一已准备**的原 Broker/Job 窄跟踪不变，先取得匹配提供者在通知初始化或 `NtTraceControl(0x0f)` 的实际返回。若落在提供者注册拒绝分支，下一问题包括实际描述符/条目更新的证据，不能直接追加权限、授予宽泛 logging capability、要求重启、结束其他 PowerShell/宿主进程、操作驱动或修改官方 PowerShell 字节来试错。本记录没有授权这些动作，也没有新增系统操作。
