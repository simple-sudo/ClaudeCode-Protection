# 精确卸载与中断续接源码

日期：2026-10-25（America/New_York）。状态：SOURCE_IMPLEMENTED_NOT_COMPILED。新增 ExactUninstall.cs、RemovalPolicy.cs 和嵌入 RemovalProtocol.json，补入实际卸载与恢复方法；没有调用它们，没有删除文件或创建安装目录。

## 顺序和权限

Start 先核对管理员状态、关闭 admission、确认无待处置旧操作，保存卸载计划，再通过所属进程owner停止本工具的进程并核对为零。随后在任何资源/文件删除前生成完整清理快照并预检所有对象。资源owner仅可清理本安装拥有的网络对象，回读不存在后，才能删除原 current.json；接着清理精确payload和空目录，最后重新核对进程、资源、指针与代码根都已移除。

所有运行期方法仍由 ILifecycleRuntimeLease 接口描述，实际生产 Job/WFP/admission owner 尚未实现。因此这些调用顺序是源码行为，不是运行验收或产品交付。没有添加长期管理员入口、任意命令/路径接口或构建解锁。真实Claude规则不会由该模块启用。

卸载还要求维护主程序与已加载的文件型程序集位于被清理代码树之外，避免删到正在加载的自身；位置无法确定时先拒绝。这只是自删除前置检查，不认证引导来源，可信外部维护主机及其所有依赖仍待实现。被用户明确退役的原告警EXE摘要也在包策略中拒绝用于安装/恢复，按摘要而非文件名匹配；这不是恶意样本或误报判定。

## 清理依据

- 私有管理员 stage intent 必须绑定本安装的 install/update 账本、release、审查清单摘要和全部固定资产。冲突的同release清单拒绝；相同内容的重复失败intent可共同提供一致范围，但不猜测是哪次创建对象。旧清理页仍接受其原始一致intent摘要，后续重装不改写历史。
- 初次快照要求代码根及版本marker语义属于本安装；文件长度、哈希、owner/DACL、最终路径、非重解析、单硬链接和卷/对象ID均核对。没有完整字节或缺少首marker时，不以目录名当所有权，失败并保留。
- 清单只存release、固定角色、对象身份及摘要；路径始终从Windows固定安装根和内置资产目录重建，JSON不能指定任意路径。
- 每个版本一个受保护CREATE_NEW清理页，主清单绑定各页SHA-256；页保留在管理员状态。主清单容量上限512版本，单页/主记录受大小限制；超界在删除前拒绝，不跳过目标。
- 恢复预检只允许快照中对象仍相同或已不存在；新文件、不同对象ID、内容漂移、外来目录或读取错误拒绝。文件名相同/字节相同但对象ID不同也不删除。

以上完整字节/marker要求描述初版。2026-10-26当前源码改用schema 3：目录使用创建归属，文件附加创建标记与ByteState；pending写入只有通过私有操作、缺失完成回执和未发布检查才可保存实际部分字节快照。完整/发布对象漂移仍拒绝，后续必须与已保存快照完全一致。旧schema 1/2不回填，详见 PENDING-WRITE-CLEANUP-SOURCE.md。

## 同句柄删除与失败

实际删除使用带DELETE访问的已核验句柄调用 SetFileInformationByHandle(FileDispositionInfo)，不把关闭后的路径重新交给宽泛删除器。文件在同一句柄内核对对象ID、长度和哈希，目录只允许相同对象且为空；不递归删除、不通配删除、不按显示名清理。每项先写BEFORE_DELETE，关闭句柄后再查询是否不存在；访问拒绝、共享冲突、delete-pending或回读失败不当不存在，也不计PASS。

失败记录保留类型、NativeErrorCode/HResult、目标角色和清单身份；失败记录本身也写失败时，保留原失败与记录失败两个异常。管理员状态、原配置、私有备份、旧账本、失败与清理页都保留。删除对象未全部证实不存在，不写完成状态。

## 中断恢复

Resume 先完整读取并核对原卸载账本、当前指针仍是原值或已不存在、没有其他未解决操作，再停止所属进程。它只能续接指定uninstall操作，不给version恢复借权。初次计划写完而begin记录未写完时，可在新时刻建立begin；不回填旧时间。

原清单与页保持不变，已删除项跳过，其余项重新预检并逐项清理。已经记录的阶段仍要求当前runtime重新确认；completed-removed也必须重新核对现状。旧的孤立证明只有与新观察完全相同才复用，并另写本次reobserve记录；不覆盖旧证据。不同指针/新安装对象一律拒绝，不影响新版本。

重装相同发布时，原授权回执和历史选择记录保留，另写restage记录；release被不同字节复用仍拒绝。用户配置和证据不随代码卸载被删除。

## 本轮验证和未完成边界

11组纯PowerShell数据检查通过，枚举嵌入删除策略96个观察格：4个有限DELETE/SKIP决定、92个拒绝。不同对象ID、内容变化、不可读、非空目录、递归删除、保留标志丢失、容量越界、重复规则与任意执行动作均拒绝。**只检查JSON策略数据，没有加载C#、读取管理员状态、调用删除API或实际卸载。**

C#只做语法解析。真实句柄删除、共享/delete-pending、目录非空、每个清单/证明/提交窗口、部分卸载恢复以及AV兼容性都尚未执行验收。实际bootstrap、生产broker/认证传输、runtime资源owner和用户态状态目录适配仍未完成。

特别保留缺口：创建目录到首marker/身份回执的窗口，以及拷贝中断产生的零字节/截断文件，当前无法凭完整摘要证明预期字节时会保留并报失败/UNKNOWN。不能把安全拒绝或保留残留当“全部恢复/卸载通过”；还需补创建身份记录与相应受控负向验收。

当前仍无批准包、无可执行交付；原停止条件保持。不恢复被删除程序、不重复原selftest、不以排除/改名/重包装/关闭AV绕过检测；不停止FlClash/TUN/BFE、不改全局网络，不要求VM或重启。完整goal继续active。

依据：[SetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle)、[FILE_DISPOSITION_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_disposition_info)。官方API语义不替代本机验证。

## 后续创建身份接入

创建时归属标记和目录快照schema 2已补入源码；已验证标记/管理员范围的目录不再仅依赖首marker存在来证明归属。旧schema 1不回填新身份。仅OPEN_EXISTING真正缺失才允许跳过，身份/ACL/最终路径查询错误及外部祖先不可用保持失败/UNKNOWN。截断程序文件的清理判定仍未接入新证据，不能把目录接入当全部窗口已闭合。未执行API，详见 CREATION-IDENTITY-SOURCE.md。

## 2026-10-26部分写入消费更新

PendingFileAuthority.cs已接入捕获、清单读取、预检和同句柄删除；schema 3保存实际摘要/长度/创建标记/字节状态。前述“截断文件消费未接入”是本次更新前的源码状态。没有编译或执行清理；损坏完成/发布回执或私有账本仍拒绝，真实运行期owner及全部故障验收仍未完成。见 PENDING-WRITE-CLEANUP-SOURCE.md。
