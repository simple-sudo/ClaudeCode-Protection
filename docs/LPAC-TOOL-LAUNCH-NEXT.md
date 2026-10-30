# 下一次实机验证：单个PowerShell事件提供者的注册权限租约

当前安装6e2cf8cd/manifest6AAE651E，INACTIVE。原GPO注册表拒绝已越过，最新真实工具失败点是PSEtwLogProvider.EtwRegister拒绝5，AMSI初始化连带引用同一失败日志类型；PowerShell/Git/编译未完成。原Job66f8bc5a闭合归零、Stop无失败、根I/O/四拒绝5通过、宿主SideBySide权限不变，无强杀。原报告235A0301、唯一错误874FA3FF保留于work/hosted-policy-r2-control/run-evidence；用户确认的原项目异常弹窗也保留。

## 原状态和修复边界

本人明确授权的一次只读ETW查询09:11:57Z完成：唯一提供者F90714A8-5509-434A-BF6D-B1624C8A19A2，EventAccessQuery=0/292字节，实际默认SD包含WD/AAP/logging capability的1800；该查询检查的带括号持久值不存在。无ETW修改、注册/会话控制、日志内容读取、特权开启或产品运行。证据work/etw-provider-query-control/evidence。该次授权已完成，不扩展为权限变更。

新SessionEtwProviderAccess复用原ProtectedSession/原Job，仅给当前安装包SID增加该唯一GUID的TRACELOG_REGISTER_GUIDS=0800，不授予日志读取、实时消费、会话控制、提供者启停或宽泛capability。只接受已观察默认SD，且同一GUID的B/D/N/P四种表示都无现有持久值、已有存储父键存在；自定义策略拒绝、不接管。先持久意图，再调用Windows EventAccessControl；添加后只允许新增一个无继承Allow0800，原owner/group/DACL/SACL内容保持，记录实际SD以及包含值名的原始值摘要，运行期同时核对。ACE插入位置可不同，不接受其他变化。

只有原Job持久关闭归零后才调用EventAccessRemove移除本次唯一新增覆盖值，并核对原默认SD及该GUID四种表示全部缺席。外部漂移不覆盖，未完成意图阻止新会话和安装维护；只读inspect及显式恢复命令复用原可信安装/管理员、全准入闭合、完整隔离及原Job持久证明。缺少进程/Job不是闭合证明，无自动恢复。中断恢复仍未实测；并发管理员/内核不属于当前对抗保证。

受限根新增“注册授权后，提供者安全描述符查询仍拒绝5”的针对性负例。ETW和AMSI保持，不修改AV、驱动、日常网络/FlClash/UU，不给开发进程管理员令牌。

## 已完成资格

六产品非生成语义通过，sourceccad110的63输入构建及64输入Bootstrap通过，复用资格库213649E6未重建。20文件/10PE/6managed/内嵌manifest匹配；新增native仅EventAccessQuery/Control/Remove，System32绑定。纯策略实测一个精确0800 ACE、原内容、位置变化、无写入意图、授予回执前中断决策、持久值摘要漂移拒绝和宽泛SID/权限拒绝通过；两个普通维护入口均125/UnauthorizedAccess且在私有状态前拒绝。work/etw-registration-build-r2/qualification.json。尚未调用权限变更API，也未资格真实授予/撤销或工具兼容。

## 待本人授权：两次UAC

1. INACTIVE更新新包e1829299，仅运行只读inspect-etw-provider-access，确认当前原默认SD/无自定义值/无待恢复意图。不创建资源、授予权限或运行工具；既有552工具文件不修改。
2. 安装及独立15文件核对后，原Broker的一轮严格LPAC PowerShell/固定自有Roslyn C#编译/离线Git验证；在原根仍挂起时按上述范围临时增加当前包注册权限，原Job闭合归零后精确撤销。独立已资格的单独查询程序在前后各读取该唯一GUID的SD，并核对四种同GUID值名均不存在。主任务40秒，各只读观察10秒，排空1秒。异常只停止本次确切新owner，不重试或自动恢复；未成功还原则保留意图并阻止下一会话/维护。若任务失败且原Job关闭证明完整，仅仅读取本次唯一工具错误记录到同一受保护结果目录。

不执行输入项目代码或真实Claude，不开放网络、不故意触发崩溃。不把安装、纯策略或固定自有样本当完整产品/项目编译/14项/GPU/全宿主隐私证明。

| 冻结输入 | 标识或SHA256 |
|---|---|
| 新Release | e18292999fe949af9f95e053131bb19e |
| 新manifest | 3B33F9494EB53D0EF7B22C3A2A1B29D7CE7E8EB57E8412371E98DFF536117B83 |
| Lifecycle库 | 213649E62741AAAA8E09826B430BA21A402D3DDE23AF48C2589F45C094403158 |
| 安装plan | 29B83A7F3FEFE48A936859FF9FEDAF9F69377F2361FC2607DC295663067354DB |
| 安装helper | 32F61F384970E5A55528D24F1C88A6004F549D22C5B23185EA31BF337AFF01EE |
| 运行plan | 17A04A75B70139B2C2497B6CBFEA413806E0F5F554DC13B5A5ECBF5B0417BD80 |
| 运行helper | E2A94BEBB2B266C18DFA5A044773613BBAD97D9D357FD800AB1D1003F67DEC29 |

完整冻结审查work/etw-registration-r2-control/system-operation-review.json。两个严格预检已实际返回、未知参数拒绝，无本次UAC/claim或权限变更。按用户指示和AGENTS.md，新包及本次单资源权限修改/运行需要具体授权和本人UAC；尚未授权或执行。旧候选f96d6c60/C7DD未安装，不使用其旧冻结文件。所有旧失败、权限状态和蓝屏证据保留。
