# LPAC 工具启动：本轮结果与下一步

2026-10-31（F 盘开发）：新窄诊断已完成普通资格和严格预检，实际受保护调用仍 **NOT_AUTHORIZED / NOT_RUN**。新控制在 `work/etw-access-diagnosis-20261031/trace`，具体范围、哈希、停止边界及失败保留见同级父目录的 `system-operation-review.md`。目的只区分匹配 PowerShell 提供者的线程通知初始化与原生提供者注册返回路径；不再试加 0800/1800 权限，不关闭日志/AMSI，不更改安装。普通官方 7.4.22 实测匹配提供者 EventRegister -> NtTraceControl(0x0f)/NTSTATUS 0 -> Win32 0；cmd/where 新父子回调通过。这些普通结果不证明 LPAC 成功。系统步骤只启动新原 Broker/Job，需一次具体人工 UAC 决定，且必须包含超时后唯一精确新建诊断 owner 的结束范围；强停不证明 Job 闭合，不自动恢复。plan6DC84D61/helper3A56FE62/launcherFE14A1BB。历史 C 盘控制保持原字节及消费后的授权状态，不运行。

当前实际安装 **62eab36f66ba4dc5b117b1fbe4d1170c / B692EEF8 / INACTIVE**，库19D64CFF。原日常入口的严格LPAC Git数据往返已实际通过，见下节及STATUS。两个对应UAC均完成，无待执行操作。下面先保留前一版7ffea33b/B23DDA0D/3B7105C7的ETW试验结果，不把它当成新安装选择。

- 11:50:53Z 更新及只读检查成功。15个安装文件的摘要、可信所有者、受保护DACL及无不可信写者独立匹配。新固定清单接线缺陷已实际修复，检查返回NO_PENDING_ETW_PROVIDER_ACCESS、原默认SD、无自定义值。
- 11:51:38Z 原Broker会话743967b9e0d34450928cfffb6349817e实际授予同一包SID、唯一F90714A8提供者的0800注册权，并在原Job2fad4a3bfec544eca52561b7356502ad持久闭合归零后撤销。独立程序前后读取的SD相同，同一GUID的B/D/N/P四种值名都不存在；SideBySide权限不变。根工作区读写和五项拒绝5通过，停止无失败、无强杀，启动时间和AV/BFE/FlClash/UU保持。
- **PowerShell仍在EventRegister返回5**，PSEtwLogProvider初始化失败，AMSI类型初始化连带引用同一失败日志类型。PowerShell未READY，Git和C#编译未运行，无结果释放；不能把权限恢复成功当成工具兼容成功。

原始证据：work/etw-registration-r3-control/installed-evidence、run-evidence、observed-result.json。报告SHA25674333285AF5B7F2CA5C1CF2CEBD52E09F565D8C893D2D3D62B645598D2FD585E；本次唯一工具错误SHA256874FA3FF16A857839BC6AADD0BEBC48F2C6B64E69C1020B217C208668A15F424（有界截断，错误内容与上次相同）。失败及旧候选均保留，不自动重试或恢复。

## 已收束的路径

单独增加0800注册权没有解决启动；不继续叠加相似授权、不盲加1800或宽泛lpacLogging。新源码撤下默认资源调用中的自动授予，并删除新的EventAccessControl导入/创建工厂。保留旧意图、授予回执、闭合回执解析、待恢复阻断、只读检查和原Job持久关闭/完整隔离之后的显式精确恢复。前一次ETW试验安装为3B7105C7；这项退役改动已随62eab36f安装；新数据链没有提供者权限修改。

ETW/AMSI保持，没有修改PowerShell官方工具文件、全机ACL、AV、驱动或日常网络。不执行实际项目代码或真实Claude；本轮结果不构成14项、网络防绕过、全部宿主敏感资源或GPU验收。

## 下一步证据边界

对实际安装SMA的只读元数据检查确认F90714A8构造常量，实际Eventing DLL导入API-set的EventRegister；KernelBase和Advapi32的导出均直接转发NTDLL.EtwEventRegister。只读公开系统PE、匹配符号离线反汇编确认该路径最终使用NtTraceControl的提供者注册分支，内核注册访问检查请求0800。未附加运行进程、未启动新产品会话。KernelBase第一次符号等待超时已保留，之后只读导出表已明确转发关系，无需再重复这项符号等待。

这些静态信息**不能指出实机返回5的具体分支**，也不能排除运行时组件影响。不能据此修改提供者其他权限、子进程安全描述符、能力或系统驱动。下一次真正有价值的实机步骤应直接区分“当前受限令牌对实际授予SD的Windows访问判定”与“真实EventRegister的返回路径”，复用原Broker/Job，避免再做一轮无变化工具尝试。尚未准备或请求新的系统操作授权。

## 已安装、严格LPAC实测通过：原有工作区 Git 数据链

PowerShell故障不应成为已有数据处理能力的无关前置。新源码仅对已校验非空WorkspaceInputSHA256的数据范围直接运行固定Git；同一原Broker/Job/严格LPAC、五项根拒绝、Git自身两项拒绝、编译期固定参数/环境、独立仓库快照和闭合清理后输出权威全部保留。该范围无法请求PowerShell，也不声称PS或编译通过；没有输入数据的完整工具资格仍要求二者。没有新CLI、新执行器或协议字段。

新包62eab36f66ba4dc5b117b1fbe4d1170c，manifestB692EEF8753B737E126924E0FC6EA764F39C4BB5BDA4BBFC472A3F45701C45E8，库19D64CFF。Sourceccc6427的63输入构建、实际数据范围拒绝PS/保留固定Git请求、管道解析/旧恢复决策及普通维护入口125拒绝通过。Bootstrape050a1a的64输入构建未重建资格库；20文件、10PE、6managed、内嵌manifest一致。work/git-data-direct-build-r1。实际已在12:40:17Z完成sessionfdf20ddd571a45b6bc77695cc392c6ae：process/review/extract均0，结果AA2F0DFD...43483、四文件无变更且独立提取字节匹配。成功权威来自原Broker闭合/精确清理后导出；没有重复私有Job回执读取。

两个已明确授权并完成的操作：

1. 保持INACTIVE更新并只读检查；没有工具运行或权限授予，不修改已有552个PowerShell文件或Git文件。
2. 普通已安装daily的现有workspace-process入口，由本人确认一次原Broker UAC，处理此前已选择并冻结的四文件数据包BA1C5764F54DF02B4E9266EE4C6414E28C6D8E8D18F9A07EB91A0CE4DC0D4138：docs/WORKSPACE-TRANSFER.md、src/Shared/WindowsDirectoryNames.cs、src/Shared/WorkspaceBundle.cs、tests/WorkspacePipe/Program.cs。仅是这些旧字节的DATA，不执行项目代码；原Broker严格LPAC固定Git init/add/commit、关闭快照、精确清理及权威成功后导出，随后普通用户review和新目录extract/逐文件字节核对。无需重跑已资格的pack。原资源范围20秒，现有daily连接后完成等待75秒；本人UAC等待由本人控制，普通runner不外部终止提升权限owner。异常保留原安全失败/StopEvidence、空输出，不自动重试/恢复，不用新命令或管理壳。

新路径无ETW权限授予、注册表/网络/AV修改，没有PowerShell/C#编译或正式Claude。现有PowerShell启动故障仍是完整产品阻碍，不能以Git数据成功替代。

安装plan4E881554740C140B2E2F1180711642B08C89E47F360D617A297E742EC11065C5 / helperFBCA336ADE659D0E8D83DAA4E47DAC72B61DD725E8A68F5D2A5EBF2961693B1E；数据plan3C8DC1D6A0A661AD1A1462EFC009BAC87BA47889D3427138EBBA146EAA401031 / runnerA5A9315BADADEB493A30877B25B7D2AB902917396F41C5463127CAF01566067B。完整冻结审查work/git-data-direct-control/system-operation-review.json。原始普通runner误写bin/daily路径，在UAC/产品创建前失败，原失败及claim保留。R2从安装目录清单解析bin/current，产品和输入未变，继续尚未执行的同一授权；planA242228F/runnerD9D0BFC8，原资源只运行一次，结果见work/git-data-direct-control/workflow-r2/observed-result.json。没有新的授权范围、保护任务自动重试或恢复。两个UAC现已完成，不再复用这些一次性入口；普通入口仍可由明确授权的新调用复用。
