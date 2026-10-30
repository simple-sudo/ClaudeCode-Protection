# LPAC 工具启动：本轮结果与下一步

当前实际安装 **7ffea33b977c4db1ae0c6b322bfc25ba / B23DDA0D / INACTIVE**，库3B7105C7。本人授权的两个操作均已完成，不能重用其一次性入口。

- 11:50:53Z 更新及只读检查成功。15个安装文件的摘要、可信所有者、受保护DACL及无不可信写者独立匹配。新固定清单接线缺陷已实际修复，检查返回NO_PENDING_ETW_PROVIDER_ACCESS、原默认SD、无自定义值。
- 11:51:38Z 原Broker会话743967b9e0d34450928cfffb6349817e实际授予同一包SID、唯一F90714A8提供者的0800注册权，并在原Job2fad4a3bfec544eca52561b7356502ad持久闭合归零后撤销。独立程序前后读取的SD相同，同一GUID的B/D/N/P四种值名都不存在；SideBySide权限不变。根工作区读写和五项拒绝5通过，停止无失败、无强杀，启动时间和AV/BFE/FlClash/UU保持。
- **PowerShell仍在EventRegister返回5**，PSEtwLogProvider初始化失败，AMSI类型初始化连带引用同一失败日志类型。PowerShell未READY，Git和C#编译未运行，无结果释放；不能把权限恢复成功当成工具兼容成功。

原始证据：work/etw-registration-r3-control/installed-evidence、run-evidence、observed-result.json。报告SHA25674333285AF5B7F2CA5C1CF2CEBD52E09F565D8C893D2D3D62B645598D2FD585E；本次唯一工具错误SHA256874FA3FF16A857839BC6AADD0BEBC48F2C6B64E69C1020B217C208668A15F424（有界截断，错误内容与上次相同）。失败及旧候选均保留，不自动重试或恢复。

## 已收束的路径

单独增加0800注册权没有解决启动；不继续叠加相似授权、不盲加1800或宽泛lpacLogging。新源码撤下默认资源调用中的自动授予，并删除新的EventAccessControl导入/创建工厂。保留旧意图、授予回执、闭合回执解析、待恢复阻断、只读检查和原Job持久关闭/完整隔离之后的显式精确恢复。当前安装仍是本轮已核对的3B7105C7；这项退役改动尚未安装。

ETW/AMSI保持，没有修改PowerShell官方工具文件、全机ACL、AV、驱动或日常网络。不执行实际项目代码或真实Claude；本轮结果不构成14项、网络防绕过、全部宿主敏感资源或GPU验收。

## 下一步证据边界

对实际安装SMA的只读元数据检查确认F90714A8构造常量，实际Eventing DLL导入API-set的EventRegister；KernelBase和Advapi32的导出均直接转发NTDLL.EtwEventRegister。只读公开系统PE、匹配符号离线反汇编确认该路径最终使用NtTraceControl的提供者注册分支，内核注册访问检查请求0800。未附加运行进程、未启动新产品会话。KernelBase第一次符号等待超时已保留，之后只读导出表已明确转发关系，无需再重复这项符号等待。

这些静态信息**不能指出实机返回5的具体分支**，也不能排除运行时组件影响。不能据此修改提供者其他权限、子进程安全描述符、能力或系统驱动。下一次真正有价值的实机步骤应直接区分“当前受限令牌对实际授予SD的Windows访问判定”与“真实EventRegister的返回路径”，复用原Broker/Job，避免再做一轮无变化工具尝试。尚未准备或请求新的系统操作授权。
