# 下一步：只读核对固定PowerShell事件提供者权限

当前安装6e2cf8cd8808409bb0b80693f7f9339c/manifest6AAE651E，INACTIVE。08:58:36Z本人UAC更新/只读检查、15文件独立摘要/ACL核对完成。随后授权的一次实际session87ee31dfc2b5405baa66a4a59844c039已越过旧GPO注册表读取，现失败于PowerShell自身的ETW提供者注册：PSEtwLogProvider → EventProvider.EtwRegister → AccessDenied5。其后AmsiUtils的初始化同样引用失败的PSEtwLog。PowerShell/Git/编译未完成，无成果。

原Job66f8bc5a闭合归零、Stop无失败、根I/O与四项拒绝5通过；无强杀owner，宿主SideBySide完整权限独立不变。按照该次明确授权，同一helper仅在闭Job后读取本次唯一错误，原字节SHA256=874FA3FF16A857839BC6AADD0BEBC48F2C6B64E69C1020B217C208668A15F424，truncated=true；Broker报告235A030177E18C3F212910DCDF2FE27CFE06D57F7196DD0CACD041F5D201F972。work/hosted-policy-r2-control/run-evidence保留。用户确认的前次项目异常弹窗及原截图、GPO错误读取、普通托管编译成功与所有失败仍保留。

## 技术方向与尚未实施的部分

固定官方7.4.22[PSEtwLogProvider源码](https://github.com/PowerShell/PowerShell/blob/v7.4.22/src/System.Management.Automation/utils/tracing/PSEtwLogProvider.cs)将提供者GUID固定为F90714A8-5509-434A-BF6D-B1624C8A19A2。[Windows EventAccessControl文档](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/nf-evntcons-eventaccesscontrol)区分注册提供者、读事件/控制会话等权限；SDK26100 wmistr.h定义TRACELOG_REGISTER_GUIDS=0800。

下一修复假设是原Broker仅为当前包SID临时授予这个提供者的注册权限，绑定原Job、意图先持久化、闭合归零后精确撤销。此授权尚未实现或批准：必须先核对实际原权限及是否已有自定义持久值，才能确定安全恢复方法。不会关闭/替换ETW或AMSI、修改AV、不授予通用日志读取/会话控制或宽泛logging capability。

## 本次仅申请一个UAC只读操作

普通固定EventAccessQuery已返回5/0，无法读取描述符；原失败在work/etw-provider-query-build-r1/run-result.json，未修改ETW。已准备work/etw-provider-query-control/query-read-launch.ps1，只通过一次本人UAC完成以下具体范围：

- 将3个已审查、固定摘要的诊断文件复制到新受保护目录C:\Program Files\ClaudeCodeProtection-EtwRead-f90714a8-r1，并只运行一次已固定.NET8查询程序。
- 仅调用EventAccessQuery读取上述唯一GUID的有效安全描述符；再只读HKLM\SYSTEM\CurrentControlSet\Control\WMI\Security中这个GUID对应值是否存在。最多65536字节，不枚举/读取其他提供者或日志内容。
- 不调用注册、授权、启停、控制、删除API，不改ETW权限，不启用特权，不安装更新/启动产品，不建Job/profile，不触及AV/网络/UU/FlClash，不自动重试或恢复。
- 主查询10秒、排空1秒；超时仅停止本次新建且持有句柄、映像/创建时刻匹配的诊断子进程。原输出及失败保留，不接管既有目录。

诊断构建没有生成器/分析器/网络包；唯一PInvoke为advapi32!EventAccessQuery，System32导入搜索范围已通过metadata核对，无模块初始化器。普通预检实际返回，未知参数拒绝，无本次UAC/claim。冻结审查work/etw-provider-query-control/query-read-review.json。

| 冻结输入 | SHA256 |
|---|---|
| plan | E38DC2EA540F0C891D467431DFBDD919AE46F62012CD1401B84E1D7B75E28926 |
| helper | 5D4D1D642BDCF37E13E1B23F6C46E42B1158D51CCEBEB94047EE46C84B351655 |
| launcher | 156B0F0AC394B0C74C04E803A1925AE5D0973D24317CFAABA904C220F60BAAA4 |
| 三文件目录清单 | 95CE3FA6B96DC132D70FECFB8AB8B5A85FB3863D4FE8AD4AB66C40E978F5B81D |

按用户指示与AGENTS.md，新增受保护系统资源读取需要具体授权及本人UAC。前次两个安装/运行授权已完成，本次只读尚未授权或执行；它不授权后续权限修改或重跑。全面宿主隐私/网络/14项/GPU/正式项目编译仍未整体验收，旧蓝屏根因未关闭。
