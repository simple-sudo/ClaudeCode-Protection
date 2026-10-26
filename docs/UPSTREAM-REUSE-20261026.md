# 固定来源复用审查与取舍

日期：2026-10-26（America/New_York）。四个仓库均通过只读GitHub连接重新读取实际源码、根许可证和依赖声明；没有运行安装器、下载发布二进制、安装依赖或复制账号资料。源码快照保存在本次工作目录的work/convergence/upstream，外部原文不混入产品源码。

## 固定版本与结论

| 来源/固定提交 | 实际用途与边界 | 许可、成本与决定 |
|---|---|---|
| [YOURSJEYO/claude-switcher](https://github.com/YOURSJEYO/claude-switcher/tree/383f927aaf821afd4151115d9ea0be83212826db) | Windows实现面向Desktop，按客户端/TUN轮询，按名称停止Claude；安装器会改时区、禁全局IPv6并写Clash配置。SECURITY明确进程急停存在轮询窗口，Windows README标Beta。 | [MIT](https://github.com/YOURSJEYO/claude-switcher/blob/383f927aaf821afd4151115d9ea0be83212826db/LICENSE)。参考启动前检查分类、失败可见性和更新权限分层；不导入保镖、安装器、账号快照或其无泄漏声明。沿用原MIT来源记录，不新增运行依赖。 |
| [nyxon-tech/claude-switcher](https://github.com/nyxon-tech/claude-switcher/tree/53b7e535cd51e78b205c2510c7eb6f9a2e86ed46) | 主要是Desktop账号/会话管理。源码journal在变更前记备份，以临时文件发布；plan/doctor区分读操作和修改。Windows启动/进程识别不是CLI进程树网络隔离。 | [MIT](https://github.com/nyxon-tech/claude-switcher/blob/53b7e535cd51e78b205c2510c7eb6f9a2e86ed46/LICENSE)。Go 1.26.7及终端UI依赖不适合引入现有.NET/WPF。采用计划→备份→执行→回执思路；不照搬可能覆盖后续编辑的通用Undo或在线自更新。 |
| [realiti4/claude-swap](https://github.com/realiti4/claude-swap/tree/042a36b673d51f4bf990b04f903aee02f1ab07e1) | Claude Code账号/额度切换；fsutil是独立原子写叶模块，含Windows共享冲突重试及明确持久性限制；locking和poll_policy分别处理并发与额度轮询。不是WFP/Kill-Switch实现。 | [MIT](https://github.com/realiti4/claude-swap/blob/042a36b673d51f4bf990b04f903aee02f1ab07e1/LICENSE)。Python>=3.12，含Textual/truststore/Windows keyring。借鉴同目录临时文件、刷盘和发布边界，直接使用既有.NET标准库实现；不引入OAuth、凭据迁移、Python运行时或把权限拒绝自动重试当AV兼容方案。 |
| [微软WFPSampler](https://github.com/microsoft/Windows-driver-samples/tree/a3ca26ddd1e69d2d8c9fc77cc96931545713bf20/network/trans/WFPSampler) | 原生WFP样例含CLI、服务、RPC、驱动、代理服务和用户态helper。事务helper明确处理Begin/Commit/Abort；RPC样例检查本地调用、接口和认证级别。 | 根许可为[MS-PL](https://github.com/microsoft/Windows-driver-samples/blob/a3ca26ddd1e69d2d8c9fc77cc96931545713bf20/LICENSE)，不是MIT。直接使用Windows已有WFP API并参考生命周期/错误处理，不整体移植样例、MIDL/WDK/驱动安装链或宽泛清理接口。未复制实现片段；以后若移植需保留对应来源/许可，不能当无条件可分发的产品SDK。 |

元数据中的活跃时间只辅助判断维护状态；没有把stars、README安全描述、上游测试数量或样例身份当本机验收。上述固定快照不自动更新到新的main。

## 直接影响当前工程的决定

1. **先修已接线的维护链。** GUI→日常CLI→三个代理字段维护已经有调用点；备份/报告原先依赖可执行目录，安装到ProgramFiles后普通用户不能正常写。现改到当前用户LocalApplicationData中的私有目录，CLI和GUI共享一个58行实现，初始ACL使用.NET现成API；没有另造存储框架、迁移旧证据或修改全局代理。
2. **复用标准组件而非跨语言整包。** JSON、ACL、文件流、同目录发布和Win32 Job/WFP直接使用.NET/Windows已有能力；不为几项基础操作引入Go/Python/驱动栈。上游通用原子写方案不替代本机权限、断电或并发验收。
3. **保留本项目更窄的权限和恢复边界。** 不采用按进程名批量终止、全局IPv6/时区修改、账号凭据交换、盲目覆盖式Undo、符号链接跟随或宽泛WFP清理。RPC的本地性/加密检查也不能单独替代本项目的调用者授权和固定管理操作。
4. **停止外围横向扩展。** 暂停新增未接线的代理审核协议/类和更多恢复状态格式。先完成无产物类型检查、用户维护切片、整体构建入口规划和受限生产调用链；真实构建/运行仍由原安全许可约束。

## 可核对的实现位置

- YOURSJEYO：[Windows保镖](https://github.com/YOURSJEYO/claude-switcher/blob/383f927aaf821afd4151115d9ea0be83212826db/windows/claude-bodyguard.ps1)、[安装器](https://github.com/YOURSJEYO/claude-switcher/blob/383f927aaf821afd4151115d9ea0be83212826db/windows/install.ps1)、[安全边界](https://github.com/YOURSJEYO/claude-switcher/blob/383f927aaf821afd4151115d9ea0be83212826db/SECURITY.md)。
- nyxon：[journal](https://github.com/nyxon-tech/claude-switcher/blob/53b7e535cd51e78b205c2510c7eb6f9a2e86ed46/internal/store/journal.go)、[plan](https://github.com/nyxon-tech/claude-switcher/blob/53b7e535cd51e78b205c2510c7eb6f9a2e86ed46/internal/ops/plan.go)、[依赖](https://github.com/nyxon-tech/claude-switcher/blob/53b7e535cd51e78b205c2510c7eb6f9a2e86ed46/go.mod)。
- realiti4：[fsutil](https://github.com/realiti4/claude-swap/blob/042a36b673d51f4bf990b04f903aee02f1ab07e1/src/claude_swap/fsutil.py)、[locking](https://github.com/realiti4/claude-swap/blob/042a36b673d51f4bf990b04f903aee02f1ab07e1/src/claude_swap/locking.py)、[依赖](https://github.com/realiti4/claude-swap/blob/042a36b673d51f4bf990b04f903aee02f1ab07e1/pyproject.toml)。
- 微软：[事务helper](https://github.com/microsoft/Windows-driver-samples/blob/a3ca26ddd1e69d2d8c9fc77cc96931545713bf20/network/trans/WFPSampler/lib/HelperFunctions_FwpmTransaction.cpp)、[RPC回调](https://github.com/microsoft/Windows-driver-samples/blob/a3ca26ddd1e69d2d8c9fc77cc96931545713bf20/network/trans/WFPSampler/svc/Framework_RPCServerInterface.cpp)、[样例组成](https://github.com/microsoft/Windows-driver-samples/blob/a3ca26ddd1e69d2d8c9fc77cc96931545713bf20/network/trans/WFPSampler/README.md)。

本轮为源码/许可/依赖审查，未运行四个上游项目的测试或安装流程，也未因此授予本项目BUILD、VERIFIED或DELIVERABLE。
