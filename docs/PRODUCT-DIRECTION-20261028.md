# 从固定工具资格走向日常开发

> 2026-10-28阶段方向，保留当时数据切片与授权边界。现行目标与优先级见
> [SECURITY-REQUIREMENTS](SECURITY-REQUIREMENTS.md)，最新实现/安装/授权见[CURRENT-STATE](CURRENT-STATE.md)。
> 下文“本次/当前/下一步”不是今天的待执行计划；DATA无代码边界不因后来v6项目能力而取消。

2026-10-28用户续开发要求。本次继续原安装程序→Broker→ProtectedSession→AppContainer/Job/WFP→授权工作区/工具→监督/恢复链；不另建执行器、VM或默认CPU-only路线。

第一梯队与强制网络隔离同为P0：真实网络/位置/设备标识、物理MAC/BSSID、代理凭据、FlClash及UU远程敏感配置/认证/历史。保护对象是资源访问，不是PowerShell命令名；必须以Python/Git/原生程序等替代接口检验。第二梯队独立保护宿主画像，尽可能减少软件安装、运行及痕迹暴露；不承诺绝对隐藏，不引入内核Hook/rootkit。禁止读取真实秘密来制造测试样本，采用非秘密控制样本及只返回是否暴露的有界探测。

AppContainer是资源边界，但不能从低完整性、无网络能力或几个拒绝样本推导全部只读宿主信息不可见。[微软说明](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)明确只读文件访问较宽。LPAC可取消ALL_APPLICATION_PACKAGES带来的访问资格，属于同一创建链的候选加固；需要逐项检查工具、运行时、注册表/COM与NVIDIA兼容，不在本次无证据切换。[原生创建与LPAC说明](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)。

## 特权执行的实现约束

不永久排除必要管理员操作。选定方向是在现有Broker内提供具体的资源操作，绑定会话、工件、目标对象身份、最小操作集、时限与恢复记录；开发进程保持受限身份，不能提交任意管理员命令、脚本、路径或继承高权限句柄。工作区字节应先由普通用户导出，Broker不得充当按调用者路径读取宿主文件的代理。涉及安装脚本、MSBuild自定义Target、包管理hook等任意代码的任务，不能因为名称为“安装/编译”就提升权限。

首次安装/确有系统影响的变更仍由本人确认UAC；一次UAC只授权固定Broker操作，不能成为高权限shell或永久许可。日常任务不要求逐命令人工审查，权限在OS资源层约束。任意宿主管理员脚本与可靠宿主隐私隔离不能同时承诺：[微软边界标准](https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria)不把UAC或NT管理员到内核作为独立安全边界。当前没有通用特权开发操作实现，不把设计记为VERIFIED。

## 本次生产切片

优先补上项目字节进出通道：普通用户显式选择源文件→有界数据包→现有自有任务目录→原Git链→Job归零后结果快照/原输入摘要绑定。包内无绝对宿主路径，不携带.git、宿主Git配置或凭据，不扩展宿主ACL；不解释/执行包内源代码。具体用法与限制见[工作区传输](WORKSPACE-TRANSFER.md)。这是实际项目接入所需的数据面，不是正式会话许可。下一步在同一所有者中接可信工作区授权和编译/测试能力，不能用固定资格入口运行任意项目。

继续并行目标：现有网关实机矩阵、14项Broker可信准入、第一梯队各资源拒绝、原生NVIDIA计算及控制器崩溃/重启恢复。FlClash、UU、AV、驱动和全机网络保持，不自动推送；真实Claude登录/推理/会话仍延期。每项按具体字节与范围记录，可靠旧证据保留且不无故重做。
