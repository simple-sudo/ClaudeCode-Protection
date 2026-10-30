# 下一次LPAC实机验证：原受限宿主的PowerShell策略上下文

当前安装df6ae4f0/manifestD2CABD45，INACTIVE。最近真实会话1c66ab54中的PowerShell已明确以System.Security.SecurityException失败。用户确认的项目异常弹窗与截图保留；原Job正常关闭归零、Stop无失败、根I/O/四拒绝5通过、宿主注册表权限不变，但PowerShell/Git/编译未完成。

一次独立本人授权的只读操作已于08:39:38Z读取原唯一错误记录：1127字节，SHA256=DE28838672394EE1A633EA50C1C19B261C05F3BD17DC725CBFEE5C0AE0C62409。调用栈为RegistryKey.OpenSubKey → Utils.GetPolicySettingFromGPOImpl → GetConfigurationNameFromGroupPolicy → ConsoleHost.ParseCommandLine，错误在脚本执行之前。证据work/tool-error-read-control/evidence；原记录未改，无重跑或额外系统操作。该只读授权已消耗。

## 已实施和普通限定资格

PowerShell原生CLI无条件先读GPO，JSON设置不能替代。[官方7.4.22策略读取源码](https://github.com/PowerShell/PowerShell/blob/v7.4.22/src/System.Management.Automation/engine/Utils.cs)证实这一顺序。新源复用同一安装Broker镜像作为受限PowerShell托管入口，保留原Broker创建、LPAC/零能力包、原Job、对象权限、固定参数/清洁环境、标准流、监督/成果/清理路径；未创建另一服务或executor。

原所有者对12个固定PowerShell GPO/旧fallback键，在64位HKCU/HKLM都必须实际观察不存在，并在资源监督/创建/工具工作门复核。存在、读取失败或变化即拒绝，不读取并丢弃现有策略，不把UNKNOWN当无策略。当前先支持无这些键的环境；已存在策略的类型化快照尚不支持。确认实际不存在后，受限入口在精确固定7.4.22引擎（SMA7.4.6.500、逐项摘要固定）的私有GPO缓存填14个负结果；JSON配置回退保留。缓存字段/键映射/版本不匹配即拒绝，不启用测试钩子、不改厂商字节、不增加宿主注册表读取或capability。

普通实际托管运行通过：固定I/O、两个自有非敏感ACL拒绝、同一官方Roslyn/参考程序集的C#编译及加载运行7+5=12，退出0、无错误输出；普通直接受限入口拒绝。62输入构建及63输入Bootstrap通过，Bootstrap未重建资格库C846DB6B，20文件/10PE/6managed/内嵌manifest匹配，无新增本机导入。证据work/hosted-policy-build-r2/qualification.json。原超时、测试错误收尾及Add-Type缺少入口ref目录的失败保留；测试已捕获异常退出，不制造故障弹窗。Add-Type -TypeDefinition通用托管引用布局仍未支持，本次自有编译使用真实相同Roslyn和固定ref，不声称整个开发工具兼容完成。普通资格不是LPAC证明。

## 待本人授权的两个操作

1. 一次本人UAC：更新新包6e2cf8cd为INACTIVE，仅做只读manifest资源检查；原552工具文件不修改、不新建工具目录、不建Job/profile，不改宿主注册表/权限。
2. 更新并独立核对15文件后，再一次本人UAC：一轮原Broker严格LPAC托管PowerShell/固定Roslyn自有编译/离线Git验证。没有输入项目代码、网络、真实Claude或管理员开发进程；40秒主期限、1秒排空；异常仅停止本次确切新owner，不自动重试/恢复。若运行失败且原Broker回执确认原Job已闭合归零、准入关闭、完整隔离、Stop无错误，同一helper才可只读本次新会话的唯一resource-tool-error记录（最多32768字节）到同一受保护结果目录；不读其他私有文件，源不改，以免为同一故障再增加一次UAC。宿主SideBySide完整权限独立比较必须完全不变。

| 冻结输入 | 标识或SHA256 |
|---|---|
| 新Release | 6e2cf8cd8808409bb0b80693f7f9339c |
| 新manifest | 6AAE651E3AFA2D592E02F70A8097048EFA7106F563FD96A766AD1A5208F2E0DA |
| Lifecycle库 | C846DB6BA60732607FC84C9E361815B1C861EC842697D4C52622F0900CE01725 |
| 安装plan | F229133E1B943113798CC95A18FC6E349F3ED41EF22030AD0493A33B14AD52CC |
| 安装helper | A8438D9EB31591A68F3FF81B8FC8BFC73FD6614447C6A437D08535F8624211F8 |
| 运行plan | DFFE1E456DBA5679A7805974F4A1353588A89839560650D87D30DF364125C44E |
| 运行helper | CACABDCBA59A792B3C3553621F3B0C6D06E77858B2FECED1FB2336FA7F3B7634 |

完整审查work/hosted-policy-r2-control/system-operation-review.json。两个launcher预检实际返回、未知参数拒绝、无本次UAC/claim。按用户指示与AGENTS.md，新安装及资源调用需要具体授权、本人UAC；两操作尚未授权或执行。保持日常AV/驱动/UU/FlClash/网络及全部旧证据。全面宿主隐私/网络/14项/GPU/正式项目仍未整体验收。
