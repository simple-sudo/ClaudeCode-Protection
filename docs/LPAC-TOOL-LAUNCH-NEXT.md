# LPAC工具启动：当前证据和一次必要系统观测

2026-10-30。开发分支codex/integrate-privacy-admission-20261027在本轮开始时本地/远端均为e101ad8。安装候选不变：b41946295d334034896319e3a0aeba7c，manifest F1418ECBB01AED35559B440E60BAF37C4E79C3D6133A62F331BB9B40EF062B01；当前安装选择仍由提升后的原helper在任何操作前重新核对，普通预检不能替代该检查。

## 已有实际进展

此前未提交到STATUS的trace6已将CreateProcess5定位到BasepConstructSxsCreateProcessMessage返回C0000022。这发生在NtCreateUserProcess成功之后。工作区读写、四项根拒绝、原Job关闭/零成员均有同次回执，工具仍未成功。原日志和空成果必须保留。

尚未辨明SxS函数内部的拒绝来源。当前没有支持放宽能力、宿主ACL或回退普通AppContainer的证据。本轮静态复核Windows映像只确认现有分支断点对应当前字节，不是实际内部调用成功/失败证据。

## 已准备、未执行的操作

复用work/create-process-trace7-control/trace-launch.ps1，由普通用户启动，只有本人确认UAC后才进入其固定helper。该操作：

- 重新持有并核验15个安装资产、10个调试命令文件、两个固定Windows映像和Microsoft签名调试器，并核对当前安装仍INACTIVE。
- 只运行原安装ProtectionBroker.exe qualify-toolchain一次；原所有者创建LPAC/Job，运行自有固定离线PowerShell/Git工作负载；不执行输入项目代码。
- 在SxS内部固定分支处仅记录数值失败码及固定阶段，不读取真实FlClash/UU配置或凭据，不使用全局错误入口断点。
- 调试主期限30秒，直接落盘日志，附加重定向管道排空各限1秒。正常停止继续由原Job所有者负责。若调试未完成，仅核对并终止这次新建、持有句柄的确切Broker owner；不附加或结束日常/其他既有进程，不推断Job关闭，不自动清理私有存储或重试。

这会创建一次受保护资源会话及一个新的受保护诊断输出目录，不能在没有本人的具体授权时运行。无安装更新、全机ACL/网络/AV/驱动变更、真实Claude或远程推送。

冻结输入：

| 输入 | SHA256 |
|---|---|
| trace-plan.json | 709283D8007DA0F2A196C1F0A7590494A45D12741127921928164D0EBF5FD832 |
| trace-helper.ps1 | 0727AE4EDC9805CAA6C4818707E857F38079D0E7BA5EA280DF3EB05A33CB1FBB |
| trace-launch.ps1 | 564E8E5738858148C170C57E326ED4C0795DCC19E998A62685B058A86D55B860 |

06:04:32Z普通预检持有校验通过，未触发UAC。原普通cmd/where跟踪样本已通过；它只证明脚本和新进程跟踪，不证明LPAC内部失败分支或工具兼容。完整审查/摘要在同目录qualification.json，实际操作仍NOT_RUN。

取得内部失败点后，应据实际对象和所需操作决定最小修复，并针对修复验证；不再重做没有改变的前置诊断。若没有到达所需分支，保留失败并先分析，不自动重跑。
