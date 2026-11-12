# 当前状态（权威摘要）

更新时间：2026-11-12。本文只保留当前可用的状态摘要；历史快照已归档至 [CURRENT-STATE-HISTORY-20261112](CURRENT-STATE-HISTORY-20261112.md)。开发过程和能力证据分别见 [STATUS](STATUS.md) 与 [PROJECT-ACCEPTANCE](PROJECT-ACCEPTANCE.md)。

## 1. GitHub 与开发基线

| 项目 | 当前事实 |
|---|---|
| 仓库 | simple-sudo/ClaudeCode-Protection |
| 可见性 | Public |
| 默认分支 | main |
| 当前线上开发分支 | chatgpt/complete-git-workflow-20261110 |
| 本次文档整理前 HEAD | 36ad1b20848fd056c1f034113b8831d7fc6b0c99 |
| 产品源码最近修订 | 2c3fb1646cf64da0817d777215d4efbf9ad4db1b（移除 Git ACL 失败诊断中的原始 SID/ACE 字符串） |
| PR | #3，OPEN / DRAFT |
| PR 目标分支 | codex/integrate-privacy-admission-20261027 |
| PR 目标基线 | 8d56b0c40ef92d384b572bb168eec6bcd8a44d4e |

本次文档变更只更新当前线上开发分支，不合并 PR #3，不推进 main，不改变仓库设置或可见性。

## 2. 最新云端验证

在文档整理前的 HEAD 36ad1b20848fd056c1f034113b8831d7fc6b0c99 上，以下三组 GitHub Actions 均为 SUCCESS：

- [Hosted Windows compile only](https://github.com/simple-sudo/ClaudeCode-Protection/actions/runs/43182143806)
- [Safe managed policy smoke](https://github.com/simple-sudo/ClaudeCode-Protection/actions/runs/43182143786)
- [Offline workspace Git workflow verification](https://github.com/simple-sudo/ClaudeCode-Protection/actions/runs/43182143869)

最新测试提交 36ad1b2 澄清了 NativeGitLpacAccessCases 测试夹具的本机 elevated Windows 运行边界。CI 成功只证明这些工作流所执行的编译和测试范围，不等于产品 Broker、Owned Job、LPAC 完整链或真实 Claude 会话已通过。

## 3. 已有证据与未证明范围

已有局部证据包括：产品/测试项目托管编译、标准用户 Runner Git 工作流、Git 对象和回执独立核验、生产目录描述符在真实 NTFS fixture 上的权限/继承验证、限定任务目录恢复状态机测试，以及若干受限网络/代理资格源码和回归。

以下仍不得标记为完整产品交付：

- 产品 Broker → Owned Job → LPAC 的 schema 2 多命令完整执行链及真实 token 访问边界。
- 产品实际创建工作区的完整端到端时序、持久状态、崩溃/取消/超时与恢复。
- 真实 Claude Code 在完整受保护会话中的启动、工具调用、网络、文件访问和关闭验收。
- 全机公网 IPv4/IPv6 强制代理、DNS/UDP/QUIC、代理端点动态租约和故障窗口零直连。
- UU 远程所有公网传输路径均经指定代理的证明。
- 全部 P0 宿主敏感信息隔离、跨来源画像与数据外传验收。
- 保留 GPU 计算能力同时隔离 GPU 稳定个体身份的完整验收。

产品常规 Build 入口的 SECURITY_REVIEW_REQUIRED 硬停止仍有效。本次文档工作没有绕过该门禁，也没有在用户主机上编译、安装、提权或运行产品。

## 4. 2026-11-12 网络架构更新

正式网络目标已从“Claude 进程专属防直连 + 用户临时控制全机 IPv6”升级为：

**用户明确启用 Protection 网络模式期间，全机所有应用和 Windows 服务的公网流量必须经过指定 FlClash 美国住宅代理。**

- FlClash TUN/Global 负责接管和选择代理路径；不是最终强制安全边界。
- Windows WFP/可信网络所有者必须阻断物理网卡上的未授权公网直连。
- IPv4、IPv6、TCP、UDP、DNS、DoH、DoT、QUIC 等分别验证；不支持代理的协议阻断，不允许 DIRECT 回退。
- 代理、TUN、端点或策略异常时保持 fail-closed。
- Claude 本机敏感资源隔离和数据外传审计仍是独立 P0。
- UU 远程在 FlClash Global 美国代理开启时能够正常使用，是用户观察到的应用兼容性证据；并未证明 UU 的全部 TCP/UDP/P2P/中继流量均经过代理。

**状态：REQUIREMENT_ONLY / DESIGN。** 当前固定 SessionProxy、WFP 身份规则、FlClash 身份核验和路由快照只是局部基础，不是全机网络模式的产品实现。规范见 [NETWORK-SCOPE](NETWORK-SCOPE.md) 和 [PROTECTED-STARTUP-SHUTDOWN-LIFECYCLE-V1](PROTECTED-STARTUP-SHUTDOWN-LIFECYCLE-V1.md)。

## 5. 公开仓库状态与资料边界

仓库当前为 Public。当前基线未发现根目录 LICENSE；公开可见不等于已授予开源复用许可。历史文档部分形成于私有研发阶段，可能包含本机路径、对象摘要或个人环境上下文。本次文档重组不构成完整的公开历史、PR、Actions 日志或 Artifacts 审计。

新文档不得加入真实公网 IP、MAC/BSSID、SSID、设备 UUID/序列号、个人路径、代理订阅、认证令牌或原始连接/崩溃日志。若需要清除已经进入公开历史的真实秘密或个人标识，必须另行制定凭据轮换、历史重写和缓存/Artifacts 清理方案；仅删除当前文件不足以清除历史。

## 6. 下一步开发重点

1. 先完成全机 TUN/WFP 正确分层、FlClash Core 与代理端点绑定、DNS 引导和 fail-closed 的底层可行性审计。
2. 实现全机公网出口强制代理的最小可验证切片，先用自研测试程序和受控接收端证明无直连。
3. 把 UU 远程纳入全机代理兼容性实测，不增加未经验证的直连例外。
4. 继续完成 Claude 本机敏感信息隔离、真实内容 L3 对抗实验和数据外传审计。
5. 将网络模式、Claude 会话、Job/LPAC、安装、退出和恢复统一到原可信 Owner 生命周期。
6. 每个可独立验证的能力尽早安排实机测试；云端能完成的编译和自动化回归由 CI 自主完成。

本摘要只记录截至上述基线的已知事实。文档整理提交本身不改变产品实现状态或实机授权。
