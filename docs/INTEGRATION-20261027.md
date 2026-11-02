# GitHub 两批成果的本机整合

> 文档效力（2026-11-02）：历史GitHub整合记录。PR头、CI、fetch和合并状态均限当次观察；本轮不联网重验或推送。不要按旧接收步骤覆盖本地改动或重新合并。
> 最新状态/授权只见[CURRENT-STATE](CURRENT-STATE.md)，正式目标与术语见[SECURITY-REQUIREMENTS](SECURITY-REQUIREMENTS.md)。以下旧状态与操作许可不自动延续。

日期：2026-10-27。类型：工程交付记录；状态：本轮源码接收完成，完整产品未交付。
适用范围：本轮本地分支；原始 CI、安装和运行证据独立保留。

后续阶段已接入会话所有者与受限转发源码，当前状态转见[保护会话主链](PROTECTED-SESSION-CHAIN.md)
和CURRENT-STATE。本页的PR接收/资格窗口为历史，不给新代码转授BUILD或运行证据。

## 接收决定与实际调用链

起点 main/8e5b4ee，工作区干净，origin/main 相同。保留用户 README、历史与远端配置；
在 codex/integrate-privacy-admission-20261027 整合两个分支，未推送或合并远端 PR。

- [PR #1](https://github.com/simple-sudo/ClaudeCode-Protection/pull/1)，头 eb2300e：保留首次恢复前单一挂起进程的严格准入；采用固定 Watchdog canary 的恢复后至多一个 conhost 限制。补充进程句柄持有至判定、存活检查、重复 PID 拒绝及主进程创建时间绑定；额外进程时间不得早于主进程。不是任意工具链准入或蓝屏修复。进入现有 qualify-watchdog 调用链。
- [PR #2](https://github.com/simple-sudo/ClaudeCode-Protection/pull/2)，头 950836b：采用十四项非权威报告、精确 HTTPS 诊断目标和共享目的地候选判据；修复其未覆盖的 Engineering 项目缺失引用，GUI 检查改用 preflight 并补命令白名单。补未来/非完整时间戳、null DNS、带 scope 的 IPv6、2001::/23 与 3fff::/20、字面目标和所选 IP 不一致的拒绝。诊断不自动重定向、不用默认凭据，显式开启吊销检查；新增时区/地区检查不再凭开发机固定目标授予 PASS。
- 十四项目录供 daily 与 Broker 共用。Broker 的 `launch` 核验安装宿主后，明确返回全部当前会话可信采集缺失及额外系统安全缺口，不接受调用者报告、目标或脚本，不启动进程，也不转入合成资格程序。此时无正向许可签发能力；不能称完整十四项强制许可链已交付。daily `launch` 仍明确延期且拒绝附加参数。

## 验证与证据边界

原 [PR #1 CI](https://github.com/simple-sudo/ClaudeCode-Protection/actions/runs/40480675575) 仅 Broker/Lifecycle 编译；
原 [PR #2 CI](https://github.com/simple-sudo/ClaudeCode-Protection/actions/runs/40480813906) 仅纯托管用例及 daily 编译。
本轮已实时核对成功状态和对应头；不覆盖本机新增补丁或 Engineering/GUI。

本机非生成检查保留 outputs/pr1-integration-source-types.json、pr2-integration-source-types.json
（Engineering 缺引用原失败）、pr2-integration-corrected-source-types.json、broker-admission-integration-source-types.json。
最后六项目 0 错误/0 警告；无 emit、MSBuild、还原、产品程序集加载或 native 调用。
新增安全负向用例已写入 PolicySmoke；其本轮执行结果尚待实际记录。

历史接续曾明确重开系统测试，而非由 CI 推导许可，准备过原转储的限定分析：
work/crash-analysis-20261027-reopened；原 dump SHA256
C38F6F02C3CEEBC6FD2A9628C76E2D671D0C8D855E6AAD5997291989D3A1FC92，7030648 字节。
微软 debugger 的既有 12 文件闭包重新核验、只读原转储、120 秒/1 GiB/8 MiB 日志预算，
不附加进程、不运行产品、不启用符号服务器或源代码服务器。启动需要人工 UAC；等待不等于已经分析。

## 本次重新接收与后续修复

接续起点为既有整合分支 `587ef08`，工作区干净；没有重新建立分支、工作树或项目副本。
重新 fetch 后 origin/main 仍为 `8e5b4ee`，两个 PR 头仍分别为 `eb2300e` / `950836b`，
均 open/draft/unmerged；本轮不执行 GitHub 合并、推送或 CI 派发。
GitHub MCP 重新核对原运行号：PR #1 的 Broker/Lifecycle compile、PR #2 的纯托管测试
及 daily compile 均 success；它们不覆盖本机后续整合补丁。

用户本次第五节明确保留系统运行测试阻断，优先于上述历史重新授权。没有启动调试器、
产品、网络测试或 UAC，没有修改 AV、FlClash、系统网络、安装或私有状态。
Broker 的五个 `qualify-*` 系统入口在权限/安装读取/native 操作前拒绝，Bootstrap 的
install/update 同样提前拒绝。只读诊断与精确 quarantine 恢复代码独立保留，未执行。
已装旧字节未被改写；入口源码阻断不能冒充已有安装包受到新限制。

GUI 原来仅输出预检 JSON，现已接入十四项中文状态与逐项处理说明。共享正式 ID 目录，
整份报告先验证唯一 ID、schema、来源/逐项时间、严格必要性与非权威标志，缺失、重复、
伪造许可或异常状态整份拒绝显示正向结果。独立核对两分钟时效和未来时间；窗口每15秒
只重绘时效，不重复 worker/网络请求；配置维护结果不会被该重绘覆盖。
FAIL 即使过期仍保留；原始报告保存机制保持，报告显示不授予启动许可。

新增 PolicySmoke 的实际 GUI 格式化器负向用例，包含旧 PASS、未来证据、重复 JSON 属性、
缺项/重复项、伪造授权与必需项降级。本机只做非生成语义核对，不编译/执行该测试程序集；
后续云端执行也须以准确提交和结果记录为准，当前不能标通过。

## 下一项产品缺口与停止条件

当前只限制自有诊断请求。正式受保护身份仍不能直接得到原始 FlClash 通道作为通用出口；
必须落实工具自有转发执行边界、可信解析/字面 IP 连接、回绕管理接口拒绝及不可绕过的 WFP 路径。
IPv6 的特殊网段依据 [IANA 注册表](https://www.iana.org/assignments/iana-ipv6-special-registry/)，
当前候选策略保守拒绝整个特殊用途 2001::/23，不能声称囊括所有公网危险服务。

十四项还缺当前会话可信采集、明确用户环境策略、安装/策略/目标/工作区/工具授权绑定、
单次创建及首次恢复前复核、运行失效撤销；日志和旧 PASS 不得补位。
敏感文件/注册表/进程/工具子进程、DNS 服务代理与真实出口等仍需各自证据。
不再为这些 UNKNOWN 增加平行执行器；先在已有所有者内完成可测试的单条生产切片。
没有事故归因或新系统测试结果时不宣称已修复蓝屏。真实 Claude 保持 DEFERRED_BY_USER。
