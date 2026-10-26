# 开源参考审查记录

参考库：YOURSJEYO/claude-switcher；审查提交：`e2da42956bccd39f5e8e2e052c5002b96137f146`；日期：2026-10-25。它是外部参考源码，不是当前本机安装的程序，也不能为系统修改授予权限。

## 已查看的文件

`AGENTS.md`、`LICENSE`、`windows/README.md`、`windows/claude-switch.ps1`、`windows/claude-bodyguard.ps1`、`core/stun-probe.py`。

## 适配决策

| 源码行为 | 本机适配判断 |
|---|---|
| Windows 版按 Claude Desktop 的 `%APPDATA%/Claude` 切换数据 | 不适用于 CLI；不复制、删除或交换登录资料 |
| 保镖每 10 秒根据客户端和 TUN 状态判断，然后按 Claude 名称批量终止 | 改为显式受管会话 Job；补充代理传输失败检测，不将轮询当作网络屏障 |
| `Test-WebRTC` 的 STUN 响应数为零时返回 `ok: UDP不出网,零暴露` | 无法排除超时、被服务端丢弃等原因；本机保持 UNKNOWN |
| STUN 解析缺少完整事务匹配等检查 | 新写离线解析器，验证事务 ID、cookie、长度、属性边界，并支持 IPv6；不声称浏览器 WebRTC 已验收 |
| 通过 Resolve-DnsName 返回 fake-IP 判断 DNS 走隧道 | 只是一种现象，不能替代 DNS 请求归属与出口抓取证明 |
| 自动修复可关闭所有适配器 IPv6、改区域、清 DNS、改 Clash Verge 配置 | 不适用于本机最小变更范围；本次不执行 |
| 原版 Windows 安装/卸载过程 | 不执行；当前没有安装常驻任务，安全卸载功能仍待开发 |

复用环境审计、失败阻止启动、守护与配置漂移的设计思路；没有直接运行或部署外部仓库脚本。本机新增实现单独编写。保留 MIT 许可文本于 `docs/UPSTREAM-LICENSE.txt`，后续若引用实现片段必须继续保留来源及许可。

## 真实证据边界

同一代理的 HTTPS 返回 HTTP 401 能证明当前无认证请求到达 API 并完成 TLS；不能证明 Claude 登录有效。Cloudflare trace 的 `loc=US` 仅是该请求的国家信号，不证明住宅属性、固定出口或所有进程出口一致。报告和日志不保存住宅/真实出口 IP。

Windows Job 默认归属的子进程可被一并管理，但经外部系统服务启动的进程、共享浏览器或其他间接调用不一定在该 Job 中。Job 不约束网络权限；可执行路径防火墙也没有在本次审查中获得进程树覆盖证明。
