# 2026-10-25 浏览器代理故障与恢复

## 用户可见故障

用户在临时隔离实验之后报告 Edge 的 Google、ChatGPT 页面显示 `ERR_PROXY_CONNECTION_FAILED`。本轮网络实验随即停止，优先排查并恢复日常网络。用户随后明确确认“已恢复正常访问”，并提供已加载 ChatGPT 界面的截图。

## 直接观察

- FlClashCore PID 26148 仍在监听 127.0.0.1:7890；FlClash TUN Up。
- 127.0.0.1:8888 无监听；显式连接该代理失败。
- 故障开始排查时，系统代理 `ProxyServer` 指向 `http=127.0.0.1:8888;https=127.0.0.1:8888`。
- 显式通过 7890 访问 Google 成功，TLS 校验保持开启。
- 探针进程/常规临时规则均为零；现有 Claude 两条规则仍禁用。WFP 测试报告验证其四个过滤器及子层已删除；临时回环例外、目录授权及配置的清理记录为 PASS。

## 第一次修复不完整

第一次仅备份并修改普通注册表代理值，再通知 WinINet 更新。其后 .NET 系统代理测试通过，但用户的 Edge 仍报错。这不能作为浏览器恢复证明。

进一步读取标准 API 后得到：WinHttpGetIEProxyConfigForCurrentUser 已返回 7890，而 InternetQueryOption(INTERNET_OPTION_PER_CONNECTION_OPTION) 仍返回 8888。普通配置和每连接配置不一致。

随后再次备份每连接配置，通过 InternetSetOptionW 的每连接代理接口仅同步代理服务器为 7890，并保留原连接标志、绕过配置及其他设置。两种 API 回读都返回 7890。WinINet 使用预配置代理的无认证请求得到：Google 302、Cloudflare 200、ChatGPT 403。403 只证明已收到站点响应，不是账号或浏览器访问资格结论。最终恢复由用户刷新后的确认和截图证明。

## 归因边界

此前实验未采集系统普通代理与每连接代理的共同基线，因此不能确定最早由哪个程序、在何时把端口设置为 8888。现有项目测试源代码中未发现设置系统 ProxyServer/ProxyEnable 的操作；这也不能替代完整的变更来源证据。不得直接宣称故障与实验绝无关系。

第一次恢复遗漏每连接配置，是本次处置的不完整步骤，不能用后续恢复覆盖这一事实。

## 后续实验的约束

在继续网络实验前，必须以只读方式同时采集普通注册表、WinHTTP IE 配置、WinINet 每连接配置；不一致或不是已经验证的 FlClash 入口时拒绝启动实验。每个隔离工作进程运行期间监测该基线，漂移时终止自己所属的实验进程并清理本轮临时项，不擅自重写系统设置。

实际的每连接修复脚本仅用于这次已发生的故障恢复，不作为正常测试或守护程序的自动修改功能。

浏览器自动控制在恢复期间因无法可靠识别当前浏览器 URL 被安全机制中止，之后未继续操作浏览器，页面恢复由用户确认。

原始恢复前备份保存在本聊天工作目录的 work/ 中，原工程与网络实验失败记录保留。

依据：[Microsoft 设置与读取 Internet 选项](https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options)、[每连接选项结构](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_option_listw)。
