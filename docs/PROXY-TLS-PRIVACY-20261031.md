# 代理诊断证书验证的网络隐私修复

2026-10-31，源码 `915a48f`，开发根目录 `F:\ClaudeCode-Protection`。

`ProxyChannelLease.CheckTransport` 原来用 `HttpClientHandler.CheckCertificateRevocationList=true` 请求固定微软目标。平台建立证书链发生在观察回调之前；在线吊销检查及缺失中间证书下载可能使用系统证书网络路径。HTTP 请求设置了固定代理，并不能单独证明这些先行验证下载也经过该代理。微软说明验证回调之前就可能发生额外证书下载，并提供 `CertificateChainPolicy.DisableCertificateDownloads` 控制它：[.NET 网络实现说明](https://devblogs.microsoft.com/dotnet/dotnet-7-networking-improvements/)。本次没有抓包或重放旧请求，不声称某次历史诊断已发生实际泄漏。

修复让该实际诊断路径使用 `SocketsHttpHandler`，直接复用现有会话网关的 `SessionProxy.OfflineTls()`：`X509RevocationMode.Offline`、`DisableCertificateDownloads=true`、`VerificationFlags.NoFlag`。平台继续检查信任、名称和吊销；证据不足时仍失败。原固定显式代理127.0.0.1:7890、禁重定向、禁cookie和默认凭据保留。固定微软CRL补充仍只处理原本允许的离线/未知吊销错误，按已固定issuer/URI及原独立原生验证完成；没有改成NoCheck、宽泛忽略错误或改变系统证书存储。观察/补充回调必须来自目标名精确为www.microsoft.com的SslStream。[离线吊销模式定义](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509revocationmode?view=net-8.0)、[链策略](https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslclientauthenticationoptions.certificatechainpolicy?view=net-8.0)。

修复触及代理**诊断**路径；既有SessionProxy会话转发路径已经使用上述离线策略，现由两处复用同一工厂。没有改变网络准入、WFP规则、上游代理配置、工具权限或真实Claude延期边界。

## 已完成验证

- 六产品非生成C#语义分析0错误/警告，未冒充构建或运行。
- 新冻结63输入、普通权限、清空外部包源的离线构建完成。生产库14856075C7A4A8E3FC190BA50E94A9381BBF7AAFBAB7B936F67B21DA3F3187B7；Broker及OwnedToolLaunch同时构建通过。151个生产原生导入及测试的4个原生导入与原资格工件相同；无module initializer。
- 新 `tls-transport-policy` 模式直接调用实际生产handler构造方法。测试固定代理/无环境凭据/无重定向、回调前已设置离线吊销与禁止AIA、默认平台验证、独立策略对象，以及错误回调上下文拒绝。它未调用HTTP发送、套接字连接、CRL读取/获取或证书存储操作；没有运行其他工具、网络或原生故障测试模式。退出0、无stderr，两管道排空。
- 构建和普通fixture前后AV/BFE/FlClash/UU及boot09:36:05.5Z一致；所读Application日志无新增AV事件，厂商全部告警覆盖仍UNKNOWN。

原始记录在 `work/tls-offline-build-20261031` 的 `source-plan.json`、`receipt.json`、`tls-artifact-review.json`、`tls-runtime-review.json`、`tls-runtime-result.json`；冻结入口在 `work/tls-offline-control-20261031`。不运行或修改旧C盘冻结构建入口。

## 尚未证明的内容

当前安装仍为62eab36f/19D64CFF，未安装此源码/构建；没有新的系统权限、UAC或在线诊断运行。工厂内存测试证明构造出的实际选项，不证明该机器的实际代理路由、所有系统证书网络行为、断网/吊销服务异常、全机零旁路或完整保护验收。真实网络验证必须使用具体新工件和明确范围；缺证书/吊销缓存不允许为追求成功关闭验证。
