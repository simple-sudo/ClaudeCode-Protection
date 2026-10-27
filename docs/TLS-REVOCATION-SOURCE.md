# 固定HTTPS资格的进程内吊销数据补充

日期2026-10-27。当前SOURCE/BUILD/原生负向及固定已安装HTTPS调用链均已取得限定证据，详见[四阶段网络资格](NETWORK-QUALIFICATION-20261027.md)。此契约仍只针对固定Microsoft资格程序，不是通用代理产品授权。

## 已有实际依据

26719a网络请求24ea1a4ee5f24e27a2dd69aada09319b中，宿主/隔离子进程同一4证书SHA链；host严格HTTPS200/链状态0，child代理TCP成功，但Microsoft TLS RSA Root G2等中间链状态64/16777216，leaf状态0。固定CRL分发点已实际观察，不是根据任意证书URL自动开放。

## 实现与限度

沿用HttpClient默认证书链/名称/时间/用途/签名验证与CheckCertificateRevocationList=true。原链完全合格直接通过。仅原错误精确为ChainErrors且全部错误位只有RevocationStatusUnknown/OfflineRevocation时，固定Microsoft资格入口允许补充吊销数据；名称错误、未知根、过期、已吊销、缺对象及其他未知错误拒绝。

修正只适用于https://www.microsoft.com/资格请求、实际4证书链以及编译进源的3个issuer SHA256和对应精确CRL地址。通过127.0.0.1:7890显式代理请求编译地址，不请求证书中其他URL、不用系统默认凭据/cookie、不跟重定向；每项3秒、1MiB上限。当前固定分区/CA会变化，变化即拒绝并重新审查，不能当作多目标/多CA通用交付。

每份数据通过Windows原生API在进程内验证：CRL解析、精确issuer签名、当前时间、证书适用范围、直接查询当前CRL中证书是否列为吊销；再用独立memory store与显式issuer执行CertVerifyRevocation(CACHE_ONLY)。三份全部合格且原chain没有其他错误才接受。保留原OS错误与新数据摘要/字节/API结果，不能把原FAIL改写为原OS检查通过。没有信任根导入、全局代理/AV修改、磁盘CRL缓存预热或不受限网络放行。

[CryptVerifyCertificateSignatureEx](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptverifycertificatesignatureex)检查签名；[CertVerifyRevocation](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certverifyrevocation)和[显式hCrlStore](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_revocation_para)提供原生吊销检查。HTTP CRL传输本身不授予信任，签名/有效期/issuer/范围/吊销全部需要通过。

## 独立资格与产品余项

先用随机自有CA/leaf及内存CRL测有效、已吊销、过期、篡改签名、错误issuer、畸形数据；RSA私钥只在当前进程内，未写文件/证书库，不调用网络。此只证明native原语，不是自签CA进入系统信任。还需检查TLS错误位拒绝及真实隔离内请求/恢复完整规则/Job/豁免清理。

该修正解决当前自有.NET资格程序的吊销数据路径，不自动改变Git/Python/Node/Claude的TLS栈；完整开发工具兼容与可信正式门禁仍需各自接通。原始FlClash端口仍为固定资格用途，代理转向本地管理资源的保密问题尚未解决。不能以本功能代替受限代理出口、故障/控制器崩溃、Watchdog、DNS服务归属、IPv6物理出口和完整生命周期验收。
