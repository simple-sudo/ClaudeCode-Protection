# 四阶段限定网络资格：2026-10-27

> 文档效力（2026-11-02）：2026-10-27限定网络资格记录。此版本结果可复用其范围，不能继承到其他包、真实Claude或当前网络安全状态。
> 最新状态/授权只见[CURRENT-STATE](CURRENT-STATE.md)，正式目标与术语见[SECURITY-REQUIREMENTS](SECURITY-REQUIREMENTS.md)。以下旧状态与操作许可不自动延续。

## 结果和身份

**2026-10-27当次版本INTEGRATED、限定VERIFIED：该次安装Broker的四阶段矩阵实际退出0。**这不是完整产品交付、物理出口无泄漏、真实Claude会话、系统DNS服务归属或故障恢复验收。

当次release fd4f9f85655342cebc46aab4d19982d8；manifest7EC62DE8F572CBED678616FF2E1F1A815C520463BD172E998A546CA975A7593C；生命周期DLL A8C9ACF27EC9BF1CEDAD03F9ACBBBA6C4E07C84DFC8AFE412AC0578318D1F8C1。固定INACTIVE更新operation3f63a9da217f47fdada03d298146cfce；管理图34输入/独立bootstrap35输入BUILD0，无module initializer。6项目非生成检查0错误0警告；28项既有判据、6项吊销候选拒绝、6项内存native原语通过，普通管理/子进程入口拒绝符合预期。

request ce160d0fddd4471c977c2c36080fceec；原始ProgramFiles/ClaudeCodeProtection-Network-20261027-r8，工作控制work/network-run-r8-control，私有state原始回执保留、不入Git。FlClash20944/Core14268保持，实际磁盘映像/创建时间/127.0.0.1:7890监听持有核对；没有启动/重配/停止日常代理。

## 实际矩阵

| 阶段 | 六个自有接收端 | 指定代理 | 结果 |
| --- | --- | --- | --- |
| 独立AppContainer对照 | TCP4其他端口/地址、TCP6、UDP4/6、原始UDP53各1 nonce收据 | 对照不请求外站 | 匹配 |
| 完整安装隔离 | TCP三项10013；UDP三项send可成功、独立收据均0，2秒窗口且collector健康 | 7890连接10013 | 匹配 |
| 仅编译IPv4代理开放 | TCP三项10013、UDP三项收据均0 | 7890 TCP成功；Microsoft HTTPS200；三份严格CRL检查通过 | 匹配 |
| 恢复完整隔离后的新子进程 | 六项独立收据均0 | 7890连接10013 | 匹配 |

每个子进程均在创建时绑定AppContainer/Job，首次恢复前核对Low4096/零capability/唯一Job成员、安装镜像、当前规则，报告管道绑定PID/nonce/角色。除独立对照SID之外均为安装专属SID。最终主机正向6个接收端仍各1收据、3个受保护阶段迟到nonce仍全0。UDP结论是该窗口没有投递，不是send API拒绝或全域网络证明。

## TLS修正的实际证据

保留原OS PolicyErrors4、ChainStatus64/16777216，不写成原联网吊销检查通过。新进程内补充从指定代理获取编译固定地址的CRL：leaf分区34664字节、Microsoft中间1032字节、DigiCert中间2102字节；精确issuer、签名、当前时间、适用范围、直接吊销项查询和Windows CACHE_ONLY memory-store原语均通过且释放成功，三份NativeError0，最终HTTPS200。地址/摘要/API明细在原回执。

源契约和负向见[TLS吊销设计与范围](TLS-REVOCATION-SOURCE.md)。只修复当前固定Microsoft资格程序的依赖，不自动兼容第三方TLS栈/其他CA或站点；编译issuer/分区变化会拒绝。没有关闭吊销检查、忽略其他证书错误、导入信任根、全机代理变化或任意地址放行。

前序r3–r7的失败、旧来源/成本/UNKNOWN各自保留，既有c9 GPU成功只属于原c9版本，不授新库GPU资格。

## 收尾与下一主线

最终独立只读回读6规则角色完整（filterId103002–103007、子层weight65533）。累计21登记Job的不可复用准入摘要/版本/关闭及零成员回执均逐一匹配；19个临时豁免意图均有精确SID不存在、原其他项保持回执。Profile Delete API0与独立不存在仍分开，后者UNKNOWN。最后无本轮产品测试进程；AV/BFE运行、有限Application新AV事件0，完整厂商覆盖UNKNOWN。没有真实Claude、AV变更、用户配置变更或推送。

后续必须把健康监控变成生产运行租约，并以自有代理/控制器做崩溃和规则漂移注入，证明先恢复网络屏障再准确结束所属执行、故障后的可信清理及更新/卸载。不得停止真实FlClash充当注入，也不得因某次Job名称缺失就认定零成员。系统解析器代理DNS、外部物理出口、原生宿主崩溃/重启、子工具、严格14可信门禁和敏感资源保护仍缺。完整目标保持active、未完成。
