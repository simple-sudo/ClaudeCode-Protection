# WFP 探针恢复协议 schema 2

日期：2026-10-25。状态：SOURCE_IMPLEMENTED_NOT_COMPILED；仅用于专用探针，不是生产安装资格。未重新执行告警对象或综合 selftest。微软说明用户态对象使用 GUID，filterId 是 BFE 分配的 LUID；本协议据此采用稳定 GUID。见 [对象管理](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)、[过滤器结构](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0)、[GetByKey](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltergetbykey0)。

## 记录与操作

新记录具有 SchemaVersion=2、32 位小写十六进制 Run、Persistent/Dynamic、SublayerKey，以及按下列固定次序排列的 Filters。每项含 Role、Key、ObservedId。ObservedId 只作当次观测，不参与任何 schema 2 恢复。

| 角色 | 完整期望条件（均另有精确 package SID = 探针 SID） |
|---|---|
| ipv4-address | ALE_AUTH_CONNECT_V4；remote address != uint32 127.0.0.1 |
| ipv4-port | ALE_AUTH_CONNECT_V4；remote port != uint16 7890 |
| ipv4-protocol | ALE_AUTH_CONNECT_V4；protocol != uint8 TCP(6) |
| ipv6-deny | ALE_AUTH_CONNECT_V6；仅 package 条件，阻断全部 connect，含回环 |
| proxy-failure | 仅故障阶段；ALE_AUTH_CONNECT_V4，仅 package 条件，阻断该探针代理路径 |

每条动作 Block、显式 UINT64_MAX 权重、指定持久标志，无 provider/context；显示名包含 Run 与角色。子层也包含 Run，核对标志、权重和 provider。健康检查要求各角色完整、条件数和类型精确，不接受额外或重复条件、disabled 标志或仅数量相同。源码对 BFE 返回表示形式采用严格比对，可能安全拒绝；实际兼容性待编译和本机验收。

native 协议：`inspect|block-proxy|cleanup RUN SUBLAYER_GUID KEY_ADDRESS KEY_PORT KEY_PROTOCOL KEY_IPV6`。cleanup 可多一个 KEY_PROXY；其余两操作只接受四个角色。PowerShell 先校验 schema、Run、持久状态、角色顺序、非空/不重复 GUID，再传固定参数，无通配搜索或编号回退。native 独立拒绝空/重复 GUID，并按 GUID 读写。

## 写入顺序与故障边界

1. 为子层与四过滤器生成 GUID，在任何 Add 前写 BEFORE_ADD。
2. 同一 WFP 写事务内添加子层和四角色；写 BEFORE_COMMIT，然后 commit，再写 READY。
3. 故障第五条：在同一写事务内先重新核对四角色语义；生成第五 GUID，写 PROXY_FAILURE_BEFORE_ADD，随后 Add、写 BEFORE_COMMIT、commit、写已阻断记录。
4. 记录通过同目录新临时文件、FlushFileBuffers 和 MoveFileEx replacement 发布，避免直接截断恢复日志。此过程不建立管理员可信目录，也不承诺断电/磁盘故障后的全链路持久性。
5. commit 前中断由事务 abort 保持无部分提交；commit 后即使 ready 写失败，预先记录的全部 GUID 仍可用于精确清理。缺失对象可作为幂等清理中的不存在处理；读取错误不当不存在。

清理在同一写事务内先核对所有对象的 GUID、package SID、子层及精确 Run/角色名，然后按 key 删除。健康与清理所有权分开：策略条件漂移不再被当健康，但仍可在精确所有权成立时清理。子层仍被其他过滤器引用时删除失败，事务回滚，不能用部分删除标成功。清理后在只读事务中查精确对象是否不存在；访问/RPC/其他读取错误保持失败/未知。

inspect 在只读事务中核对四条；block-proxy 在同一写事务核对与添加。控制器退出的报告新增 PolicySemanticsVerified 与 HealthyRoles；上层不能仅凭 Present/Persistent 数量给 PASS。

## 旧编号记录

无版本、仅 FilterIds 的旧记录不能由新 inspect/block-proxy 使用，不能自动改写为 schema 2 或回填 GUID。新协议失败绝不回退旧编号。

仅显式 `cleanup-legacy-ids` 接受四/五个旧编号；纯参数验证器另要求 LegacyCleanup 选项。在同一写事务内按旧 ID 读取当前对象、转为 key、核对旧包 SID/子层/Block/网络层和旧名称，再全量删除；任一外来对象拒绝，全部回滚。日志独立标记 LEGACY_IDS_CLEANUP_ONLY、GuidRecoveryQualified=false。该兼容路径只服务历史清理，不能证明跨重启身份稳定或保护健康。旧记录及失败原样保留。

## 证据等级与剩余验证

PowerShell 纯协议输入测试覆盖有效记录、五角色边界、重复/空/错 GUID、错 Run、角色缺失/漂移、schema 混用、持久状态类型、编号回退拒绝、旧编号非法值。它不调用 native、WFP 或网络。

C++ 尚未编译；必须后续覆盖：四角色逐项漂移/额外条件/disabled 的拒绝，归属正确但语义错误的精确清理，外来对象拒绝且零删除，重复清理，初始/第五条各提交窗口失败，记录写失败，控制器退出及第五条恢复，完整本机范围的实际阻断。不能停止本机 BFE 或重启来替代规划；尚无 BFE/系统重启实证。持久策略也不能推导为启动早期屏障已合格。

当前管理员脚本、helper、manifest 和 journal 仍在用户可写项目路径；参数验证与哈希是证据，不能防同用户替换。正式生命周期必须先建立可信代码/状态和固定操作协议。旧停止入口继续保留。
