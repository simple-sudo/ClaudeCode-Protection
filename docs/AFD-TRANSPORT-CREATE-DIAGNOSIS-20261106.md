# AFD传输层创建拒绝：已实测边界与后续方向

最新安装、授权和整体缺口以[CURRENT-STATE](CURRENT-STATE.md)为准。本文不签发安装、
trace、权限变化或Claude许可；后续方向可按新证据调整，不是必须逐项执行的清单。

## 真实观察与解释边界

固定5D5CD38F…实验沿现装610b原daily/owner/LPAC/Job完成三请求，原owner封存后执行，
正常闭合才释放11文件。实际capability0、low、package access mask2、两项自身权限
及128字节默认DACL前后完全相同。自身pseudo handle时间查询成功，没有OpenProcess、
Token/设备ACL写入、IOCTL、bind/connect/CUDA/Claude或网络转发。

输入5DB5E7AF…、结果CC92D106…、独立核验EF51C3DD…；原Token/actor/时间原值留
work/afd-call-correlation-20261106-01/candidate-r4及新外部结果目录，不进入Git。
观察器自己的trace/GUID/进程句柄闭合、Stop0、Token保持通过；ETL BA20FCB7…原位
保留。数据流中实际读取1983记录，其中1982为AFD event1000，未见其他AFD事件ID；
4条记录同时匹配原owner封存ToolPid、header/payload PID、native TID和各次精确时窗。

| 请求 | 真实事件 | 真实NT返回 | 有限解释 |
| --- | --- | --- | --- |
| 有效IPv4/TCP | location1006/enter0/status0；随后1013/exit1/C0000022 | C0000022 | 已经过endpoint分配，传输层端点创建完成路径报告拒绝 |
| family35负标记 | location1003/enter0/C000000D | C000000D | 同一actor的独立参数拒绝正控制 |
| flags2负标记 | location1001/enter0/C000000D | C000000D | 同一actor的另一早期拒绝正控制 |

离线工具只读取匹配SHA256 F93639BB…的afd.sys数据，不加载/修改驱动。匹配微软PDB
标出AfdCreate RVA15480在156FE成功分配后发1006；AfdCompleteTLEndpCreate RVA54C0
在54F0发1013，读取IRP status并无条件记录，因此1013名称必须为“完成”而非泛称失败。
调用点包括15AEE及TL回调2FFE0。实际拒绝状态由事件本身提供，不能只从函数名推断。

这将后续排查收敛到传输层创建/完成路径，不再优先盲测全机AFD设备ACL或默认DACL。
但最终是TCPIP访问检查、检查层/WFP、compartment、其他策略还是其他组件，仍UNKNOWN。
没有Socket/HTTPS通过，普通网络可用不能推导受限网络可用。

## 覆盖及解析限制

16MiB circular的BuffersWritten=261，三项lost=0但存在绕卷可能，完整覆盖UNKNOWN。
四条已实际留存事件是正向证据；缺失事件、其他分支没有出现不能算未执行证明。
不能用部分时间窗或选中记录宣称全机无网络旁路或完整L3。

原只读reader二次解析PowerShell已转换的UTC DateTime，丢失Kind/小数秒并加入当地
时差，造成误拒绝。保留原冻结文件，在同一数据/身份/哈希/实际时窗门下纠正只读解析；
不扩大输入或改变系统。首次文本替换未生效，临时测试未Stop而产生的不可信Passed4
已用invalidated记录明确作废，原文件保留；后续严格4项检查通过。版本化C#桥补充
UTC对象/ISO-Z精度和歧义拒绝检查，最终73项普通检查、四项目BUILD0/0通过。

独立关联391D7E91…保留完整状态和有限映射，不输出kernel指针。UTC修正、映射扩展
均是普通只读分析，不是重试系统实验，不改原批准reader/review/ETL或原失败结果。

## 有价值的下一方向

本机TCPIP事件定义已只读取得，未启动新的TCPIP采集。provider2F07E2EE…、keyword
1024/部分附带1，固定1001/1010/1011/1012/1013/1562可分别提供总体完成、family未
附加、compartment不存在、inspection状态、成功和明确access denied路径。版本与
模板须按本机定义严格解析，ProcessStartKey仅作为实际字段，不自行猜测与actor创建
时间相同。若继续有限联合诊断，应优先区分这些具体路径，而非重复相同AFD三项状态。

网络capability是候选机制而非已证明根因。微软[AppContainer启动说明](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)
将网络访问与具体capability关联；[Chromium设计](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md)
也将无internetClient的lowbox用于阻止网络。两者不能唯一解释本机失败，不构成给当前
actor扩权的许可，更不能抵消P0真实内容拒绝、永久WFP/受控网关和完整工具链验证。
如未来证据支持最小网络cap或限定包的WFP机制，须复用原owner、固定新工件及人类决定，
成对检查合法功能、强制代理和真实宿主信息读取面；不默认新增registryRead、设备ACL
或不受限回退。零cap的原实验保持原结论，产品目标不被缩小成“只能离线运行”。
