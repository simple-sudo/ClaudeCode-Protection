# 固定 AFD 参数解析对照

只用于定位端点创建障碍，不授予网络或启动权限。
复用 `DeviceBoundary/NativeBoundary.cs` 的固定 x64 NtCreateFile 路径：
`\Device\Afd\Endpoint`、access C0140000、share3、disposition3、options0、EA57。
三项依次为原 IPv4/TCP 输入、family35、packet flags2；无 Socket/IOCTL/连接或安全写入。

匹配本机 afd.sys F93639BB… 与公开 PDB 8FC962E7… 的离线分析：
family>=35 在 RVA1562B/1562E 转入无效参数分支；flags2 在 RVA1559A/155A0
转入无效参数分支。两者均位于本路径的 AfdAllocateEndpoint 调用之前。
普通用户已实测原输入成功、两个对照 C000000D。驱动变化后须重新确认分支与普通参考。
该差异可以帮助区分参数解析前后的阻碍，不能独自证明实际内核执行路径或唯一拒绝组件。

构建和普通参考不代表真实 LPAC、Job/WFP、Socket、HTTPS 或 L3 通过。
本程序拒绝管理员；真实 LPAC 对照仅能在另行固定并获具体批准的原 owner 链内执行。
结果必须使用全新绝对路径。原生失败时不认领输出句柄，也不将 IO_STATUS_BLOCK 的
默认零值当成功。原有五项矩阵仍可独立使用，其历史证据字节不变。
