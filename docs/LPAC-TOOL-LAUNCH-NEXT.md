# LPAC工具启动：具体修复及系统验证范围

2026-10-30。本轮开始时本地与远端开发分支均为e101ad8；后续仅本地提交，未推送。

## 实际阻碍与修复

人工授权/UAC的trace7确认：LPAC worker调用NtCreateUserProcess成功后，Windows在NtOpenKey(KEY_READ)打开固定系统SideBySide键时返回C0000022，导致SxS消息构造失败和CreateProcessW错误5。不是PreferExternalManifest值查询失败或安全软件归因。当前键DACL允许AAP及registryRead，不允许ARP/本安装包。原始证据在work/create-process-trace-installed-r7；原Job正常关闭归零，四项根拒绝通过，工具未成功。

原ProtectedSession资源所有者增加SessionManifestReadAccess。在根已绑定原Job且仍挂起时，为当前包SID给以下固定64位键增加一条KEY_READ、无继承ACE：

`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide`

这允许读取该键自身的值、直接子键名称及安全信息，不能写值/权限，不能据此读取子键的值，不增加registryRead或其他capability，不给AAP/ARP通用访问，不改变LPAC或工具令牌。这个宿主系统权限变更需要本人明确授权。

原Broker先保存保护意图并核对原权限，运行期持有并检查该键；只有同一Job持久关闭/零成员后才恢复完整原权限。外部权限漂移不合并、不覆盖。未完成记录阻止后续新会话和安装维护；显式恢复入口仍要求闭合准入及完整隔离。中断不能保证自动恢复，强杀owner不作为Job关闭证明。

56输入离线构建、生产DACL策略、真实生产安全读写函数在唯一普通HKCU空样本中的精确授予/恢复，以及普通调用维护入口被拒均通过。57输入Bootstrap构建复用完全相同的已资格库，未重建库。20文件/10PE/6managed及内嵌清单匹配。以上不是宿主键授予、LPAC工具运行或中断恢复成功。

## 待本人授权的两个具体操作

1. 一次本人UAC：work/manifest-read-control/install-launch.ps1将下方候选更新为INACTIVE，然后只读检查无待处理manifest读取资源。不创建Job/profile，不授予宿主键权限。
2. 安装及普通回读确认后，第二次本人UAC：同目录run-launch.ps1只运行原安装Broker的qualify-toolchain一次，验证固定离线PowerShell/Git、工作区及原拒绝样本、Job关闭和上述键权限精确恢复。产品原所有者临时授予该键读取；helper独立比较前后权限。无调试器、输入项目代码、网络开放或自动重试/恢复。主期限40秒；未完成时，只结束本次新建并持有句柄、映像/创建时刻匹配的确切Broker，不结束其他进程，不编造Job或清理证明。

| 冻结输入 | 标识或SHA256 |
|---|---|
| 新Release | 0c1613f0c6a4447b83af3814b4d267d6 |
| 新manifest | 850D193EFB259C819B215333A5F7D60D49BFE5C8456957587C84424EEFB81C69 |
| Lifecycle库 | C858806499789388E4E3F09A262F9630924AA89967761C8B066FAF253DB39F1A |
| 安装plan | D97D67B41C7ACC80034526A206EECE54C64596CAD785F656654A2BB2AAECEEBB |
| 安装helper | 17B198A919C49D7BB0558236499068A9C65484653FDA6D3DA17AE27295BB05C9 |
| 运行plan | 7AC5A0AC256E72E8EDCF0C9414B0464E9B19CA4F6FC04096A55A4C1704148D92 |
| 运行helper | 8BBDC597CFFF0615FF65722E30AA6122856E3D90BC50C202F2F7FD5BA84F61B6 |

普通持有文件预检和脚本语法检查完成，完整审查在work/manifest-read-control/system-operation-review.json。新安装/运行尚未授权或执行；此前b4194629安装保留。日常AV/驱动/全机ACL/网络/FlClash/UU保持，真实Claude延期；新能力不能冒充整体隐私、网络、14项准入或GPU验收。
