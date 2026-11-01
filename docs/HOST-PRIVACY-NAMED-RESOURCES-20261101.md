# 真实命名资源访问门

2026-11-01后续：用户明确确认卡巴斯基误报并要求改变实现，不再反复归因。
打包已改为只读取PE资源/元数据，不在打包进程内载入/调用产品代码。00bcd9b7/60EC9056候选
已暂存，复用精确5600CD36；独立普通fixture核对原生产纯迁移门、基线及策略摘要，与实际候选
数据匹配。ED3DDCB2基线逐字节保留，隐私策略18AC844D。无新产品构建、真实宿主探测或UAC。
首次fixture nullable编译失败保留，独立r2修正通过。Bootstrap/完整候选审查与具体系统步骤尚待完成；
当前安装14ea仍未变化。后文入口拒绝是历史过程，不是当前没有进展。

当前是新源码，尚未安装或实测真实宿主资源。现有14ea8f9c项目成功继续复用，不重跑其独立Git或编译资格。
本功能接在同一普通客户端 -> 原Broker -> 原Job/LPAC worker/编译工具 -> 成功清理导出链中。
两名受限执行者必须分别完成固定资源的原生访问检查；任一OPENED、缺失、共享冲突、未知、目标漂移
或缺失工具报告都不能释放本次项目结果。正式准入及AllHostResourceIsolationQualified仍为false。

最终dca7afa/86输入离线构建和六普通模式通过，库5600CD36。原生自身文件夹具实测最小ReadData
允许/拒绝、元数据可读、缺失2、DACL精确恢复/内容不变；自身进程仅句柄/等待对象，不读内存。
契约用例证明缺失工具、OPENED/UNKNOWN/混淆schema不能成功，合成报告不是实际LPAC证明。
证据work/host-privacy-r3-build-20261101/qualification.json SHA2B690C76。
旧8d7/D8B911D6候选已在Bootstrap/UAC前废弃，保留但不运行。r3暂存脚本的工具进程创建两次
报AccessDenied5，短只读入口间歇恢复；未改权限/AV或换执行路线，未创建r3候选/Bootstrap/系统控制。
实际安装仍14ea/F415392F/334E9AA8，新具体人工系统决定尚无可批准的冻结候选，不提前请求。

## 固定清单

所有路径由原owner为本机固定catalogue解析，不接受CLI/工作区包传入的宿主路径。
只查看了真实目录/文件存在性及应用安装元数据，没有读取真实配置、凭据或标识值来生成样本。

| 角色 | 固定目标 | 请求 |
|---|---|---|
| flclash-config-json | Roaming/com.follow/clash/config.json | FILE_READ_DATA |
| flclash-config-yaml | 同目录config.yaml | FILE_READ_DATA |
| flclash-preferences | 同目录shared_preferences.json | FILE_READ_DATA |
| uu-user-settings | Local/GameViewer/setting.ini | FILE_READ_DATA |
| uu-user-configures | 同目录configures_info.ini | FILE_READ_DATA |
| uu-system-user | ProgramData/Netease/GameViewer/user_info.ini | FILE_READ_DATA |
| uu-system-assist | 同目录remote_assist_code.ini | FILE_READ_DATA |
| private-claude-settings | 当前真人Profile/.claude/settings.json | FILE_READ_DATA |
| private-git-config | 当前真人Profile/.gitconfig | FILE_READ_DATA |
| device-machine-guid | HKLM64/SOFTWARE/Microsoft/Cryptography | KEY_QUERY_VALUE |
| proxy-user-key | HKU64/当前真人SID/Software/Microsoft/Windows/CurrentVersion/Internet Settings | KEY_QUERY_VALUE |
| flclash-ui-memory | 精确E:/program/FlClash/FlClash.exe现存单进程 | PROCESS_VM_READ |
| flclash-core-memory | 同目录FlClashCore.exe现存单进程 | PROCESS_VM_READ |
| uu-service-memory | 精确E:/program/uu/GameViewer/GameViewerService.exe现存单进程 | PROCESS_VM_READ |

14个资源角色与“十四项环境准入”是不同清单，不能互相代替。注册表选择真实HKU真人路径，
不把AppContainer虚拟HKCU里的不存在误当成宿主代理配置拒绝。

## 操作与证据

文件只申请FILE_READ_DATA=1，使用OVERLAPPED避免把同步句柄的额外权限拒绝误称为数据读取拒绝；
共享READ/WRITE/DELETE，立即关闭，不调用ReadFile。注册表只Open/Close，不Query/Enum值；
进程只Open/Close VM_READ，不ReadProcessMemory。明确返回5才是ACCESS_DENIED，0为OPENED，
其他原生值为UNKNOWN。相关权限含义见微软[文件访问权限](https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants)、
[CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)、
[RegOpenKeyExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw)及
[进程访问权限](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)。

原owner先做存在性/元数据/当前映像正控制：文件无重解析、原文件ID，注册表键Open成功，
宿主进程唯一且映像精确，持有QUERY_LIMITED_INFORMATION|SYNCHRONIZE非继承句柄，
零等待观察原对象为未退出；不把可能也是程序退出码的259当作独立存活证明。无秘密内容hash。
计划绑定session/installation/release和摘要，原任务目录持有只读文件；没有高权限句柄传给开发侧。
关闭原Job后、项目结果释放前，原owner再核对当前目标文件ID/存在性和所持进程仍存活，
然后核对root PID与已在原Job中持有核验后放行的compiler PID、各14项观察。
元数据句柄使用共享删除，不阻碍正常软件轮换配置；轮换使身份变化时本次失败，不更改或恢复宿主文件。

资源计划升级为显式v5并必须有HostPrivacySHA256；v3 DATA不变且不能选择此任务。
项目管道回复v5必须有绑定原session/plan/两actor的完整拒绝摘要才能成功，旧v4不满足新的门。
失败可以保留root-only或明确OPENED/UNKNOWN的脱敏观察，不把它们变成PASS或准入。
导出的摘要只有固定角色、操作种类、状态、错误码、PID及上下文摘要，没有宿主绝对路径、
配置字节、认证材料、注册表值、物理标识或进程内存。

本次源码仍仅接受精确TextSummary输入，没有任意调用者项目代码授权。检查数据文件不是
未来任意恶意代码的独立可信证明：任意项目接入前还须把观察发布收紧到同一原owner的
不可伪造阶段与通道，不能让任意项目伪造自身检查报告。当前固定编译程序和固定输入绑定保留。
这些观察是一次有界任务中的命名对象访问结果，不是所有未来访问或所有宿主信息不可见的证明。
MAC/BSSID、其他设备API、COM/WMI、管理接口、所有配置/历史文件、强制网络与GPU均仍需补齐。

新系统操作必须先完成离线构建/普通自身非秘密fixture、具体候选与冻结控制，再取得人工UAC决定。
真实配置/键/宿主进程探测尚未运行；不改它们的ACL/权限，不启用调试权限，不读秘密、不关软件或AV。
