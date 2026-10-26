# 管理组件首次离线构建：具体范围

此动作尚未执行，须新的明确范围授权；不是再次申请或重用已完成的日常CLI S1。依据AGENTS.md，S1已消耗且不授权其他项目。常规Build/Assert/cmd停止入口及空包批准pin保持。

- 唯一构建入口：`src/ProtectionBroker/ProtectionBroker.csproj`，其唯一ProjectReference为`src/ProtectionLifecycle/ProtectionLifecycle.csproj`。两项目共21份C#、2份csproj及4份嵌入JSON；没有包、自定义任务/目标/导入或工程/native/日常/GUI编译输入。
- 固定当前提交和逐文件摘要；SDK8.0.422、引用包8.0.28，执行前复核输入、父级覆盖、工具、可取得的AV状态及新异常。当前五项目非生成类型检查通过，SDK/引用168项摘要与S1工具基线一致；这不是完整SDK任务签名闭包。
- 普通权限，在原checkout的唯一新目录`work/broker-offline-build`生成工件，不复制工程。用固定SDK锁、显式本地空源NuGet配置离线恢复，再执行一次Release/no-restore构建图；允许唯一库依赖随该图生成，不运行产物。
- 使用SDK内置ArtifactsPath/IncludeProjectNameInArtifactsPaths，让两个项目的obj/bin分别落到新目录，避免共用project.assets.json。已只读检查SDK的默认路径实现；尚未以MSBuild执行该图。
- 关闭共享编译、遥测、工作负载更新、NuGet审计、用户通配符/父级构建导入和SDK分析诊断；引用包内置生成器须纳入实际输入记录，不声称构建没有生成器。展开导入只允许该SDK及两个已核对项目，遇外部来源即停止。
- 记录预处理/restore/build退出码、完整原日志和每个新EXE/DLL/依赖/运行配置/嵌入输入摘要。失败保留；不回退公网源、不安装依赖、不恢复旧样本、不改名规避。新告警、来源异常或无法解释的安全风险立即停止。

本次**不包含**：任何新旧程序/DLL执行或项目程序集加载、quarantine动作、Job/进程创建或终止、WFP/防火墙/代理/AV修改、安装、publish、打包、提权/UAC、GUI/工程/native/日常CLI重建、真实Claude启动、推送。没有自动授予“构建成功后运行”；后续安全资格必须匹配实际动作。

构建即使成功，也仅能授予这两个组件的BUILD；不能证明本机WFP ABI/阻断、Job故障、即时断网、重启恢复或完整保护链。工件不会被复制到安装目录或正常启动路径。
