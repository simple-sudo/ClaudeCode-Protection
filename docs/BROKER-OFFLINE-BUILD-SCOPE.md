# 管理组件首次离线构建：具体范围

2026-10-26用户已明确答复“授权这一次离线构建”，并完成以下限定动作；不是重用已完成的日常CLI S1。管理组件此次独立授权现已消耗。常规Build/Assert/cmd停止入口及空包批准pin保持。

- 唯一构建入口：`src/ProtectionBroker/ProtectionBroker.csproj`，其唯一ProjectReference为`src/ProtectionLifecycle/ProtectionLifecycle.csproj`。两项目共21份C#、2份csproj及4份嵌入JSON；没有包、自定义任务/目标/导入或工程/native/日常/GUI编译输入。
- 固定当前提交和逐文件摘要；SDK8.0.422、引用包8.0.28，执行前复核输入、父级覆盖、工具、可取得的AV状态及新异常。当前五项目非生成类型检查通过，SDK/引用168项摘要与S1工具基线一致；这不是完整SDK任务签名闭包。
- 普通权限，在原checkout的唯一新目录`work/broker-offline-build`生成工件，不复制工程。用固定SDK锁、显式本地空源NuGet配置离线恢复，再执行一次Release/no-restore构建图；允许唯一库依赖随该图生成，不运行产物。
- 使用SDK内置ArtifactsPath/IncludeProjectNameInArtifactsPaths，让两个项目的obj/bin分别落到新目录，避免共用project.assets.json。执行前检查SDK实现，并实际求值核对两项目路径均落于指定目录。
- 关闭共享编译、遥测、工作负载更新、NuGet审计、用户通配符/父级构建导入和SDK分析诊断；引用包内置生成器须纳入实际输入记录，不声称构建没有生成器。展开导入只允许该SDK及两个已核对项目，遇外部来源即停止。
- 记录预处理/restore/build退出码、完整原日志和每个新EXE/DLL/依赖/运行配置/嵌入输入摘要。失败保留；不回退公网源、不安装依赖、不恢复旧样本、不改名规避。新告警、来源异常或无法解释的安全风险立即停止。

本次**不包含**：任何新旧项目程序/DLL执行或项目程序集加载、quarantine动作、产品Job/进程创建或终止、WFP/防火墙/代理/AV修改、安装、publish、打包、提权/UAC、GUI/工程/native/日常CLI重建、真实Claude启动、推送。没有自动授予“构建成功后运行”；后续安全资格必须匹配实际动作。

## 实际结果：BUILD，不含运行资格

源码提交`8a9c4b13711598187cde8845794f24d455ea0004`，27项实际输入逐一与提交blob核对并记录SHA，构建期间持有只读共享文件句柄防止改写。21份C#、2项目、4嵌入JSON；SDK/引用及4项原始保留文件复核一致。一次固定入口`scripts/Invoke-BrokerOfflineBuild.ps1`未修改任何原停止脚本，拒绝重复目录、不同提交、不同图或外部输入。

09:56:01–09:56:14 EDT，离线恢复及唯一Release构建图均退出0；0错误、0警告。两个Csc调用，分别生成生命周期库和管理入口；引用库副本与独立库摘要一致。restore前后分别展开两项目导入，恢复后各89项，仅固定SDK、当前项目与各自SDK生成的NuGet props/targets。资产表无第三方包；6个引用包内置生成器另记摘要。构建子进程使用最小环境白名单和独立CLI home，不继承令牌/服务设置，禁用首次证书生成、全局工具PATH添加、共享编译及重用节点。原始SDK日志保留，未向Git加入日志或产物。

| 实际产物 | SHA-256 |
|---|---|
| ProtectionBroker.exe | `B86187957A19EE03F56C9B35BCB0161EB6BE203725AD564EAE18FAD37D50F344` |
| ProtectionBroker.dll | `494BDC1BF8FF281305C8A09CAC68EDBDE7CBA71866D88CADBF08C747FC2C1F90` |
| ProtectionLifecycle.dll | `1C32A76B6C068D35B07C1AD44CFC5BD367C5F7D6043D0A892E5AC4E2873BB27B` |

以PEReader读取新产物元数据，不加载/执行项目程序集：四个实际嵌入协议名及原始字节SHA均与源JSON一致；两程序集的模块初始化方法为0；未包含旧SelfTests/隔离实验/NativeJob工程类型。这里只是工件静态身份核对，类型静态构造、P/Invoke、策略读取器和管理动作均未执行。

原日志、退出码、27输入、全部产物摘要、导入前后清单、路径求值和元数据核对位于本项目忽略目录`work/broker-offline-build`。前后卡巴斯基服务/注册状态和BFE运行，真实两规则禁用，FlClash/Core PID不变；有限Application观察未见新AV事件，完整厂商告警覆盖仍UNKNOWN。4项原始文件及既有S2工件不改写。

本次只授予两个组件在该提交的BUILD，不授予运行INTEGRATED/VERIFIED或DELIVERABLE。WFP ABI/阻断、Job故障、即时断网、重启恢复、可信安装与完整保护链仍未证明。没有运行程序、加载项目程序集、安装、提权、创建/停止产品进程或修改网络/AV；新工件不复制到正常安装/启动路径。历史失败及UNKNOWN保持。
