# 显式用户 C# 项目开发入口

当前SOURCE / BUILD / INTEGRATED，六产品非执行语义检查通过，普通限定样本VERIFIED；
尚未安装或运行新受保护入口。
原00bc/60EC/5600的固定TextSummary及28次真实敏感资源拒绝继续复用，不视为本入口通过。

普通入口新增`workspace-check-csharp BASE_BUNDLE`，只检查任务；新增
`workspace-build-csharp BASE_BUNDLE NEW_RESULT_BUNDLE`，显式请求项目代码执行并由本人确认UAC。
二者都只接受普通用户已选择并打包的字节，不向提升后的Broker传宿主项目路径。
原`workspace-process`仍仅处理数据，不能从包内的文件或字段推导执行授权；原固定示例命令保留。

输入是原WorkspaceBundle，包含`cpc-project.json`、源码及可选普通数据。声明严格限定为：

- SchemaVersion=1、Kind=CSHARP_LITERAL_EDIT_BUILD_RUN_TEST_V1；1至32个明确列出的UTF8 `.cs`源文件。
- 1至32项按声明顺序应用的文字修改，每项Before必须在当时源码中精确且仅出现一次；不支持脚本或表达式。
- EntryType和TestType各声明一个不同的类型；均须提供public static int Run()。入口返回0，
  测试返回与ExpectedTests一致的1至256计数；这是项目自身测试结果，不是安全准入证明。
- 至多128个输入文件、6MiB输入内容，为原8MiB结果上限保留空间；输入不得占用`cpc-output`。

使用原固定Roslyn与引用程序集，直接编译所选源码，不运行`.csproj`、MSBuild、包恢复、
用户指定编译器、命令或宿主路径。不加载PowerShell引擎。当前不覆盖依赖包、多项目、
原生编译器、Python或异步运行入口；这些仍是完整开发环境的后续工具范围。

原Broker/原Job/严格LPAC/零capability及全隔离状态保留。v6内部计划绑定任务种类、完整输入
摘要与隐私计划，工具使用原映像与原创建通道。原owner在代码前封存root/compiler各14观察，
第二次核验成员/令牌/同一工具PID后消耗一次执行许可。v6成功回复必须包含原owner封存标记
和成对拒绝摘要，不能作为旧v3 DATA或v5固定任务接收。原20秒runtime/10秒工具等待等期限不延长。

同一受限工具修改所选源码、编译到`cpc-output/CpcProject.dll`、调用运行与测试入口；
捕获的stdout/stderr分别最多4096字符、16384 UTF8字节，恢复工具自己的控制台流后写入结果。
原Job闭合后，owner只做数据快照/PE元数据检查，不加载项目DLL；核对所有原文件的声明修改、
精确五个新增输出、结果基线、运行退出码、测试数、文本上限和原成功清理回执后才释放结果。
普通客户端还会重复核对数据内容，随后使用现有review/extract或GUI审阅/新目录提取。
不覆盖原项目，不在宿主执行导出DLL，不扩大权限来换取编译或测试成功。

完整示例在samples/CallerWordCount，三份源文件/一项修改/三个测试，与内嵌六测试示例不同。
可显式选择README、cpc-project.json、src/Counter.cs、src/Entry.cs、tests/Checks.cs作为打包清单。
它用于本轮普通新自有样本资格；当前不要求用户运行尚未安装或资格未完成的受保护入口。

本轮同时补入实际已安装60EC9056的精确inactive迁移白名单，并将普通纯转换检查更新为00bc。
这一项不代替活Job闭合、quarantine、安装审查或新的本人UAC决定；没有执行新的系统操作。
PowerShell、其他宿主资源/API、强制网络、十四可信准入、GPU、恢复和完整GUI交付仍保持开放。

## 普通验证与候选准备

source23f0374的96输入离线构建五项目0错/0警告。首次6cf49b1的产品构建成功，但新增fixture
五个局部变量与原harness外层重名，测试构建失败；原日志/来源保留，未运行测试或产品。
独立r2仅修正fixture局部变量，七个普通模式全部0/无stderr：新任务40项清单/编辑/结果/v6
检查、新v6原工具启动策略、新WordCount真实普通编译/运行/三个测试/十文件恢复、实际00bc
精确inactive转换，以及被修改解析器的原v3 DATA/v5固定项目兼容检查。未重跑原Git/LPAC/
真实宿主拒绝资格。库7DDC1FD0A2F4B8C650879DC35B58D24D81794251151D5AA9B9EF91EED43CBA69，
BrokerA7401B84、dailyA1B3EA70；158原生导入逐项不变，无模块初始化，没有加载SMA。
work/caller-csharp-r2-build-20261101/qualification.json
SHA2459F3CC5D62BD6B6ADF19103E9383015A14D51F4CB9B59DAC58CE2708103BA1。

十文件结果独立核对后保存在work/caller-csharp-ordinary-delivery-20261101，输入
9F07437B305EA7A99EDC2AA1FB08135CF9F534BE76B8B98E787D3AC821825B65；控制记录
work/caller-csharp-control-20261101/ordinary-observed-result.json
SHAC479313BDE1B5FDB69552087EFCF55CA03BEE8207A50B725D18CAA18A882392B。
只执行了冻结自有非秘密代码，没有原产品入口/Job/UAC/网络或真实宿主探测；boot/AV/BFE/
FlClash/UU前后一致。普通测试不是新LPAC、原生两阶段放行或所有用户项目的资格。

候选42f7fe36a4d24194ac9f2da0f967b289，manifest917202DE05F414EAA62803811D673CDD1A9071A3F7F08B0B188E358E57057399，
合入原已资格GUI934E826A，4资产变化/10复用。打包只读字节/元数据，不在打包进程调用产品代码。
独立普通intake仅调用实际暂存库的纯迁移、任务解析/编辑/规范序列化、隐私策略成员，确认
实际60EC→9172选择、9F07输入及全部五个原文件预期修改与数据准备逐字节一致；不是现场current
或Job检查。证据actual-staged-transition-review.json SHA87CBCB53FBB0CDF7EE2AA37CA2677EFEE11A3D18C4F189A188463239CDC1BEBC。
后续Bootstrap已完成：source978f183的106输入只构建安装器，复用精确7DDC核心与934E GUI；
完整20文件/10PE/6managed无模块初始化，内嵌9172清单匹配。实际安装仍00bc/60EC/5600。
两个持有预检/三个严格未知开关拒绝、直接提取本次runner的2正例/73拒绝通过，未触发UAC/
产品入口/私有状态读取；消费者合成检查不是实际Job或隐私证明。
work/caller-csharp-control-20261101/system-operation-review.md已冻结
SHA500D13483C1686CCF762D82A108C110B706896BA09EFB5A9229F45B501739791。
新范围为INACTIVE更新/只读检查，再一次固定WordCount源选择/打包/任务检查/原Job严格LPAC
改编运行三测试/双端真实命名检查及执行前封存/成功清理导出/普通审阅提取。只允许精确普通
客户端超时停止，不停提升开发owner、不读私有错误/原始Job/Stop、不自动重试恢复。
新v6用户项目和原生封存首次运行仍需具体两次本人UAC决定，READY不是授权或安装/实测通过。
