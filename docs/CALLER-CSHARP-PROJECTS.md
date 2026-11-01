# 显式用户 C# 项目开发入口

当前SOURCE / INTEGRATED，六产品非执行语义检查通过；尚未构建、安装或运行新入口。
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
