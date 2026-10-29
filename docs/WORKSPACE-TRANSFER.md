# 授权工作区数据传输

已安装入口`workspace-process BASE_BUNDLE NEW_RESULT_BUNDLE`：普通用户daily先核对并持有安装资产、创建新的输出文件，然后请求本人UAC启动同版本固定Broker。仅本人SID可访问的本地管道传入确切数据字节；双方核对内核进程PID，Broker还核对普通调用者映像及本人SID。复用原ProcessWorkspaceData/ProtectedSession，成功闭Job与精确清理后再导出绑定原包的成果。没有特权宿主路径、脚本、任意命令或通用提升入口。取消/失败保留新建的空/部分输出供检查，不能覆盖已有结果。ac570b47已实测四份本仓库文件的pack→process→review→extract完整往返；仅process请求UAC，其余日常维护始终普通用户。v2失败回执仅返回固定阶段/异常类型/错误码及可选会话编号，不返回原始异常消息或私有路径，不自动重试。

daily命令必须普通用户运行。2026-10-29当前安装ac570b47 / INACTIVE；完整工件与证据边界见STATUS。

`workspace-pack ROOT SELECTION_JSON NEW_BUNDLE`从明确指定的本地NTFS项目根读取清单中的文件，将内容、相对路径与SHA256写入一个新数据包。清单是JSON字符串数组，例如`["README.md","src/main.py","tests/test_main.py"]`。没有目录递归/通配符或默认全项目扫描；未选择文件不会进入包。输出父目录必须已存在；已存在输出拒绝覆盖。终端只返回包摘要与文件数量，不打印项目内容、宿主绝对路径或环境变量。

`workspace-review BASE_BUNDLE RESULT_BUNDLE`核对每个文件摘要及结果的BaseSHA256，列出ADD/MODIFY/DELETE及前后摘要。绑定的是原始输入包的确切字节；其他项目或重新编码的包不能借用。只比较，不自动应用、删除或覆盖用户原项目。包是未加密源数据，显式选择不等于秘密识别/脱敏；不要把含凭据的文件加入清单。

v1上限：512文件、每文件1MiB、总内容8MiB、序列化12MiB、相对路径160字符/12层。保留二进制和空文件；不保留ACL、文件时间、可执行模式、空目录或Git历史。当前相对文件名限ASCII字母/数字、空格、点、下划线和连字符；拒绝设备别名、尾点/空格、ADS、绝对路径、穿越、.git、大小写别名、文件/目录冲突及未知/重复JSON字段。边界超限明确失败，不偷偷遗漏文件。

实际I/O逐级打开并持有目录与文件句柄，核对固定本地NTFS、最终路径、对象类型、无重解析点及文件单链接；源文件拒绝并发写/删除共享。输出仅CREATE_NEW，不改宿主ACL。材料化仅在原任务所有者持有的根下新建项目目录及文件，拒绝已有目录接管。不提供“管理员按任意宿主路径打包”的入口。

原`qualify-toolchain`使用同一包格式和材料化实现准备嵌套三文件项目，仍只执行编译在工件中的离线Git命令，不接收项目/脚本/命令参数。管理侧独立核对全部blob/tree/commit与固定身份，原Job停止归零且完整隔离后快照工作树，跳过根.git元数据，结果绑定私有输入账本；成功才清理原任务目录。固定包结果当前受私有账本128KiB上限约束；任意大项目仍需同一所有者的持久成果存储/授权交付，不扩大安全账本限制。

数据包不是签名、身份凭据、正式准入或管理员授权；哈希只绑定内容。新增命令不执行项目代码，不授予通用会话、网络、设备或GPU权限。固定Git包的源码接线、普通用户传输实测及新安装受限运行分别记账，互不代替。

当前已实测：普通用户明确选择本仓库四份源码/文档，安装daily交给原AppContainer/Job链完成固定Git提交、对象核对、闭Job结果快照和精确清理，成果经过同一受验证Broker返回，比较/提取及独立逐文件摘要匹配。原固定三文件/52项清理是较早独立证据，保留在STATUS；不借用其计数描述本次任务。入口已接收显式选择的数据包，但不能执行输入项目代码；编译/测试工具链与全面隐私资格仍需继续推进。

开发中新增数据操作（构建/实机状态以STATUS为准）：已安装Broker在现有提升上下文中接受`process-workspace-data EXACT_INPUT_SHA256`，标准输入只接原始数据包字节，15秒/12MiB封顶，不接受宿主文件路径、可执行目标、命令或脚本。SHA256表达对这些具体输入字节的选择，不授予项目代码执行。沿原任务所有者执行固定离线Git init/add/commit，对所有对象独立核验、关闭Job归零后快照/精确清理，成功终态后方可`export-workspace-data SESSION EXACT_RESULT_SHA256`把原始结果包输出到stdout。失败/未完成结果拒绝导出；存储数据与小型安全回执分开，原包/结果字节留在管理员私有state，不自动清除原证据。

普通用户`workspace-extract BASE_BUNDLE RESULT_BUNDLE NEW_DIRECTORY`先比较确切原包绑定，然后只创建全新目录及文件；不合并既有树、不写回原项目、不删除文件。原JSON包无BOM；通过标准输入时须保留字节，不用会改编码/换行的文本管道。结果导出应定向到用户自己选择的新包文件，stdout包含源数据，仅在主动导出时输出。

真实项目的.gitattributes及.gitignore作为文件保留，但数据处理固定在.git/info/attributes中取消text/filter/ident/working-tree-encoding转换，Git add --force仅作用显式清单，使二进制/CRLF与被忽略的已选文件完整进入独立对象核对。依据：[Git属性优先级](https://git-scm.com/docs/gitattributes)、[Git显式强制添加](https://git-scm.com/docs/git-add)。不执行项目hooks、filter、MSBuild或测试。该入口是数据维护，不是正式会话或完整隐私资格的替代入口。
