# 授权工作区数据传输

> 文档效力（2026-11-02）：工作区数据机制与各版本证据。旧“当前62e”等按当时解释，v3 DATA仍是无代码能力。日常Claude授权工作区不默认包括保护源码/敏感内部资料；可信维护授权另审，不由Broker任意读取宿主路径。
> 最新状态/授权只见[CURRENT-STATE](CURRENT-STATE.md)，正式目标与术语见[SECURITY-REQUIREMENTS](SECURITY-REQUIREMENTS.md)。以下旧状态与操作许可不自动延续。

## 2026-11-10/12：显式离线 Git 工作流 schema 2（托管构建、普通用户真实 Git、结果快照和对抗配置验证通过；LPAC待验收）

本节描述开发分支 `chatgpt/complete-git-workflow-20261110` 当前源码能力，不覆盖上方历史安装证据。当前已验证实现基线为 `316248272d37aa3a85ffa71b437960fbd03207cd`，Draft PR #3 保持开放且未合并；当前安装仍以[CURRENT-STATE](CURRENT-STATE.md)为准。GitHub Actions 43137292096 完成全部产品/专项测试编译并以标准用户实际执行 Git 工作流；43137292097 编译全部产品但不运行受保护代码；43137292087 通过纯托管策略 smoke 并编译 daily CLI。三组均 SUCCESS。

**证据边界：** 43137292096 的标准用户测试实际启动 Runner Git，执行 hash-object/init/add/diff-check/numstat/commit/log/status/fsck、两个私有对象拒绝对照及 Owner 独立 commit/tree/blob/ref/GitReceipt 核验。对抗样例注入仓库本地 clean filter、恶意 hooksPath 和 textconv 驱动；固定 info attributes、外置 hooksPath、`--no-ext-diff` 与 `--no-textconv` 使其不能改变文件内容或启动转换器。样本覆盖 CRLF、未终止文本、NUL 二进制、空文件、显式选择的 ignored 文件，以及首 8000 字节无 NUL、其后含 NUL 的边界。Owner 依据不可变 GitPlan 文件内容独立重算 numstat 新增/删除/二进制指标，拒绝伪造指标；再独立验证 commit/tree/blob/ref 和精确 GitReceipt 绑定。以上是 Runner 普通用户真实 Git 和 Owner 托管验证证据，不是产品 LPAC 证据。

**结果快照与 receipt：** Job 关闭后，Owner 的文件系统快照先以 schema 2 GitPlan 为基线，验证结果包的路径清单、文件数和每个文件字节完全一致，再允许附加 GitReceipt。改变任一选中文件、增加/删除文件或使用错误 baseline 均拒绝。普通用户 NTFS fixture 已覆盖精确快照正向、工作区文件篡改拒绝、篡改结果不得附加 receipt；这不是产品 Broker/LPAC 端到端验收。

Owner 在 Job 归零后独立核对 commit、tree、每个 blob、`HEAD`、`refs/heads/main` 及提交身份，再附加与精确输入包哈希绑定的 `GitReceipt`。普通 `workspace-review` 可显示提交摘要；`workspace-extract` 仍只提取项目文件，不写回原项目。

**明确边界：** 只创建全新的隔离仓库，不导入原项目的 `.git`、历史、remote、凭据或配置；结果不导出 `.git` 对象，因此此第一阶段的提交历史不会跨会话持久化。它是一次受限的初始化提交工作流，不是可替代完整 Git 客户端的任意交互式终端。项目文件和 Git 结果仍是未加密数据包；哈希是内容绑定，不是签名、准入或授权。全过程不执行项目代码、测试、MSBuild、Git hooks 或 filter，不开放网络、不启动 Claude。

包的文件数量、单文件、总内容和路径边界沿用原 workspace 限制。CommitMessage 只允许 1–160 字符、单行、无控制字符的有效 UTF-8；路径验证额外拒绝在扩展名前含空格的 DOS 设备名别名。失败不导出部分成果；原工作区、输入包和私有失败证据按原恢复流程保留。后续若需要跨会话历史，必须另行设计并审计专用 Git bundle 导入/导出，不能把 `.git` 目录直接放入普通文件包。

普通用户可先运行：

`workspace-git-pack ROOT SELECTION_JSON COMMIT_MESSAGE NEW_BUNDLE`

它只捕获显式清单中的文件，并将固定分支 `main`、单行提交说明及 UTC 提交时间写入
schema 2 的 `GitPlan`。然后运行既有入口：

`workspace-process BASE_BUNDLE NEW_RESULT_BUNDLE`

输入包仍经原普通 daily、本人 UAC、已安装 Broker、原管道、原 Owner、Job 和 LPAC
资源生命周期处理；没有新增提权入口、执行器或 IPC 命令字段。Git 计划不是命令行、
脚本或任意参数集合。

schema 2 的固定顺序为：输入摘要核对、在新目录初始化 SHA-1 `main`、按 Owner 预先
创建并持有的 NUL 路径清单执行显式 `git add --force`、带固定 `--no-ext-diff --no-textconv`
的暂存差异空白检查和 numstat、单次提交、提交元数据读取、工作树清洁检查、
`git fsck`，最后执行既有两项私有对象拒绝对照。Broker 对命令序列和参数逐项限定；不接受 clone/fetch/push/remote、任意
config、脚本、hook、filter 或宿主路径。Git 配置、环境、身份、hook 路径和对象格式
均固定；作者为 `Local Workspace <local@invalid.example>`，不读取或导入宿主 Git
身份配置。提交日期绑定数据包创建时间。

**Git 工作区 DACL 分层（源码候选，LPAC 尚未实测）：** Broker 在任务根下分别创建
`git-project` 与 `git-control`，不再把两类对象放在同一可写目录。项目目录允许指定
LPAC Package SID 读写项目文件及 Git 工作树；控制目录只允许该 Package SID 读取，
存放空全局配置、空 Hooks/Template 目录和 Owner 预建的 NUL pathspec。两者均使用
受保护 DACL、Owner=Administrators、Group=SYSTEM、继承的 OWNER RIGHTS（仅
READ_CONTROL）及低完整性标签；不授予 LPAC WRITE_DAC/WRITE_OWNER。Owner 的资源
持有检查会重新核对两个目录的实际安全描述符、控制目录精确清单、空 Hooks/Template、
空全局配置和 pathspec 长度/内容。该分层保护的是外置 Git 控制输入；仓库自身的
`.git` 元数据仍位于 LPAC 可写的 `git-project` 中，不能把外置控制目录的只读权限
误写成整个 `.git` 都只读。当前 CI 只证明描述符/fixture 逻辑和普通用户真实 Git，
真实 Broker 创建的目录 ACL 继承、LPAC token 实际读写边界仍 NOT_RUN。

Owner 在 Job 归零后独立核对 commit、tree、每个 blob、`HEAD`、`refs/heads/main`
及提交身份，并根据不可变输入重新计算 numstat 新增行、删除行和二进制文件数量，
拒绝 child 报告中的伪造指标。结果快照必须与 GitPlan 的路径清单及每个文件字节
完全一致后，才附加与精确输入包哈希绑定的 `GitReceipt`。普通 `workspace-review`
可显示提交摘要；`workspace-extract` 仍只提取项目文件，不写回原项目。

**明确边界：** 只创建全新的隔离仓库，不导入原项目的 `.git`、历史、remote、凭据或
配置；结果不导出 `.git` 对象，因此此第一阶段的提交历史不会跨会话持久化。它是一次
受限的初始化提交工作流，不是可替代完整 Git 客户端的任意交互式终端。项目文件和
Git 结果仍是未加密数据包；哈希是内容绑定，不是签名、准入或授权。全过程不执行
项目代码、测试、MSBuild、Git hooks 或 filter，不开放网络、不启动 Claude。

包的文件数量、单文件、总内容和路径边界沿用原 workspace 限制。CommitMessage 只允许
1–160 字符、单行、无控制字符的有效 UTF-8；路径验证还拒绝扩展名前含空格的 DOS
设备名别名（例如 `CON .txt`）。失败不导出部分成果；原工作区、输入包和
私有失败证据按原恢复流程保留。后续若需要跨会话历史，必须另行设计并审计专用 Git
bundle 导入/导出，不能把 `.git` 目录直接放入普通文件包。


当前62eab36f（INACTIVE）已实际通过严格LPAC的Git数据处理：此前已选择的四文件数据包，经普通daily→本人UAC的原Broker→同一Job/LPAC固定离线Git→原所有者闭合/精确清理/成功权威→普通review/extract，新目录四文件字节独立一致。输入BA1C5764...D4138，结果AA2F0DFD...43483，未改原项目，未执行项目代码、未开放网络。证据work/git-data-direct-control/workflow-r2；这是已安装可复用的数据能力，不是PowerShell/编译或完整开发准入通过。

仅已验证的非空工作区数据包走Git数据范围，该范围明确拒绝PowerShell请求，不以PowerShell自有编译样本为前置，也不持有/查询其资产和GPO。无输入数据的完整工具资格仍要求PowerShell与编译；其最近原生结果仍失败。原有四命令、普通用户维护、本人工具UAC、固定Git参数/环境、同一管道、身份/Job/五根拒绝和Git自身两拒绝、独立仓库核对及成果权威均保留。该历史版本未新增执行器或IPC协议字段；schema 2数据包扩展见本页后续章节。

已安装入口`workspace-process BASE_BUNDLE NEW_RESULT_BUNDLE`：普通用户daily先核对并持有安装资产、创建新的输出文件，然后请求本人UAC启动同版本固定Broker。仅本人SID可访问的本地管道传入确切数据字节；双方核对内核进程PID，Broker还核对普通调用者映像及本人SID。复用原ProcessWorkspaceData/ProtectedSession，成功闭Job与精确清理后再导出绑定原包的成果。没有特权宿主路径、脚本、任意命令或通用提升入口。取消/失败保留新建的空/部分输出供检查，不能覆盖已有结果。ac570b47已实测四份本仓库文件的pack→process→review→extract完整往返；仅process请求UAC，其余日常维护始终普通用户。v2失败回执仅返回固定阶段/异常类型/错误码及可选会话编号，不返回原始异常消息或私有路径，不自动重试。

daily命令必须普通用户运行。ac570b47的普通AppContainer往返仅是历史成果；本页顶部62eab36f才是本次严格LPAC的Git数据链实机证据。不得把两者当成PowerShell、实际项目代码或完整工具链验收，当前缺口见STATUS。

开发中的v3失败回执沿同一管道返回可选的五项原生创建诊断与四项Broker停止观察：两个自身进程策略值及各自查询错误、固定映像执行打开错误；准入是否关闭、停止前隔离观察、最终Job零成员观察、停止错误数量。未知值保持null，拒绝额外/重复字段、路径文本、矛盾数值和未绑定会话。它们只在失败时出现，不释放成果，也不证明私有目录清理、恢复成功、正式准入或完整隐私保护。此版本要求同包daily/Broker一起更新，无协议降级；构建/安装/原生资格以CURRENT-STATE的限定摘要及原证据为准。

`workspace-pack ROOT SELECTION_JSON NEW_BUNDLE`从明确指定的本地NTFS项目根读取清单中的文件，将内容、相对路径与SHA256写入一个新数据包。清单是JSON字符串数组，例如`["README.md","src/main.py","tests/test_main.py"]`。没有目录递归/通配符或默认全项目扫描；未选择文件不会进入包。输出父目录必须已存在；已存在输出拒绝覆盖。终端只返回包摘要与文件数量，不打印项目内容、宿主绝对路径或环境变量。

`workspace-review BASE_BUNDLE RESULT_BUNDLE`核对每个文件摘要及结果的BaseSHA256，列出ADD/MODIFY/DELETE及前后摘要。绑定的是原始输入包的确切字节；其他项目或重新编码的包不能借用。只比较，不自动应用、删除或覆盖用户原项目。包是未加密源数据，显式选择不等于秘密识别/脱敏；不要把含凭据的文件加入清单。

v1上限：512文件、每文件1MiB、总内容8MiB、序列化12MiB、相对路径160字符/12层。保留二进制和空文件；不保留ACL、文件时间、可执行模式、空目录或Git历史。当前相对文件名限ASCII字母/数字、空格、点、下划线和连字符；拒绝设备别名、尾点/空格、ADS、绝对路径、穿越、.git、大小写别名、文件/目录冲突及未知/重复JSON字段。边界超限明确失败，不偷偷遗漏文件。

实际I/O逐级打开并持有目录与文件句柄，核对固定本地NTFS、最终路径、对象类型、无重解析点及文件单链接；源文件拒绝并发写/删除共享。输出仅CREATE_NEW，不改宿主ACL。材料化仅在原任务所有者持有的根下新建项目目录及文件，拒绝已有目录接管。不提供“管理员按任意宿主路径打包”的入口。

原`qualify-toolchain`使用同一包格式和材料化实现准备嵌套三文件项目，仍只执行编译在工件中的离线Git命令，不接收项目/脚本/命令参数。管理侧独立核对全部blob/tree/commit与固定身份，原Job停止归零且完整隔离后快照工作树，跳过根.git元数据，结果绑定私有输入账本；成功才清理原任务目录。固定包结果当前受私有账本128KiB上限约束；任意大项目仍需同一所有者的持久成果存储/授权交付，不扩大安全账本限制。

数据包不是签名、身份凭据、正式准入或管理员授权；哈希只绑定内容。新增命令不执行项目代码，不授予通用会话、网络、设备或GPU权限。固定Git包的源码接线、普通用户传输实测及新安装受限运行分别记账，互不代替。

当前已实测：普通用户明确选择本仓库四份源码/文档，安装daily交给原AppContainer/Job链完成固定Git提交、对象核对、闭Job结果快照和精确清理，成果经过同一受验证Broker返回，比较/提取及独立逐文件摘要匹配。原固定三文件/52项清理是较早独立证据，保留在STATUS；不借用其计数描述本次任务。入口已接收显式选择的数据包，但不能执行输入项目代码；编译/测试工具链与全面隐私资格仍需继续推进。

开发中新增数据操作（构建/实机状态以CURRENT-STATE为准）：已安装Broker在现有提升上下文中接受`process-workspace-data EXACT_INPUT_SHA256`，标准输入只接原始数据包字节，15秒/12MiB封顶，不接受宿主文件路径、可执行目标、命令或脚本。SHA256表达对这些具体输入字节的选择，不授予项目代码执行。沿原任务所有者执行固定离线Git init/add/commit，对所有对象独立核验、关闭Job归零后快照/精确清理，成功终态后方可`export-workspace-data SESSION EXACT_RESULT_SHA256`把原始结果包输出到stdout。失败/未完成结果拒绝导出；存储数据与小型安全回执分开，原包/结果字节留在管理员私有state，不自动清除原证据。

普通用户`workspace-extract BASE_BUNDLE RESULT_BUNDLE NEW_DIRECTORY`先比较确切原包绑定，然后只创建全新目录及文件；不合并既有树、不写回原项目、不删除文件。原JSON包无BOM；通过标准输入时须保留字节，不用会改编码/换行的文本管道。结果导出应定向到用户自己选择的新包文件，stdout包含源数据，仅在主动导出时输出。

真实项目的.gitattributes及.gitignore作为文件保留，但数据处理固定在.git/info/attributes中取消text/filter/ident/working-tree-encoding转换，Git add --force仅作用显式清单，使二进制/CRLF与被忽略的已选文件完整进入独立对象核对。依据：[Git属性优先级](https://git-scm.com/docs/gitattributes)、[Git显式强制添加](https://git-scm.com/docs/git-add)。不执行项目hooks、filter、MSBuild或测试。该入口是数据维护，不是正式会话或完整隐私资格的替代入口。

## 有界项目失败反馈（2026-11-02）

显式caller项目沿原编译/运行/测试、owner、管道、daily及GUI链返回可选ProjectFailure。
仅阶段Compile/Entry/Run/Tests，以及最多8条CS错误码、所选源码序号与物理行列；不传编译消息、
异常消息/栈、源码内容或#line映射路径。GUI只按自己审阅的Sources映射名称。字段/大小/阶段/绑定严格校验，
仅失败、原封存和隐私观察满足时可出现；不改变成功、停止、清理和成果权威，不自动重试或导出失败结果。
旧V1/V2成功与旧失败回执保留。普通自有失败验证与安装/真实LPAC验证分别记账，最新范围见CURRENT-STATE。

2026-11-02限定实测：00ac安装daily实际返回固定LPAC编译失败CS0103及所选源码物理9行52列；
无映射路径/异常消息，结果0字节，原两actor46拒绝/owner封存/公开关闭观察满足。此前3cfd诊断丢失
与修正保留，非通过；运行/测试失败反馈仍只有普通验证。GUI显示接入及普通数据验证不等于实机点击。


控制文件执行门（2026-11-02）：原33项门包括原14宿主/9owner进程与新增十个私有identity/当前指针/运行库最小文件权限打开；仅真实拒绝5可执行代码。原owner派生固定路径/持有对象身份、query token与DACL AccessCheck维护正控制，文件占用32不算拒绝。没有内容读/写或SD修改。新版policy拒绝旧23项报告。新增门已安装/普通验证；真实LPAC NOT_RUN，见CURRENT-STATE。

8a22后续本人单次授权实测：新33项两actor全部拒绝5，包含控制文件十权限共20次句柄打开；原owner封存后正常DataReport修改/编译/三测试/十一文件恢复与Count3 Total12通过。原owner成功结果门保持，未额外private/raw Job/Stop读取或实际危险句柄操作。仅该固定对象/权限/项目范围，非完整P0或GUI点击验收；原NOT_RUN段落为运行前历史。


### 原pipe调用者生存与停止

工作区pipe所有者保留已鉴权日常进程的QUERY_LIMITED_INFORMATION|SYNCHRONIZE句柄到整个交换结束。WorkspaceCallerLifetime等待同一对象；只有WAIT_TIMEOUT可表示尚未退出，退出码259不能代替等待状态。DATA/固定样本/调用者项目路径将非空检查传入原资源runtime，在创建/恢复前、健康与代码放行、结果导出/发送前检查。失败抛入原finally的撤销准入→隔离→精确Job停止/原恢复链；停止和清理不调用生存检查，不认领或停止未知进程。没有新增通用停止命令。

这是已接入的机制说明；当前安装及证据只见CURRENT-STATE。自有进程等待与正常普通编译不证明真实受保护失联Job停止，后者仍需固定范围的具体授权与原所有者回执。

2026-11-02（UTC11月3日）e249固定场景已实测调用者退出：普通控制器只结束同一持有普通daily，原owner因WorkspaceCallerExited关闭准入/保持隔离并确认同Job零/停止失败0；66拒绝/执行前封存保持、结果未保存。只读观察按单独具体授权投影原记录，不能将摘要当未来许可。首控制器路径核对误拒绝保留FAIL，修正版经新一次具体决定执行。证据与范围见CURRENT-STATE/验收账本；profile清理与owner崩溃重启仍未由此证明。
