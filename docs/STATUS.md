# 当前开发状态

## 2026-10-29 当前事故：0x1E蓝屏；停止新增产品执行

SOURCE / INTEGRATED（修复中，未结案）：Wof匹配反汇编表明FileNamesInformation=12跳过事故中的元数据转换，.NET默认类2会进入。现已将Lifecycle所有目录清点接入原WindowsPathSeal的仅名称查询，保留逐项身份/ACL/tag及原清理边界，无旧枚举回退。六产品及两组测试源码语义0错误/0警告；tests/DirectoryNames已给出只访问新普通用户临时样本的具体资格入口。BUILD / 原生资格 / 消除崩溃均未取得；等待对冻结离线构建→工件审查→普通用户有限样本的明确决定，不安装/运行Broker、不恢复旧负载、不改系统。详见事故记录“继续解决”。

VERIFIED（只读事故比较，非产品验收）：用户明确授权操控已安装微软WinDbg并本人确认UAC；两份原dump的匹配符号均显示ProtectionBroker目录枚举、WofPreDirectoryControlCallback+0x695、Ntfs!FindNextIndexEntry2+0x675后RIP=0，完整分类同为AV_Wof!WofPreDirectoryControlCallback。强烈支持同一失败机制；Wof/AV/硬件责任、具体CLR行与目录仍UNKNOWN，不授予重试。06:53Z收尾复核两份原dump摘要未变，7次分析GUI/7引擎精确结束，日志/符号失败及成功原样保留于work/windbg-installed-20261029；未上传转储。详见[有效比较及限定结论](INCIDENT-20261029-SYSTEM-CRASH.md)。

05:58Z补充：本人UAC的固定只读采集已确认重启后actual current仍为ecb06a/INACTIVE；原转储SHA256=B81AB79BF339A8FB89833C564F86483B950409B3D836BA7D80D46CEC09BD47F3。1501项有界库存的明确UTC事故窗口没有匹配新会话/profile/Job/task回执；不证明请求未执行或恢复成功。r1时间类型误拒绝失败保留，r2修正为明确UTC后307ms退出0。该采集本身无产品/调试器执行；旧拒绝及后续手动分析计划为历史，已由上方本人授权的安装WinDbg路径取得有效结果。

BLOCKED（产品build/install/runtime/fault injection）：本次人工UAC窗口在05:44:37Z已完成INACTIVE更新到ecb06a57929a45d1adf9dd1d8415c4a4，manifest851701939666F35F4E0C4323C408E00690B4CFB96165C81F5C6092AF5D8238C6；错误输入摘要拒绝125已落盘，随后正确项目数据请求没有终态。05:44:54Z系统重启，System1001确认0x1E(C0000005,0,8,0)。驱动/根因/本项目因果均UNKNOWN；不重试、不自动恢复，不把失联当完成。
新staging/版本目录存在，旧659d76df保留；重启后当前指针已直接回读，但未完成Job/profile及WFP恢复仍未验证。普通读取转储AccessDenied保留，后续本人UAC成功；未改ACL/上传。
重启后AVP/BFE运行，FlClash/Core24520/17272及UU GameViewer服务进程存在，无产品测试进程；这些不证明整体系统健康/保护验收。
SOURCE / BUILD / INTEGRATED：457d9bd的普通用户成果恢复/输入边界及256KiB二进制测试通过（DLL AD4FFD697890AB0AFF5A52071D8AFE1AA7F632AF1595C4AE771622C7A8914F7D），实际七文件项目包393114字节SHA EA0D3E9410ABE5BAE70B535EA91F7A679E59D30F7F12B4922AA13DD96B0072F0。
e0845ac产品49输入、ea66eff Bootstrap50输入均离线build0/零警告错误；21个staging文件/内嵌清单核对通过。新安装仅有安装及错误pin拒绝的限定证据，正确数据处理/导出/清理NOT_CONFIRMED。
原始证据work/system-crash-20261029-0544Z；详见[本次事故](INCIDENT-20261029-SYSTEM-CRASH.md)。只读诊断继续，完整goal未完成/未暂停；不假称后台继续。

## 2026-10-29 开发中：真实项目字节处理与普通用户成果恢复

SOURCE / INTEGRATED：process-workspace-data只接标准输入+确切SHA256，调用原ProtectedSession/SessionResources/Git，执行固定离线Git数据操作，不执行输入中的构建/测试/脚本。
源数据和结果另用12MiB有界私有payload及小型摘要/NTFS身份回执保存，不扩大128KiB安全账本上限；export-workspace-data须消费成功终态及相同原包/结果绑定。
daily workspace-extract只恢复至全新目录，先核对原包绑定；拒绝合并/覆盖/删除用户原项目。Git二进制内容由全部对象独立验证，info/attributes覆盖工作区转换，显式所选文件不受.gitignore漏收影响。
新源码未据旧版取得BUILD/运行许可；本次新构建/传输/已安装数据处理尚待执行。当前安装仍659d76df，旧证据见下节。正式会话、网络、编译测试、GPU及完整隐私准入继续关闭。

## 2026-10-29 当前：项目数据传输已安装并接入原受限Git链

SOURCE / INTEGRATED：caeea49新增daily普通用户workspace-pack / workspace-review，以及原SessionResources中的同一材料化/快照实现。
显式清单支持嵌套/二进制/空文件，逐文件摘要、结果绑定确切原包；不执行源代码或自动写回原项目。
逐级持有目录/文件，要求本地NTFS最终路径、无reparse/文件硬链接，拒绝越界/大小写冲突/覆盖/已有目录接管；不扩大宿主ACL。
Broker不接收宿主源路径或任意项目命令；固定qualify-toolchain仅用编译在包内的三文件输入走这条数据面，不能用它绕过正式准入。
两级隐私及Broker具体资源操作的特权原则见PRODUCT-DIRECTION-20261028；[命令与限制](WORKSPACE-TRANSFER.md)。哈希不代表身份、准入或权限授权。

BUILD：caeea49的62个输入覆盖Broker/Lifecycle、daily及源链接传输测试；全部离线restore/build为0，零错误/警告。
当前939f059产品49输入、aa864bc Bootstrap50输入分别构建为0，复用且持有同一Lifecycle字节；六产品非生成语义均0错误/0警告。
新包20个staging文件/14产品资产、内嵌清单、10个PE/6个managed/无module initializer均核对；daily五项采用新构建，GUI四项复用旧批准字节且未运行。

VERIFIED（普通用户传输）：真实NTFS样本的硬链接/目录联接、并发写、路径穿越、覆盖/接管拒绝，以及二进制保真、增删改/错基线拒绝均通过；测试DLL=3683D4B123E4B84A67A500D35F9460D1C808FA6192D9005ECDA31A0331471853。
实际daily命令还打包了当前仓库显式选定的四个源码文件，并比较真实文件变化，均退出0；daily DLL=AC660FD271AA1E982CD0CCD9F540F466ECDF4128599A58986C3D73C50D061550。
相关输入未变化，不因后续安装路径修正重跑同一测试。原始记录在work/workspace-transfer-*。

VERIFIED（安装和离线任务限定）：人工UAC安装release=659d76df00d14dac9c6f46a6dc611157，保持INACTIVE；
manifest=CB5515C9CED7D08248EA903F7EA2817B2F47D5EA952D366B31ABB775520C4264，operation=791fda19ce0a430b8c232f05e3fd1192。
04:03Z Session=0760ef71e8fd42a78e726376bc8b556a：原管理侧核验PowerShell/Git同Job/AppContainer/Low4096/零capability，随后离线Git完成三文件提交f231d5d78177ea3105eb1b75da08280e796847a6；管理侧独立核对所有blob/嵌套tree/commit。
原私有样本读写及Broker VM_READ均AccessDenied5，Git独立读私有样本退出128/Permission denied。
Job=951cc0733e1a4f32a048af868cc444f7完整隔离后关闭归零，才快照工作树；原输入摘要D8F4EF6FA02AC7D5732AE8FD1D604DE66A29EDCAD7E8FD561B03E8090A8ECB59，结果F63E18E7C78562B72E4FAD5A422E6E0B44109A0A8561B922E9F4C3B4C88BB6D2。
原精确清理删除52项、任务根缺失、跨Broker无待恢复回读通过；普通用户独立核对14安装文件/7目录、拒写/私有state拒读/旧包保留/无产品进程；安装daily成功读取Broker闭Job结果并比较为零变化。
原始实机证据在ProgramFiles/ClaudeCodeProtection-Update-659d76df00d14dac9c6f46a6dc611157及work/workspace-transfer-r2-control；没有给任意项目签发启动许可。

FAIL保留：首包44af7ba9在04:00Z退出125，Bootstrap仍固定旧git-r4路径而helper使用workspace路径，必然在安装state变更前拒绝；指针仍fc2d7c8b，无新版本目录/会话。
939f059修正为从内嵌批准的严格Release导出唯一ProgramFiles/ClaudeCodeProtection-Update-<release>路径，并继续核对三个实际宿主映像/受保护ACL/全部字节；不接受caller路径，不再为实验目录名称重编产品。r1工件、拒绝、stderr/回读全部保留。

DELIVERABLE / BLOCKED / DEFERRED：整体未交付。可用新增能力是已安装daily的显式项目打包/结果比较，以及原受限任务链的数据材料化、Git处理和闭Job成果快照。
任意用户项目进入Broker仍缺可信工作区授权/持久成果交付及编译测试工具接线；Python/编译器、MAC/BSSID/位置/敏感软件数据与管理接口完整拒绝、环境画像、受控特权开发操作、14项可信采集、NVIDIA及控制器崩溃/重启恢复仍有缺口。
网络入口仍关闭；本包包含既有ab509a5修复，但未运行网关/上游TCP实机矩阵，不能继承旧包网络资格。真实Claude继续延期。
FlClash/Core24132/12484前后保持、AVP/BFE运行、有限Application AV窗口0；厂商全覆盖仍UNKNOWN。未操作UU、全机网络、AV或驱动，未自动确认UAC，未推送。

## 2026-10-28 接续：网关核对实际上游连接身份

SOURCE / BUILD / INTEGRATED：ab509a5的SessionProxy的DoH隧道及目标隧道现在共用同一持有的ProxyChannelLease，
在发送CONNECT前及接受200响应后，核对已建立连接的反向IPv4四元组对应PID，要求等于持有的FlClash进程。
监听端口归属仍需持续符合，但不再能单独证明已接受连接的归属；查询失败、非ESTABLISHED、非唯一或PID不符均拒绝。
连接等待前后还重查当前转发许可；新策略摘要NET2使旧环境意图不能自动套用。
生产TCP表解码器直接进入原有监听/下游/上游身份读取，新增策略用例覆盖可信监听恢复后已接受连接仍属于另一进程的情况。
六产品非生成语义检查0错误/0警告。固定SDK8.0.422/ref8.0.28、47输入Broker/Lifecycle及17输入策略测试
分别离线restore/build退出0、0错误/0警告；输入按提交核对并持有，只允许本地空包源/已审查SDK导入，无产品执行或安装。
VERIFIED（策略限定）：测试实际退出0，覆盖反向端点/状态/唯一PID/边界拒绝及监听者与连接者不一致，
并保留原TLS/双向转发/关闭账本用例；测试DLL=34AA2EBF24ACA85FBB2C0C6DCBCCA58A8C7745181B9323F9A7C6685DDF0C3951。
它只执行生产解码器及内存策略/账本读取；账本的native变更协作者始终抛异常，但会读取当前Windows身份。
实际TCP表/竞争时序及新安装网络运行仍NOT_RUN。原始输入、导入、构建及运行记录保留在work/upstream-peer-*。
当前安装仍为下节fc2d7c8b，不能继承其离线Git运行证据；未改AV、FlClash或网络配置。

BLOCKED / DELIVERABLE：正式网络会话仍关闭。此修复不证明上游保留literal目的地或非DIRECT出口，
不解除十四项准入、宿主隔离与独立系统条件；完整交付仍未完成。普通旧构建/启动入口仍阻断，无新AV告警的全覆盖证明。

## 2026-10-28 当前：已安装的固定离线Git工作流、拒绝与任务目录清理通过

BUILD / INTEGRATED：a97a967产品46输入、13eafd8 Bootstrap47输入分别离线构建0错误/0警告，
六产品SOURCE语义0错误/0警告（Lifecycle39源）；内嵌批准/20项staging/同一Lifecycle/无module initializer核对完成。
更新后的账本隔离测试15输入实际退出0（E0354E4A41ACFC0D499D4B030D313D924AAACC8226685A690821E9A58467350A），
内核及任务清理协作者为抛异常替身，仅为读取器/策略证据；任务删除的native证据来自下述真实会话。
当前Broker十项普通用户拒绝、Bootstrap两项拒绝均125并确认退出。

VERIFIED（限定）：人工UAC流程退出0，安装release=fc2d7c8b668c47dea505fc2f19f923a3，
manifest=2F23479431360CC5BE0B0E84DFB821FBF2FFD8D04BE3A100EC0F7677B0EDB20B，
operation=0346c287c1fd450cb7ecffd9747b4ebf，保持INACTIVE。
11:24Z的Session=5607967e70a1403191c53ec499cab1d7，根程序及PowerShell均退出0；
管理侧实际核验PowerShell及等待stdin的Git进程处于同一Job/AppContainer/Low4096/capability0后才释放负载。
Git stdin哈希、init/add/commit/show通过；commit=bbbdfdada70f6ac14a0dc7ea327587e921271b95。
管理侧独立限长解压并核对实际blob/tree/commit/分支引用，以及固定无账号身份/日期/消息；
Git读取真实存在的非秘密私有样本返回128和Permission denied，配合正常操作证明有限拒绝路径。
根程序私有样本读/写及Broker VM_READ打开也仍是AccessDenied5；没有把Git128冒充Win32错误5。
完整隔离回读后Job=d2c339aa4bb84b8897ea712312621f72关闭/归零，精确删除43个任务项，根路径回读不存在；
私有task意图/created/closed与profile闭Job清理意图摘要绑定独立回读一致，另一Broker返回NO_PENDING_PROFILE_CLEANUP。
任务closed摘要=5FD3F3501572862DCCC03BE4FCF813BEB5B1E3AB4D423527711AF7D2692086D8，
资源原始报告摘要=6C6BED1438750AA0C06D9E545BA2A2C87423F88262650412F0244065AF8334F9。
独立普通用户再核对14安装资产/7目录、普通写打开全拒绝/私有state读取拒绝、旧包保留，未见产品进程。
AVP/BFE运行、FlClash28452/Core27708保持，有限Application AV事件0；厂商完整告警覆盖仍UNKNOWN。

DELIVERABLE：正式产品仍未完成；本次真正新增的是安装Broker可运行的离线Git工具链及自有任务数据生命周期。
不是任意用户项目、在线Git/凭据、Python/MCP/GPU、全宿主资源/注册表/服务隔离、实际网关网络矩阵、14项正式准入或控制器崩溃/重启验收。
未签正式Admission、未开放网络、未启动真实Claude；9项daily/GUI仍复用旧批准字节，未重建或运行GUI。
未改现有宿主/Git/个人目录ACL、AV、全机网络或日常FlClash，未推送；下述三次失败全部保留。

qualify-toolchain已接入InstalledBroker → ProtectedSession → SessionResources/同一AtomicChild与RuntimeLease，
不接收命令、目标或项目路径。复用本机ProgramFiles Git的签名有效exe与5个非系统DLL，当前摘要固定、
管理侧持有可信目录及所有资产；路径变化或文件更新必须重新审查，不从路径本身推导可信身份。
Git的stdin哈希负载在管理侧核验同Job/AppContainer/Low/零capability后才释放；随后固定init/add/commit/show，
禁用宿主配置、凭据助手、hooks、签名及所有Git传输协议，环境清空，提交身份/日期使用无账号关联的固定样本。
管理侧将独立解压/限长核对实际Git blob/tree/commit及分支引用，Git还独立尝试非秘密私有样本读取并要求拒绝。
只在新nonce Git工作区授予文件DELETE以支持Git的锁文件替换；不授予DELETE_CHILD/WRITE_DAC/WRITE_OWNER，
不改已有宿主/Git目录ACL，封存的输入及工作区根仍由不共享写/删除的管理句柄保护。
现有Git资格三次真实结果保留：r1在创建子进程前拒绝，随后只读fsutil确认exe4个链接、DLL各2个；
已只为固定只读资产增加精确链接数量/摘要/可信ACL例外，源/安装包/状态/删除路径仍单链接。
r2根程序/PowerShell及三项拒绝通过，但Git在放行stdin前退出；r3保留其真实退出128及stderr：
Unable to read current working directory: Permission denied。r3还触发了已退出Git不在就绪快照的拒绝；
125是随后精确停止造成的根程序退出，不能伪装为Git原退出码。两次均完整隔离后Job归零。
有界CodeIntegrity/AppLocker窗口查询无匹配事件，但不能排除未覆盖的安全事件；未改AV或改用其他入口。
该失败窗口的dd87aad181d24fc096370685595ef478/manifest66DBD24CB8A296BC0023A24E806B755973344DC95B387E3E8A21F2EDFE367EE5保留，不能由r4成功覆盖其FAIL。

已接入并实际验证的修复：Git任务数据改为新建ProgramFiles/ClaudeCodeProtection-Task-<nonce>，不开放个人profile祖先ACL。
任务目录本身仍为BA所有者、Low标签、当前用户/精确package最小修改权限，祖先为既有公开可遍历的可信系统目录。
新任务根在创建前后分别写入与profile创建摘要绑定的私有意图/NTFS身份；进程创建前必须完成这些记录。
清理接在原profile的闭准入/零Job checkpoint之后：完整no-follow/单链接预检、持有句柄按叶到根精确删除、回读根不存在，
拒绝路径替换、未确认创建、越界、重解析点、硬链接或超限；不使用递归路径删除兜底。
FileDispositionInfoEx仅用于这个新建临时任务树，DELETE+POSIX+image check+ignore readonly，所需WRITE_ATTRIBUTES限于已核验的任务句柄；
不是权限/所有者/全机安全配置修改或安全擦除保证。依据见[Windows删除语义](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/2e860264-018a-47b3-8555-565a13b35a45)。
所有历史Git包/失败/实际stderr与Job归零仍保留在work/git-toolchain*及ProgramFiles固定资格目录。
下方75320489是已成功的较早离线/恢复窗口，不转授新代码运行证据；当前资格范围以本节r4为准。
正式会话、网络、14项准入及任意用户项目仍关闭；下一主线优先真实授权项目/工具扩展及受控网关与可信准入。

## 2026-10-28 当前：已安装的离线会话与跨进程profile清理恢复通过

用户已人工核实本次codex.exe有效OpenAI签名及对应SHA256的OpenTIP Clean；接受该记录，
不扩大为所有历史告警均属误报。受信任条目截图不代替完整选项/最终保存确认；本工具未改AV。
普通开发命令现已成功执行。下方上一窗口“停止新增执行”是当时状态，不构成本次续开发的总禁令。

SOURCE / INTEGRATED：InstallationProfileLease创建前拒绝现存目录；v2私有账本记录实际NTFS身份/当前用户，
原子进程创建前持久记录唯一Job绑定。Job关闭/零成员后才建立精确清理checkpoint；清理不跟随重解析点，
限定目录/文件数量与深度，Windows删除API成功还必须实际回读整个profile目录不存在。
recover-session-resources通过现有InstalledBroker所有者，只处理有checkpoint的本次安装/当前用户资源；
要求全部准入关闭、持久零成员及完整隔离。目录替换、未知创建窗口、未关闭Job或旧账本均不获得删除许可。
qualify-resource-recovery沿ProtectedSession原离线资源链验证Job归零后延后清理并退出；
下一次独立Broker调用recover-session-resources从私有账本完成恢复，无活的profile对象传递。
固定PowerShell用“数据关闭后发布signal”握手，在管理侧持有进程句柄核验Job/token/image后才执行负载；
工作区仍只有原读写权限，未为通知改名增加DELETE权限。正常退出阶段由运行租约/Job排空监督。

BUILD：7fb4570产品44输入、d8ae593 Bootstrap45输入分别离线构建0错误/0警告；同一Lifecycle字节复用，
六产品非生成语义检查0错误/0警告（Lifecycle37源），20项staging/内嵌批准/无module initializer核对完成。
账本读取器14源/15输入的隔离测试实际退出0；内核/删除协作者为抛异常的替身，WindowsIdentity读取用于当前用户匹配，
只证明账本逻辑，不能冒充native恢复。后续产品改动未改变这15输入，逐项摘要核对后复用该范围证据。
当前Broker九项普通用户拒绝（含伪造资源计划）及Bootstrap两项拒绝均125，并确认退出。

VERIFIED（限定）：人工UAC流程最终退出0；当前release=7532048921364d978518e2e6993a9b9e，
manifest=1C2D5F29BB27A0ED4A003F67210C12286956FE2AD9F9547ECA34865C8BB8D2FB，
operation=03f023fd29fe4e11aa62ffe7ccd0303a，保持INACTIVE。
09:14Z固定离线会话Session=5468d53da63c43fa92d74c05843120bc，根程序/PowerShell均退出0，
工作区读写及私有样本读写/Broker VM_READ句柄请求拒绝通过；管理侧核验PowerShell同Job/AppContainer/Low4096/capability0。
Job=0d755fbd82a4437fb4f967b3072f7d50完整隔离回读后关闭/归零，主动保留清理checkpoint并退出。
第二个Broker实际恢复1个精确profile，Delete API0且整个storage根路径OPEN_EXISTING回读不存在；
第三个Broker返回NO_PENDING_PROFILE_CLEANUP。管理侧独立回读created/job/intent/closed摘要绑定一致。
资源原始报告SHA256=B64444331EE6B1A2CBE0876D411A194018BB92A4D6B1CF30139578E17A42EA46。
独立普通用户核对14安装资产/7目录、全部普通写打开拒绝与私有state读拒绝，旧包保留；当前未见产品进程。

原失败保留：r1首次成员快照不稳定，停止后Job归零，125是停止后的根程序退出码，不能倒推根程序主动拒绝；
原记录未保存两端快照，具体成员变化尚不确定。r2握手的File.Move需要工作区未授予的删除权限，PowerShell退出1；
原始stderr未展开，归因为权限设计不匹配的工程判断，不虚构已捕获其原生错误5。
r3改为不需要rename的双文件握手后通过；没有扩大目录权限或降低身份检查。另一个普通用户rename诊断在设置
测试目录ACL时被拒绝，未执行rename对照，保留NOT_RUN，不充当上述判断的实测证明。
全部包、失败和固定工件在work/profile-recovery*-control/build及ProgramFiles对应固定目录保留；不入Git。
本次观察AVP/BFE运行、FlClash28452/Core27708保持，有限Application AV事件0；厂商完整告警覆盖仍UNKNOWN。

DELIVERABLE：整体未完成。真正控制器死亡/重启、native创建与created回执之间的未知窗口仍缺安全自动恢复；
真实授权项目/Git/Python/MCP/GPU、全面宿主隔离、网关实际网络矩阵与十四项可信准入仍是主要交付缺口。
未签正式Admission，未打开网络或运行真实Claude；9项daily/GUI仍复用原批准字节，当前GUI源码未随Broker重新构建。
未修改AV/全机网络/日常FlClash、未推送。下文为历史窗口，不能覆盖本次成功及其范围。

## 2026-10-27 当前：离线资源会话通过；随后Codex进程被卡巴斯基拦截

SOURCE / INTEGRATED：固定 qualify-resources 已进入 InstalledBroker → ProtectedSession → AtomicChild → ProtectionRuntimeLease。
它只运行安装包内固定离线负载、profile自有工作区与系统PowerShell，不接收目标/脚本，不签正式Admission或开放网络。
用户与package读写DACL只用于新nonce工作区；先用DACL创建，再以LABEL_SECURITY_INFORMATION设置低标签并回读。
父目录/文件身份与卷元数据由持有整条路径的管理侧核验；受限子进程只需正常文件I/O，不为辅助元数据查询扩大宿主访问。

BUILD：最终产品95a3a53的43输入、Bootstrap fb11989的44输入分别离线构建0错误/0警告；
六产品非生成语义检查0错误/0警告（Lifecycle36源），20项staging/内嵌批准/同库/无module initializer核对完成。
普通用户资格/更新入口及伪造资源计划的普通子程序入口均实际125拒绝。

VERIFIED（有限）：最终安装release=3990f55726ad4515ad4f335912179bef，
manifest=32D20BF3646356B71FEECA9875192C631A9503A497B2480C074B245FC577373C，
operation=c06f8dc2add44b0b8d01ccd085cb635b，选择保持INACTIVE。
01:19Z的固定离线会话实际退出0：根程序工作区读写、PowerShell读写与敏感样本读取拒绝成功；
管理侧确认PowerShell处于同一Job/AppContainer、Low4096/capability0及固定映像；根程序样本读/写和Broker VM_READ句柄请求均错误5拒绝。
SessionId=60086a41a80e4357b6c984667f1fce69，JobId=9b0eed6e11b546ba822c66c13e307661。
Stop确认完整隔离回读后精确Job关闭/零成员；清理无异常意味着profile Delete API0，不推导独立存储不存在或崩溃/重启恢复。
原始报告SHA256=B316B89A1BA0928A1E6B2EACFFD360C58EBBF31BA902F608FA43E69D19976B58。
独立核对14安装资产哈希/普通写拒绝与7目录权限、私有state读拒绝、旧包保留；当时未见遗留产品进程。

前四次真实失败完整保留：r1早期Win32Exception；r2工作区叶元数据打开错误5；
r3创建时提交整个SACL导致1314，未创建Job/子进程；r4低标签专用接口与DACL回读成功，但受限叶元数据查询仍错误5。
因此权限继承假设不足以单独解释原故障；r5把管理元数据查询留在可信所有者后，实际I/O和工具调用通过。
所有原包、失败、固定脚本/输入/工件摘要在work/resource-session*-control/build与ProgramFiles对应固定目录保留，不入Git。
停止重复这条已成功正常矩阵；下一功能应扩展实际宿主资源/授权项目与工具边界及网络/可信准入，不以固定fixture替代整体目标。

后续新事件：用户截图确认2026-10-27 21:23:22（America/New_York）系统监控检测并阻止codex.exe/PID30504，
名称PDM:Exploit.Win32.Generic，对象为进程、原因为行为分析；不是项目二进制被该截图直接标记。
随后新shell进程创建错误5的现象与此一致；尚不能确认具体行为、误报或历史事件归因。
已停止新增产品构建/执行；仅通过既有Node文件工具保存截图、核对文件摘要/文档，未换入口启动被阻止命令，未修改AV例外。
告警后只读确认上述安装manifest/Lifecycle/Broker DLL字节仍匹配；不能代替私有current指针/运行状态重新核验。
详见[本次Codex告警](INCIDENT-20261027-CODEX-SYSTEM-WATCHER.md)。本页更新尚未Git提交：不通过替代进程绕过执行阻断。

DELIVERABLE：整体仍未完成。DEFERRED：真实Claude继续延期。BLOCKED：新的执行需先处置此次具体AV事件；
完整宿主资源/注册表/管理接口、真实授权项目及Git/Python/MCP/GPU、网络功能、十四项可信采集及异常恢复仍缺。
成功窗口AVP/BFE运行、FlClash28452/Core27708保持，有限Application AV事件0；随后截图证明此日志观察不覆盖全部厂商告警。
没有从旧PASS、当前局部成功或用户误报假设签正式许可；没有改FlClash/全机网络/AV、推送或运行真实Claude。
下文是历史窗口，不覆盖最新安装、真实离线成功和此次新AV事件。

## 2026-10-27 安装主线：固定新Broker已实际INACTIVE更新

接续2328e24，本次用户明确P0宿主资源隔离与网络防护并重，P1设备身份/遥测为正式目标，优先真实产品贯通。
修复Bootstrap入口无条件拒绝全部更新：仅接回现有UpdatePinnedInactive，不新增平行安装器。
管理侧要求固定保护目录、嵌入完整包批准、旧版本精确白名单、独占锁、所有历史准入关闭/零成员、
回环豁免关闭、屏障不存在或完整封闭、原账本/原子选择。事故时814cf433包仅获允许迁出，不清除事故。
新建安装及WFP/Job/GPU/Watchdog/迁移/合成会话仍未获资格，正式Claude仍DEFERRED_BY_USER。

- SOURCE / INTEGRATED：5ea85b5接回同一安装所有者；六产品非生成语义检查0错误/0警告。
- BUILD：5ea85b5的Broker/Lifecycle42固定输入与7fd42ba的Bootstrap43输入分别离线构建成功，均0错误/0警告；
  固定SDK8.0.422/ref8.0.28、空源、导入审计。Bootstrap构建持有并复用相同Lifecycle，未重编写库。
- VERIFIED（限定安装）：20项staging文件/内嵌批准/同库/无module initializer核对完成；
  实际七个Broker系统拒绝、普通用户更新拒绝、新建安装拒绝均退出125并确认退出。
  人工UAC后固定Bootstrap更新实际退出0；当前release=f43484dc7fd6410086d3bc6785126793，
  manifest=B58EDC15D9C21C17565A57ACCA08B39B1AC1992E59429CB4F719E4FD3EAB7962，
  operation=db5149274f4a4d678a8f4ce465cbec37，Activation=INACTIVE。
  管理侧current指针回读与更新回执一致；独立普通用户核对14资产字节/权限、7目录权限，
  14项Write打开均AccessDenied（零字节写入），私有state读取AccessDenied，旧814cf433 manifest保留。
  此权限结果仅适用于安装资产/管理state，不冒充开发侧宿主敏感资源隔离。
- DELIVERABLE：完整产品仍未完成。此次交付进展是最新会话/网关源码已进入实际安装Broker包，
  不再仅停留在checkout；尚未打开其转发监听、恢复挂起程序或运行受保护会话。
  9项既有daily/GUI资产按原批准字节复用，未重建/运行，不声称当前GUI已获得后续源码更新。
- BLOCKED：工件的受保护进程/网络/资源功能资格、授权工作区与工具设备、上游字面目标保持/非DIRECT路径、
  十四项完整可信采集仍缺。下一实际切片优先同一已安装所有者的宿主资源拒绝及授权工作区可用，
  需固定有限负载资格，不能从安装成功或旧网络/GPU证据签正式许可。

证据保留work/session-inactive-update-control、session-inactive-broker-5ea85b5-build、
session-inactive-bootstrap-7fd42ba-build，以及ProgramFiles/ClaudeCodeProtection-Update-20261027-session-r1，均不入Git。
实际运行窗口00:44:40–00:44:49Z（本地2026-10-27）；原失败/包/私有账本不删除。
前后有限观察AVP/BFE运行、FlClash28452/Core27708保持、Application新增AV事件0，完整AV覆盖UNKNOWN，
Kaspersky事件及0x1E根因均未结案。没有WFP写入、Job创建、故障注入、全机设置/AV/FlClash变更或真实Claude。
最后未见本轮产品进程存活。fetch后origin/main仍8e5b4ee且已在本地历史中；README/origin保留，未推送。
下文均为先前窗口，不能覆盖上述实际安装或转授运行资格。

## 2026-10-27 CONNECT目标与TLS首个握手名称绑定（本轮）

接续904d360，工作区干净。先只读核对当前上游：14:07Z的本机控制器GET观察为global、
选中适配器链Selector→Vless，未观察到DIRECT；配置摘要前后未变，未披露选中名称/节点/订阅/secret，
未改FlClash、未调用延迟测试或外部出口服务。work/upstream-route-readonly-20261027-r1保留固定脚本与脱敏结果。
这是瞬时元数据，不是连接原子路由或真实出口资格，不能给十四项或独立安全条件签PASS。

SOURCE / INTEGRATED：SessionProxy实际转发前新增同一路径的ClientHello检查。
对已认证、当前许可及精确Job/token的连接，先返回本地CONNECT响应并接收至多32KiB/8条TLS记录的首个握手；
必须是完整ClientHello、唯一可见SNI与授权目标一致，ALPN如存在只能http/1.1或h2。
缺失/重复/私网名称/不同名称、明文、畸形长度、ECH/旧加密名称等拒绝并沿原Fail/撤销链退出。
随后才发起该连接的DoH解析及字面IP上游CONNECT，再把预读字节交回原复制器，完整计入流量预算、
维持每次写出前许可复核和原端点排空。两次上游操作后仍核对当前身份/许可；无直连回退。
策略摘要包含此限制；当前只服务固定自有HTTPS目标，不代表一般浏览器/ECH及全工具链兼容完成。

上游审查还表明普通CONNECT不能代表已锁定独立出站；Mihomo会按模式选择GLOBAL/DIRECT并可能处理映射/嗅探。
已把网关独立安全UNKNOWN原因明确为当前内核功能及上游字面目标保持/非DIRECT路径未获资格。
TLS名称约束不是服务器证书验证，也不能防止上游重新映射同一授权名称；此必要缺口继续阻止正式许可。
依据与范围见[主链说明](PROTECTED-SESSION-CHAIN.md)，不以当前配置或源码分支推断已安装Core行为通过。

六产品SOURCE语义0错误/0警告（Lifecycle35源），12源纯测试语义无诊断；
outputs/session-tls-target-source-types-final.json、session-tls-target-policy-source-types-final.json保留。
新增分片/名称/扩展/容量/截断/撤销及原样重放和计费用例。
66428c7的Broker/Lifecycle（42输入）及12源纯测试均离线构建0错误/0警告；首次纯测试退出-532462766，
堆栈为网关正确拒绝明文输入后的InitialTlsRecordRefused。原因是测试辅助器仅捕获IOException，
漏掉InvalidDataException；修正辅助器异常分类，未放宽产品条件。首次policy-tls-result.json与程序集/脚本保持原样。
随后16329f9的修正测试独立离线构建0错误/0警告，实际执行退出0；
程序集SHA256 7906217AB70D4C504AEF25AF395D43B69BE51B6C1A170B680CE76E1B2863BEA8。
原失败没有覆写；新结果policy-tls-r2-result.json与work/session-tls-policy-r2-16329f9-build分别保留。
最终产品的42个构建输入逐一与66428c7构建摘要核对一致，只复用相同产品输入的BUILD证据，不推导运行资格。
work/session-tls-broker-66428c7-build、session-tls-policy-66428c7-build及固定控制脚本/导入/输入/工件摘要均保留。
两次测试均无native入口/module initializer；本次产品工件仍未安装或执行。
内存用例不证明真实TLS互操作/ECH兼容、当前FlClash的字面目的地保持或真实出口隔离；相关资格仍NOT_RUN/UNKNOWN。
本轮未恢复WFP/Job/Watchdog实验、未安装或执行新产品、未启动真实Claude；完整产品仍非DELIVERABLE。

## 2026-10-27 会话许可直接约束网关转发（本轮）

接续36c4d7e，工作区干净。修复网关只核验连接身份、转发阶段未直接消费Admission的缺口。
SOURCE / INTEGRATED：同一ProtectedSession.Admission一次绑定同一SessionProxy；WFP开放要求该已签发许可，
实际解析/连接/响应及复制写出还要求首次恢复许可已消费、全部环境/独立安全快照仍有效。
原ProtectionRuntimeLease在所有安装/Job/fence/代理/许可检查成功后，才续期最多2秒的内存转发健康期；
健康期不超过实际运行租约剩余时间，激活缩短期限时同步收紧；首次恢复前也检查健康期。
会话运行租约构造只接受挂起准备，正式许可只能通过同一实例的AttachAdmission接入；删除未使用的直接正式许可构造路线。
缺失、撤销、过期或迟到续期拒绝。复制器读取前及写出前均检查，不让阻塞读沿用旧许可；
检查使用同一所有者的单调时钟/内存能力，不在每个数据块上重复WFP或进程扫描，也不接受GUI/文件PASS。
策略摘要已包含新约束，旧策略配置不会自动获得本次权限。

六项目SOURCE语义0错误/0警告（Lifecycle35源），11源纯测试语义无诊断；
outputs/session-forwarding-admission-final-owner-source-types.json、session-forwarding-admission-policy-source-types-r1.json保留。
新增实际复制器+实际健康期对象的内存用例：阻塞读时撤销/过期、零字节写出、双方排空、
迟到心跳不复活、运行剩余时间收紧。
BUILD：3a3c1c5的Broker/Lifecycle（42固定输入）与11源纯测试分别离线还原/编译成功，0错误/0警告。
有限VERIFIED：同提交纯测试实际退出0；程序集SHA256
3CB4C15C7AB2D7306C2BF88D43504F7A5878B768C149CECD1CEC2720AE12793E；无native入口/module initializer。
固定工件/导入/输入/前后观察和原始结果在忽略的work/session-forwarding-broker-3a3c1c5-build、
session-forwarding-policy-3a3c1c5-build、session-validation-reopened-control中保留。
内存用例验证实际复制器与健康期类；安装后的Broker/Job/进程身份绑定、2秒实际时序、物理出口隔离仍NOT_RUN。
新产品工件未执行/安装，未改变原系统测试入口限制；没有从上述纯测试签发任何正式许可。
这是网关写入前的检查，不能撤回已交给内核/上游的字节，也不是独立进程Watchdog或Broker挂起时的CPU/文件撤销。
完整门禁、功能性网络/DNS、宿主资源/工具/GPU及集中实机证据仍缺，完整产品仍非DELIVERABLE。
本轮不恢复WFP/Job/Watchdog实验、不重试调试器审批、不启动真实Claude、不改AV/FlClash/系统网络。

## 2026-10-27 受控网关正常结束与故障排空修复（本轮）

接续8611fd2，工作区干净。发现SessionProxy任一方向正常EOF会取消两个方向，可能截断仍在返回的数据；
其余方向的并发错误也可能被当作取消清理而吞掉。修复直接进入ProtectedSession使用的同一SessionProxy：
正常EOF仅对对应目的Socket发送FIN，另一方向继续传输；错误/超时/撤销取消并观察两个复制任务后才释放端点。
原每方向8MiB、会话64MiB、连接20秒/会话60秒上限保持，字节在写出前计入预算；不存在直连回退。
固定会话canary改为精确HTTP/1.1 HEAD，避免GET只取头后丢弃未读正文自行中止隧道；未改目标或证书验证。
网络策略摘要包含新传输语义，旧环境预期/屏障不会自动继承新策略。

SOURCE / INTEGRATED：六产品项目语义检查0错误/0警告（Lifecycle35源），11源纯托管测试语义无诊断。
原始报告为outputs/session-duplex-source-types-final.json、session-duplex-policy-source-types-final.json。
新增内存双向端点用例覆盖两个方向延迟回复、后发错误、写失败、方向/会话预算及截止撤销、排空；
测试调用实际SessionTunnel复制器，不开端口/文件或调用native。
随后7543cb1的Broker/Lifecycle（42固定输入）与11源纯测试分别离线还原/编译成功，均0错误/0警告；
纯测试实际退出0，含上述双向延迟响应、错误/预算/截止的排空验证。
测试程序集SHA256 6274B63D189D25D62C3217517EAB0D610F27739243044B42687BD4363A195C19，
保留work/session-duplex-broker-7543cb1-build、session-duplex-policy-7543cb1-build及固定控制脚本/结果。
历史迁移读取另补一个更新兼容修正：完成的旧网关策略记录不再要求等于当前策略摘要，仍核对完整前后像、
固定端口/对象键/安装归属；实际迁移/恢复及启动仍要求当前策略，不从历史回执签发许可。
这避免本次传输策略摘要升级后把已完成的维护历史误判为不合法；该后续源码语义检查六项目0错误/0警告，
outputs/session-duplex-history-source-types.json。
最终源码c9cd81a的Broker/Lifecycle已再次独立离线构建通过，0错误/0警告，
work/session-duplex-final-c9cd81a-build保留42输入、导入、产物摘要及前后观察；未执行/安装产品。
此前7543cb1纯测试的12个输入SHA256逐一与c9cd81a核对一致，复用的是相同测试输入的执行结果，
不是新会话或系统资格；policy-duplex-input-reuse.json保留逐范围说明。历史迁移读取修正仍无实机执行证据。
Socket半关闭与真实TLS/HEAD互操作均NOT_RUN，内存排空成功不能冒充内核/网络验收。
有限前后观察AVP/BFE运行、FlClash/Core PID保持，Application新增AV事件0，完整覆盖UNKNOWN。
本轮未恢复WFP/Job/Watchdog实验、故障注入或真实Claude，未改AV、FlClash或系统网络。
完整会话的可信证据、资源/工具/GPU授权和系统资格缺口未被此修复补位，完整产品仍非DELIVERABLE。

## 2026-10-27 用户重新授权：本机验证与封闭网络迁移

用户已明确允许有界构建/系统验证继续，并接受可能再次蓝屏；历史停止不是永久禁令。
不自动重现、不绕过AV/UAC、不改日常FlClash/全机网络，先固定证据与具体工件范围。
真实Claude仍延期，十四项与系统门禁不能从这份授权推导PASS。

- BUILD：当前源码提交48f9293c的9源纯托管测试、Broker/Lifecycle（35源+2项目+4资源）分别离线还原/编译成功，
  0错误/0警告。固定SDK8.0.422/ref8.0.28、空包源、导入审计、独立输出与前后快照。
  前序b204c979的两次独立构建同样保留，不覆盖其回执。
- VERIFIED（有限）：48f9293c纯策略用例实际退出0，包含实际消费的迁移阶段决策，
  程序集SHA256 0986B48CB1C2F196124E1CF44835538691F1DC3AF3FD011B943155C5E0B2152D。
  新工件migrate-session-network/session-synthetic/admission-child均退出125，三个进程确认退出；
  前两者明确返回SYSTEM_ARTIFACT_NOT_QUALIFIED，后者经公开库保护拒绝；没有系统操作。
  前序b204c979 Broker `inspect-runtime` 退出0，x64结构布局符合声明。
  `inspect-wfp` 实际退出2，ReadBuiltinConnectLayer错误5（访问被拒绝），保留原FAIL/UNKNOWN，不改权限。
  两个普通用户诊断均退出；未安装、未创建Job/进程隔离、未变更WFP规则。
- SOURCE / INTEGRATED：安装Broker新增 `migrate-session-network`，只接受固定7890旧策略与当前17891策略。
  所有历史单次准入关闭、回环豁免关闭后，先完整封闭，再一事务替换同安装SID/同7个对象键；
  保留新旧完整字节和摘要，内核独立回读后比较旧摘要原子选择新计划。中断只由同入口按新旧标记恢复；
  未完成迁移阻断正常启动/安装生命周期。不会杀任务来使迁移通过，也不授予启动许可。
  六项目语义分析0错误/0警告：`outputs/session-network-migration-final-source-types.json`（Lifecycle34源）；
  同一实际迁移阶段决策进入PolicySmoke的事务前/提交后/选择后及反向/未知/未封闭拒绝用例，九源语义检查无诊断。
  `outputs/session-network-migration-policy-source-types.json`保留源码证据；执行结果另见上项。
  此迁移实现已编译，但尚未安装/执行；纯决策通过不证明WFP事务/崩溃恢复通过。
- 事故诊断：核验了既有10:34Z日志。`!analyze` 未找到扩展导出，内核符号缺失；退出0不代表分析成功。
  显式扩展+微软公开符号的修正分析在启动前被自动审批拒绝，仅返回blocked by policy；不换入口绕过。
  尚未取得可归因的故障栈，无新蓝屏/故障注入；详见事故记录。

复现资料均保留在忽略的 `work/session-validation-reopened-control`、
`work/session-validation-policy-b204c97-build`、`work/session-validation-broker-b204c97-build`；
当前源码构建分别位于 `work/session-gateway-migration-48f9293-build`、
`work/session-migration-policy-48f9293-build`，固定控制脚本/输入/导入/工件摘要/测试及拒绝结果均保留。
原失败和受保护分析日志不覆盖。有限前后观察AVP/BFE运行、FlClash28088/Core16112未变、
Application新AV事件0，完整AV覆盖UNKNOWN，Kaspersky事件未结案。

正式许可仍不能签发：当前工件的安装/系统资格、功能性网络/DNS可信证据、宿主资源隔离与工具/GPU授权仍缺。
源码入口的限制现明确为当前工件未获资格，不把用户已重开的授权继续解释为永久蓝屏禁令。
完整产品仍非DELIVERABLE；没有推送、AV/系统网络/FlClash改动或真实Claude执行。
下文是各轮原窗口记录，其“停止/未编译”只适用于当时。

## 2026-10-27 挂起准备与实时环境证据接线：当前结论

上一轮progress为 `04e7419`。本轮修正“需要根Job/SID证据才能创建根对象”的准备依赖：
同一所有者以一次Preparation只创建固定挂起程序、完整隔离和原租约监督；实际Job/映像/token核对后，
仍须全14项和独立安全条件满足，才签发另一个不可替代的首次执行许可。失败走原封闭/零成员/清理。
新建进程/主线程对象在创建时提供管理侧DACL并回读，避免仅凭默认ACL假定外部不能提前恢复。

环境预期的检查/配置进入当前安装Broker管理接口，固定私有状态、实际人类Owner SID、旧摘要比较与前后回执；
没有PASS、豁免或启动参数，不更改OS设置。时区/用户与系统Locale、分阶段路由及启动监督已接入当前采集源码，
环境观察10秒刷新、创建/恢复前强制刷新，策略摘要改变即失效；没有配置或读失败仍拒绝。
本轮没有运行配置、采集器、进程创建、对象ACL或网络代码；事故停止与Claude延期不变。

SOURCE：六产品项目0错误/0警告（生命周期33输入）；八个测试源输入仅语义核对。
报告 `outputs/session-preparation-delivery-source-types.json`、
`outputs/session-preparation-maintenance-policy-source-types.json` 不入Git。新增用例没有执行结果。
BUILD/VERIFIED没有本轮新增，完整产品非DELIVERABLE。当前系统安全与其余环境采集、受审查控制探针、
旧屏障迁移、宿主资源/工作区/工具/GPU授权及实机集中验收仍缺，不能签发正向正式会话许可。
详细调用链与边界见[主链说明](PROTECTED-SESSION-CHAIN.md)。

## 上一轮主链接线记录（历史窗口）

上一轮属于progress，提交 `b18d5cc`；本轮继续同一分支，不改变完整产品目标。
SOURCE / INTEGRATED：正式Broker launch和受阻断的session-synthetic进入同一ProtectedSession所有者；
一次性创建/首次恢复许可、安装/策略/SessionId/Job/SID/fence/固定资源绑定，复用原AtomicChild、
PersistentFence、ProtectionRuntimeLease和成员核验，连接到撤销、封闭、零成员与资源清理。

实际SessionProxy转发源码已接线：仅固定自有HTTPS目标，受保护侧新WFP允许17891而非原始7890，
每会话认证+精确Job/token/监听核验，经固定DoH解析并审查A/CNAME回答后发送字面IP上游CONNECT；
无宿主DNS解析或直连回退。详情与实际调用接点见[主链说明](PROTECTED-SESSION-CHAIN.md)。

**正向会话仍不能运行**：14项可信采集当前均UNKNOWN，独立宿主资源/通道实机/资源授权也UNKNOWN；
旧7890 fence需要封闭迁移，当前拒绝复用。真实Claude继续DEFERRED_BY_USER，系统测试停止有效。
公开库入口的系统资格、安装和admission-child也补上同一事故阻断；未运行这些代码。

验证仅SOURCE：六项目非生成语义检查0错误/0警告；共享转发解析负向用例未执行。
原始报告为 `outputs/session-chain-closure-source-types.json` 和
`outputs/session-chain-final-policy-source-types.json`（不入Git；后者仅测试源码分析）。
BUILD / VERIFIED无本轮新增；新代码未安装，完整产品非DELIVERABLE，未改AV/日常网络/FlClash。
后续缺口是实际可信采集/环境策略、当前工件安全资格、旧屏障迁移、宿主敏感资源及授权工具/GPU，
以及在事故调查和具体安全条件满足后的集中实机验收。不能把源码接线或单个合成负载当全产品完成。

## 上一轮PR接收记录（历史窗口）

**本轮完成源码接收和限定修复，完整产品仍非 DELIVERABLE；系统测试继续 BLOCKED。**
用户本次第五节明确保留 0x1E 后的系统测试阻断，替代历史重新授权描述。本轮未构建、安装、
运行新产品或离线调试器，未做 WFP/Job/Watchdog 测试、故障注入、UAC 或网络/AV 修改。

当前分支 `codex/integrate-privacy-admission-20261027`，接续起点 `587ef08`、工作区干净。
重新 fetch 后 origin/main=`8e5b4ee`；两个 PR 仍 draft/open/unmerged，头分别
`eb2300e` / `950836b`。原始开发提交及本地修复均在当前分支；未推送、未修改远端 README/origin。

SOURCE / 调用链已接入：本地整合 PR #1 的固定 canary 成员检查并持有进程对象直至第二次快照/判定，
拒绝重复 PID、主进程创建时间不符；整合 PR #2 的日常十四项报告及诊断目标限制，补工程项目引用、
GUI preflight 调用、严格时间与目的地拒绝。Broker 新 `launch` 仅核验安装并返回十四项当前可信采集缺失，
不接收日常报告/旧 PASS、创建进程或转用 qualification；这是启动拒绝路径，尚不是完整可用许可链。
原始 FlClash 仍仅资格通道，目的地候选策略未构成正式转发边界。

本轮后续修复已进入既有 GUI / Broker / Bootstrap 源码入口：

- GUI 显示十四项中文状态和处理建议，报告缺失/重复/格式异常/伪造授权时不显示正向结果；
  两分钟时效独立核对，每15秒仅重绘失效状态，不反复运行检查；FAIL 保留，原始报告仍可保存。
- 五个 Broker 系统 `qualify-*` 入口在权限/安装读取和原生调用前返回125；Bootstrap 安装/更新同样拒绝。
  只读诊断和精确 quarantine 恢复分开保留。本轮未执行它们，已有安装包不会自动获得源码新限制。

| 证据等级 | 本次实际状态 |
| --- | --- |
| SOURCE | 六产品项目非生成语义检查0错误/0警告；PolicySmoke七个源输入同样仅语义检查，无诊断 |
| BUILD | 实时核实原PR #1 Windows Broker/Lifecycle编译、原PR #2 Windows daily编译成功；本机整合后未构建 |
| INTEGRATED | 成员核验进入原Watchdog资格链；十四项进入daily/GUI；Broker正式启动仅拒绝；新入口阻断是SOURCE接入 |
| VERIFIED | 原PR #2纯托管CI成功限其提交；新增GUI负向用例未执行；没有本次新实机功能验收 |
| DELIVERABLE | 完整保护产品未完成，当前补丁也未安装；不能当作可用保护版本 |
| DEFERRED | 真实Claude登录、推理与正式会话DEFERRED_BY_USER |
| BLOCKED | 蓝屏归因/故障栈仍UNKNOWN；整合工件的本机构建、安装、系统运行及故障注入保持停止 |

原始报告（不入Git）：`outputs/pr-intake-closure-source-types.json`、
`outputs/pr-intake-test-source-analysis-final.json`；均未Emit/MSBuild/restore或加载/执行产品程序集。
只读进程检查未见四个产品名称的进程，AVP21.26/BFE运行；这是有限快照，不是完整AV或主机安全证明。

下一条网络生产缺口是可信转发实际执行目的地限制、可信解析与字面IP连接，并拒绝受保护侧绕过到原始7890；
还缺代理中继访问宿主管理接口、DNS服务代发、工具子进程与敏感资源隔离的实际拒绝证据。
十四项仍缺Broker当前可信采集、明确用户策略、安装/策略/目标/工作区/工具/设备及会话绑定、
创建与首次恢复前实时复核、证据失效及运行撤销。当前并无完整正向许可签发链，不能以报告/UI修复代替。

完整差异与接收决定见 [本轮整合记录](INTEGRATION-20261027.md)。本次无需例行审批；
恢复系统测试须先取得事故调查和具体工件的安全条件，不从CI推导授权。

## 以下为此前安装、运行及接续窗口的历史记录

下文“当前”“下一步”“目标恢复”等均指各自当时，不覆盖上方本次结论。
前次测试重新授权曾存在，已由本次保留系统测试阻断的明确要求收紧；不删除其历史。

更新时间：2026-10-27，最新实际运行窗口07:10Z（America/New_York）。当前状态以本页为准；旧版本、原失败、各轮源码/构建描述完整保存在[历史状态快照](STATUS-HISTORY-20261027.md)和[历史验收账本](PROJECT-ACCEPTANCE.md)，其中“当前”“待执行”均指各自当时，不代表今天的选择。

## 当前系统事件：停止运行验证

**BLOCKED（运行验证）：测试窗口发生系统蓝屏0x1E，因果关系UNKNOWN。** 已停止新增产品构建/安装/执行和故障注入，先做只读故障定位。未发重启命令并不证明测试无关；在查明原因前重复诊断的操作已停止。当前无本轮产品测试进程，真实Claude继续延期。当前安装实际为814cf4331fcb4fd6a95fee2973b734a6/3EB4F1A88CAC2B3CFB6A561B357E65600745F6B989D8D9A7916A7FA0537FC7BD，operation81960efc780d462395c796056a4e0861，INACTIVE；下方版本/通过范围为历史。详见[系统蓝屏事件](INCIDENT-20261027-SYSTEM-CRASH.md)。
## 结论与统一目标

**四阶段限定网络矩阵已实际通过，隔离内小型CUDA计算亦有原c9包成功证据；完整产品尚非DELIVERABLE。** 当前网络结果/范围见[四阶段网络资格](NETWORK-QUALIFICATION-20261027.md)。

[2026-10-27完整产品指导](PRODUCT-DIRECTION-20261027.md)统一要求网络、严格十四项可信门禁、独立系统安全准入、宿主敏感资源隔离、可用开发工具/子进程及本机GPU。不得以局部成功宣布整体完成。真实Claude登录/推理/正式会话继续DEFERRED_BY_USER。

目标运行已恢复active；上一轮usageLimited是当时终态记录，不是功能完成。上一轮分类为progress：严格CRL依赖修正及四阶段限定网络矩阵通过。当前继续原目标及完整2026-10-27要求，不声称会话停止后后台继续。

## 当前安装与运行证据

- 当前release：fd4f9f85655342cebc46aab4d19982d8；manifest SHA256 7EC62DE8F572CBED678616FF2E1F1A815C520463BD172E998A546CA975A7593C；operation 3f63a9da217f47fdada03d298146cfce，INACTIVE。
- 当前生命周期DLL SHA256 A8C9ACF27EC9BF1CEDAD03F9ACBBBA6C4E07C84DFC8AFE412AC0578318D1F8C1；正式代码C:\Program Files\ClaudeCodeProtection\versions\上述release，私有状态C:\Program Files\ClaudeCodeProtection-State。旧版、原bootstrap及全部失败保留。
- 本轮管理图34输入BUILD0、bootstrap35输入BUILD0；限定离线、SDK8.0.422/ref8.0.28、无第三方包/分析器/生成器。非生成检查6项目0错误/警告；无module initializer。
- 28项既有TLS/GPU/UDP/ASN判据、6项吊销候选拒绝和6项内存native原语通过；是限定验证，非完整保护证明。普通用户inspect-runtime0，其余受限管理/子进程入口125拒绝。
- 已安装更新20项来源/嵌入批准及14资产哈希/权限/普通写拒绝核对成功。原9项GUI/daily字节复用，当前目录GUI未重新打开；没有常驻产品进程、服务或自启动。

| 能力 | 证据等级与实际结果 | 尚不能据此得出 |
| --- | --- | --- |
| 原子进程准入 | INTEGRATED、限定VERIFIED：安装AppContainer SID、Low4096、capability0、Job绑定均在创建时完成，挂起核对后首次恢复 | 任意Claude/工具可运行、所有子进程完整归属 |
| 持久网络隔离 | INTEGRATED、限定VERIFIED：最终独立只读回读6角色完整，最新filterId103002–103007、子层weight65533 | 重启/全机外网、系统DNS服务流量全部归属 |
| 本地网络负向 | 限定VERIFIED：对照6路各1收据；完整隔离及代理开放阶段TCP4其他端口/地址、TCP6均10013，UDP4/6/原始UDP53发送调用可能成功但独立nonce收据均0，负向窗口2秒，collector健康 | UDP发送API被拒绝、物理出口无泄漏、系统解析器已覆盖 |
| 指定代理 | TCP连接127.0.0.1:7890实际成功；既有FlClash进程/创建时间/磁盘映像/监听身份受持有核对 | TLS/Claude服务/真实出口成功；映射内存与磁盘逐字节相同 |
| 严格HTTPS | 限定INTEGRATED/VERIFIED：原OS离线错误保留；3份经代理取得的固定CRL在进程内严格检查均通过，最终HTTPS200 | 其他TLS栈/CA/网站已兼容；不能关闭吊销检查或泛化放行 |
| NVIDIA GPU | c9e823版本限定VERIFIED：宿主及隔离内RTX4060均完成16项Driver API、1KiB显存、256整数加7内核、同步/全量回读/同摘要、释放成功 | PyTorch、代表性大型工作负载、其他进程GPU内存隔离；新ebd库不继承旧包运行证据 |
| 精确生命周期 | 累计21个登记Job均有绑定一次性准入摘要的关闭/零成员回执；每次精确豁免已移除、原其他项保持，profile Delete API0 | profile独立不存在、进程崩溃/断电/重启、活动更新/卸载已验收 |
| 严格十四项与系统门禁 | 统一要求已SOURCE记录；当前正式Claude启动仍关闭，未有完整可信体检准入链 | 十四项已实现/全绿或CLI可绕过启动 |
| 文件/注册表/进程敏感资源与开发工具 | 已有安装状态/资产权限验证；面向开发侧的完整资源拒绝+授权工作区/工具/子进程纵向评估尚缺 | 完整宿主保密、Git/Python/Node/PowerShell等开发兼容已通过 |
| 完整交付 | 未完成；真实ClaudeDEFERRED_BY_USER | 可交付完整产品或持续后台保护 |

## 本轮关键原始记录

**GPU成功**：c9e8231060b14950a878ad56a4e05260，manifest49B57CE036DBE8391D9967875BE1A7CB4505EB0F92407040DB88EE4CF7CB6CBE，request93054db03fd842dbb0c9be331e8abebb，Job e655fd78177b4a65a29c92616f95eb3c，child40508。结果SHA256 4ADEB88C463E46506A15EF3743B8E106C7554A7CE7427BE97E291713B95A4034，宿主/子进程一致；网络未开放。ProgramFiles/ClaudeCodeProtection-Gpu-20261027-r1、work/gpu-run-r1-control及私有回执保留。GPU仅搜索System32 nvcuda.dll，实际签名Valid、驱动32.0.16.1047、CUDA Driver版本13030；固定驱动摘要/只读租约，不下载/运行模型、不改设备/驱动设置、不CPU替代。

**历史TLS失败（r6，原样保留）**：request21720be4982541ca9543e0ba8835e12b，代理阶段Job d501d256092e41feb43ec85784d9c64a，child41488。ProgramFiles/ClaudeCodeProtection-Network-20261027-r6与work/network-run-r6-control及私有记录保留。64=RevocationStatusUnknown、16777216=OfflineRevocation，已用本机枚举与[微软定义](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509chainstatusflags)核对。观测确认吊销依赖无法完成；具体CRL/OCSP请求与流量归属尚未抓取，因此“受限系统验证路径”是待核实原因，不是已经证明全机吊销服务停机。此轮未执行第四阶段，最终完整隔离回读成功。不得将前几轮信息较少的FAIL改写为通过。

TLS诊断callback仍要求certificate/chain存在、PolicyErrors0、所有ChainStatus0，吊销检查开启；没有接受任意证书。UDP send完成不等于投递，见[微软sendto契约](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-sendto)。这些条件与当前有限证据明确分开。

## 下一步工程判断与剩余缺口

1. 固定Microsoft资格的吊销路径已修复且四阶段通过，停止重复相同成功矩阵。接续生产运行租约/Watchdog及工具自有代理、控制器崩溃/规则漂移注入，保持FlClash日常组件不动；先明确持久屏障/Job句柄所有权、精确故障信号、恢复/封闭证明，避免把名字消失当零成员。
2. 系统DNS经服务代理、物理出口、真实代理/控制器崩溃、重启仍UNKNOWN。当前TLS修正限固定CA/分区，第三方TLS依赖及受限代理防本地管理转向仍需产品集成；不把自有HTTPS成功当完整工具网络保护。
3. 尽早做自有敏感文件/注册表/进程对象拒绝与授权工作区读写、代表性工具/子进程同时可用的纵向切片；明确管理侧和开发侧权限。GPU已证明当前边界可计算，无须为此撤销边界；随后按需要补PyTorch/代表工作负载。
4. 将十四项环境信息与独立系统安全条件接入同一可信Broker/原子准入/实际会话绑定、时效与失效撤销；接通GUI状态。不存在用旧PASS或GUI绿色代替当前安全授权的捷径。
5. 完成恢复、维护冲突/中断、活动更新、精确卸载与普通用户日常流程；当前固定INACTIVE迁移不当作通用生命周期完成。

## 保留边界

Kaspersky事件未解决；有限Application观察无新告警，完整厂商告警覆盖UNKNOWN。AVP/BFE运行、FlClash/Core20944/14268保持；没有重配Global/系统代理/TUN，没有全机DNS/IPv6/时区更改，没有退休样本/旧聚合自测/AV排除或规避。UAC本人控制。真实Claude规则仍禁用、未启动Claude。最后检查没有本轮产品测试进程存活。

原有origin及Git历史保留，已安全合并用户README的ddb9d9c到49ac5c1，未推送；后续本地提交仍只包含可审查源码/文档，状态、日志、备份、PID、二进制和私人数据不入Git。当前页面整理只移动历史文本，保留[历史快照](STATUS-HISTORY-20261027.md)原字节；历史快照和账本不具有新的运行授权。

## 吊销定位与修正的阶段历史（以下“当前”“待”指当时）

当前实际安装仍ebd633；新SOURCE只扩展固定Microsoft HTTPS诊断：宿主/子进程同样记录每张证书SHA256、逐项链状态及CRL Distribution Points，限8层链/16KiB扩展/8级ASN深度/16地址/每项1024字符，解析错误明确保留。证书地址是不可信观察，未新增任何目标访问/信任库/缓存写入，不放行任意CA地址，不放宽TLS。6项目非生成0错误/警告。fa755f8管理图33输入离线BUILD0，无module initializer；7项ASN解析容量/畸形负向通过，原21项判据与普通命令拒绝通过，无新网络调用。批准26719a907d0a4863b68c6e46d24d4dfb，manifest A31A246BFE3A021B3E443138906119BDAFD8518EBDC0B8CB349D87E0BFFBE2BD；待独立bootstrap及实际观察。

普通用户CAPI2只读查询返回权限拒绝，保留UNKNOWN，不启用日志。通过系统curl读取公开链的进程启动被自动审批审查拒绝（仅blocked by policy、无细分原因），该启动没有执行，不换壳重试。改为已安装Broker原有资格入口内的受审查观察，沿用具体工件构建/资格/人类UAC边界。
26719a固定bootstrap34输入BUILD0/安装更新0；网络request24ea1a4ee5f24e27a2dd69aada09319b实际3。host/child同一4证书链，leaf均无链错误，隔离中间证书64/16777216，实际观察到Microsoft两类CRL及DigiCert GlobalRootG2分发点。没有自动请求这些URL，原严格FAIL保留；ProgramFiles/ClaudeCodeProtection-Network-20261027-r7和私有回执保留，完整隔离/Job/精确豁免清理、AV/BFE/FlClash保持。

下一修正SOURCE见[TLS进程内吊销补充](TLS-REVOCATION-SOURCE.md)：只对固定Microsoft资格目标及精确issuer/地址补充3份通过指定代理取得的CRL，以签名/时间/范围/直接吊销查询+Windows显式memory store CACHE_ONLY原生检查证明状态，不忽略其他TLS错误，不导入全局信任。当前managed非生成6项目0错误/警告（生命周期27源），0a93899管理图34输入BUILD0；无module initializer，6个内存native原语案例全部符合：valid接受、revoked/expired/bad-signature/wrong-issuer/malformed拒绝，6项TLS候选拒绝资格通过。未访问网络或系统信任库；原其他28项资格及普通入口拒绝通过。批准fd4f9f85655342cebc46aab4d19982d8，manifest7EC62DE8F572CBED678616FF2E1F1A815C520463BD172E998A546CA975A7593C；尚待bootstrap/真实TLS，不覆盖原失败或第三方工具TLS资格。

## 当前运行收尾

request ce160d0fddd4471c977c2c36080fceec实际0，四阶段匹配、最终主机正向6项/受保护迟到收据0；21 Job绑定关闭与19豁免精确清理回读完成，6持久角色完整、无存活本轮产品进程。原始路径与详细范围见四阶段网络资格文档。目标保持active，不标完整交付。

## 本轮进行中：运行租约与故障响应

新SOURCE把原代理阶段轮询接入共用ProtectionRuntimeLease，绑定选择摘要/核验版/一次性Job/代理身份/fence与有界期限；停止先回读隔离，再精确Job终止/零成员及关闭回执，记录时序。新增已安装固定qualify-watchdog，用自有长活canary验证1000ms期限到期和本工具收窄隔离漂移，不停止FlClash、不移除守卫、不把两例冒充代理/控制器崩溃。源契约/缺口见[RUNTIME-WATCHDOG-SOURCE](RUNTIME-WATCHDOG-SOURCE.md)。生命周期28源；首次非生成检查因漏传Enable的control参数1错，原报告保留，修正后6项目0错0警告。4fcd3ec管理图35输入BUILD0、无module initializer；40项既有判据/native资格通过，普通qualify-watchdog等入口125拒绝。批准7a235d0d3395432b97b114f8b57fee22，manifest3B2DBEDD06AF0B8230E3527CEC2790159CCEA9A36F8A2E3CF4213BC0CC25D9B3；待独立bootstrap及真实Watchdog。新库不继承fd4f网络或c9 GPU运行证据。
## Watchdog首次运行与成员诊断

5635752独立bootstrap36输入BUILD0，7a235d0d3395432b97b114f8b57fee22/3B2DBEDD06AF0B8230E3527CEC2790159CCEA9A36F8A2E3CF4213BC0CC25D9B3已INACTIVE更新0，operation448bc1a84ff34e048cad02ecad5c3460。首次Watchdog requestddb0939b095643119aa04c2f28a60505退出3：ready HTTPS200，但Job3a7ddf9f7c934b55a6b3ef6ea219bf96由首次恢复前唯一PID13696变为13696+34780，严格唯一目标核对拒绝，未做期限/漂移注入。失败后共用Stop已观察完整隔离先于Job停止、真实零成员/关闭回执，精确豁免/profile清理，AV/BFE/FlClash保持。原ProgramFiles/ClaudeCodeProtection-Watchdog-20261027及私有记录保留；多出成员身份仍UNKNOWN，不能忽略或按名字放行。

当前SOURCE新增仅对同一Job已枚举成员的只读身份诊断，先持有句柄并IsProcessInJob确认归属再读映像/创建时间/令牌，失败逐项保留；无终止权限/外部PID接口，目标唯一检查不放宽。前后Job快照与成员诊断先记录再拒绝，帮助判断下一实际修正。6项目非生成0错0警告；2bc326f管理图35输入BUILD0、40项资格与普通入口拒绝通过，批准814cf4331fcb4fd6a95fee2973b734a6/3EB4F1A88CAC2B3CFB6A561B357E65600745F6B989D8D9A7916A7FA0537FC7BD；待bootstrap/安装及成员诊断运行。新版本不继承旧网络/GPU证据。
## 蓝屏只读定位接续（08:12Z）

原转储SHA已取得：C38F6F02C3CEEBC6FD2A9628C76E2D671D0C8D855E6AAD5997291989D3A1FC92，7030648字节；WER确认BlueScreen/0x1E参数，无驱动栈。已有成员诊断确认额外conhost同Job/同AppContainer，不证明它导致蓝屏，未放宽准入或恢复测试。

WER目录读取辅助进程曾异常增长；首次停止UAC取消后，经用户明确允许重显UAC，仅精确终止PID18080/创建时刻匹配的helper，停止回执08:06:15.580Z，当前不存在。单个WER的有界读取替代路径已退出0；原失败/取消/资源异常保留，原因未猜测。

微软官方WinDbg工具已下载/签名核验，未系统安装/执行；离线分析调试器的启动被自动审批拒绝（仅blocked by policy），没有换入口绕过。故障模块、内核栈及测试因果仍UNKNOWN，产品构建/安装/运行/故障注入保持BLOCKED。完整事件/工具来源/证据及手动离线诊断步骤见INCIDENT-20261027-SYSTEM-CRASH.md。无产品测试进程，AV/BFE/日常FlClash保持；目标未完成。
