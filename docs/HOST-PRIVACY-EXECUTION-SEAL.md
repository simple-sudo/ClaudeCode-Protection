# 项目执行前由原所有者封存隐私观察

## 2026-11-02 原门禁新增保护所有者最小进程权限检查

P0-SELF-READ/CONTROL/CHILD接入原HostPrivacyProbe→HostPrivacyExecutionGate→代码释放链。
原14项宿主检查保留；根进程和编译工具各新增九项对同一原Broker所有者的最小OpenProcess：
VM_READ、TERMINATE、CREATE_THREAD、VM_OPERATION、VM_WRITE、DUP_HANDLE、SUSPEND_RESUME、
WRITE_DAC、WRITE_OWNER。每次只请求一个权限，立即关闭；不调用读写内存、终止、挂起、注入、
复制句柄或权限修改。组合权限的拒绝不能代替单项拒绝。原owner只选择自身PID，持有独立
query/wait句柄；两个actor必须与ResourceProbePlan的BrokerPid精确绑定，不接受路径/身份替换。
owner在自身上做同权限打开正控制以保留可信维护；这不是破坏性维护演练。

共同目录为23项，策略指纹升级为V2；缺少九项的旧报告或旧策略不能满足新成功门。
原封存阶段、二次实际Job/token身份检查、不可变副本及结果/闭合/隔离/清理所有者均保持。
没有新执行器、任意PID参数、通用提权或宿主路径读取服务。新版GUI显示实际项目数，不再硬编码14。

SOURCE/BUILD/INTEGRATED，122项原owner合成阶段检查、严格IPC/项目回执、60项普通数据检查及
九权限自有普通进程正控制通过。本人单次项目授权及UAC后，12:51:07Z完成a3b6fab8上固定
CallerWordCount的修改/编译/3测试/十文件结果恢复：root48116/compiler29052共46项拒绝5，
含18项owner权限拒绝；OwnerSealedBeforeCode=true，原导出成功门包含精确闭合/清理。
证据`work/owner-control-gate-20261102-01/protected-run/observed-result.json`
SHA58BD60BABC0311135E6E8E6CD2CE0AA3486CCE82F6824CA2270F85EA1F389C8A。
CAPABILITY_DELIVERED(该固定项目与两个实际受保护actor的最小进程权限拒绝)。未实际破坏owner，
不代表全部自我保护/源码保密/其他工具/IPC/失败恢复/网络/GPU或正式Claude链已验收。

## 2026-11-01 封存机制与限定历史证据

2026-11-01原生实测已通过：当前42f/9172/7DDC的v6 CallerWordCount，project-r2独立本人授权/
UAC后11:55:19Z成功。会话6afe136f45a54bbba5f95acc47245889，root15236/compiler1488各14
真实对象全拒绝5，认证回复OwnerSealedBeforeCode=true；完成改编运行三个测试/清理/十文件
导出核对。原owner成功路径包含前述封存与二次真实身份门，代码后使用内存副本；没有额外raw
Job/Stop读取。证据SHA5EA1649150AC575D8217B831E2EEF8E76C159C76874EC02306672E41BCCD0AEA。
本案例复用，不重跑；不是所有恶意项目/其他宿主API/全产品证明。下方未安装/未原生资格为历史。

当前SOURCE / BUILD / INTEGRATED，六产品非执行语义检查通过，普通纯阶段检查VERIFIED；
尚未安装或实际运行新受保护阶段。
已安装00bc的固定项目与28次真实命名拒绝仍是原实测成果，不升级其历史证据，也不重跑。

接入用户项目前，必须先解决子进程报告可写的问题。旧固定程序在代码执行后由owner读取任务
目录里的检查报告；对已经固定并审阅的TextSummary有效，但任意项目不能把这些可改写文件
当成可信证明。本改动仍保持固定任务输入，先将它的原执行链收紧，尚未放行任意项目。

新顺序全部由同一个原Broker/Job控制：

1. 原worker执行现有14项原生检查，开始固定Git入口并等待原身份门。
2. owner验证持有的Job成员/令牌/映像，同时读取worker检查并复制到owner私有内存；明确14项
   拒绝才释放Git。原Git资格及实际结果复用，操作集合没有扩大。
3. owner只允许一次编译工具创建。编译工具先等待原身份检查，通过后执行自己的14项原生检查。
4. 编译工具发布新ready后等待第二个执行信号；它此时尚未编译或加载项目代码。
5. owner再次验证稳定Job成员、同一个编译工具PID和原LPAC/零capability身份，读取并复制工具
   观察。两端14项均明确拒绝，才消耗一次执行许可并发布执行信号。
6. 项目执行后，owner不再打开子进程可写的观察文件；结果阶段从自己保存的不可变副本生成摘要。
   原目标存在性/文件身份/所持进程最终检查、原Job闭合与成功清理导出门仍然强制。

HostPrivacyExecutionGate是原owner的进程内状态，不接受文件中的阶段声明，不跨进程传递。
拷贝输入与导出数组，避免后续修改引用污染已封存观察。它不提供Job/token证明；调用方必须
先执行现有真实持有句柄检查。重复创建、重复封存、错误角色/PID/会话/计划或缺少成对拒绝
都拒绝执行。编译工具创建阶段开始后不再允许新的Git请求，没有新工具、权限或执行器。

在尚未发布执行许可的失败中，owner仍可读取固定预执行程序产生的有界报告作为失败诊断；
这类报告不能支持成功。执行许可消耗先于信号写入，信号写入失败保持本次失败并停止，不重试。
原20秒runtime、8秒本地等待、10秒根工具等待和原停止/隔离边界均不延长。

这只保证观察在受控预执行阶段采集并被原owner保留，不代表所有宿主资源、持续任意代码访问、
网络、十四准入或PowerShell均已通过。下一步用户项目支持必须显式声明执行范围，保持独立的
输入摘要/编译器/结果验证；不能仅删去当前固定基线检查来扩大接入。

## 本轮构建与资格

source efc40ef的73输入冻结覆盖Lifecycle、Broker和WorkspacePipe及其源链接/嵌入资源。
第一次准备模板误将原本地Lifecycle项目引用判成外部依赖，在构建/测试前拒绝；原FAIL和日志
保留在work/privacy-owner-seal-build-20261101。独立r2仅允许ProtectionLifecycle/1.0.0、type=project、
精确../ProtectionLifecycle/ProtectionLifecycle.csproj；继续拒绝任何外部包。r2离线构建均0错误/
0警告，工具/引用/输入持有与输出目录限制保留。

核心库3EB2AD99ECD12A6AAF8135FBA606300790817D5E04D87F9FE828ED6CC8C044DD，
Broker040092C717460C901F3107F1CEAD836804D924E1878E58D6522C31CBFC8978A6。
PE元数据检查无模块初始化；核心158原生导入与实际00bc/5600逐项不变，Broker0导入。
新WorkspacePipe测试直接源链接生产HostPrivacyExecutionGate，80项普通合成观察检查0/无stderr：
原始及返回数组逐槽改写不能污染owner副本；错阶段、双重创建/封存/释放、错会话/摘要/PID，
以及每一个root OPENED或tool UNKNOWN槽位均阻止推进。不执行原LPAC/Job/项目/真实宿主检查。

证据work/privacy-owner-seal-r2-build-20261101/qualification.json
SHA2EE6C044DD255166DD93F226AB63E0A241FEBA7C9D3460624A4C2A522C7B56B8。
boot07:39:57.5Z、AV/BFE、FlClash25816/20828、UU6812前后一致，厂商覆盖仍UNKNOWN。
没有新安装/受保护操作/UAC/网络/权限变更，也未重跑已经通过的Git/项目/28次真实拒绝资格。
这是新内存封存逻辑的普通资格，不是新两阶段原生Job放行通过或任意项目执行资格。
GUI934E和此核心仍待后续完整候选合并交付。下一候选须加入并核对实际60EC9056前置迁移pin，
不能直接安装此尚未准备迁移/Bootstrap/清单的核心字节或复用已消耗授权。
