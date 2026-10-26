# 创建身份、初始状态修复与缺失判定

日期：2026-10-25（America/New_York）。状态：SOURCE_IMPLEMENTED_NOT_COMPILED。本文记录设计和源码，未调用创建/修复/删除方法、设置实际ACL或进行Windows身份往返验收。

## 为什么创建后回执还不够

先创建对象、再把卷/文件ID写入状态，中间仍可能中断。新增 CreationIdentity.cs 将归属标记一并放入 CreateDirectory/CreateFile 的初始安全描述符；成功返回后立即从实际句柄回读owner/DACL和标记。源代码不再把“目录名字正确”或“计划存在”单独当归属证据。

标记是普通、非继承、仅READ_CONTROL的ACE，数字SID用于本应用的元数据编码。它不注册账户或服务，不产生进程token、不授予写/删除/执行权限，也不是Windows签发的服务身份、包签名或WFP package SID。数字形状不能被拿去作为网络过滤范围。

标记本身不能阻止提前伪造同名目录，因此管理员状态根改为ProgramFiles下独立的ClaudeCodeProtection-State，与ClaudeCodeProtection代码根并列；不再以可由普通用户创建子目录的ProgramData父目录作为初始化信任位置。创建、打开或初始化修复时都要求父目录的适用ACE不向普通主体授予创建/写/删除权限。只对子项继承、不适用于父目录本身的ACE按其实际范围处理。此项不修改父ACL，不移动/删除既有ProgramData或项目state，代码卸载保留私有状态兄弟目录。

26个固定角色编码状态根、代码根、各目录、元数据和14个固定资产。状态/代码根绑定本安装ID；暂存对象绑定原install/update操作ID，角色与release再通过私有管理员计划和stage intent交叉核对。ID不是秘密，安全边界仍依赖受保护owner/DACL、固定路径及管理员账本；不防恶意管理员/内核或已受控bootstrap。未知、继承、重复、回调、权限扩大或角色不符的标记均拒绝，不给既有未标记对象补标记来接管。

这是基于Windows支持初始安全描述符和普通ACE的设计推断。数字标记的实际保留、canonicalization、RC权限、拒绝反例、文件系统与AV兼容性尚未测；若系统不保留或改变语义，源码应失败并保留现场，不能放宽权限重试。

## 已接入的生产者与读者

状态根在创建前生成安装ID，在同一创建调用提交受保护DACL和对应标记；身份文件也使用固定角色标记。代码根、versions、release/bin/current/center/admin、元数据及资产均在创建时绑定角色。只接受固定角色重建路径，不能让JSON指定其他路径或SID。

字节完成回执从实际FileStream/句柄重新读取、核对授权摘要/长度及路径/标记后生成，不接受调用者传入的“通过”布尔值或任意hash。完成回执只表示字节核验，不授予网络、账号、安全软件或完整安装资格。

版本核验现在检查这些创建范围。卸载目录快照升为schema 2，保存目录标记与卷/对象ID；读取旧schema 1时明确拒绝，不回填新身份。对于已验证创建标记及管理员范围的目录，首marker文件尚未创建的窗口可以记录并按既有空目录规则清理；不能把未知目录或路径碰撞当本工具创建。

## 私有状态初始化修复

RecoverInitialization 只定位固定管理员状态根，要求已存在且初始标记角色为StateRoot、owner/DACL合格。它不会给既有目录改ACL或补标记，不创建/批准包，不恢复程序，也不激活真实Claude。

取得同一操作锁后，只允许修复固定installation.json：不存在时创建具有匹配StateIdentity标记的文件；零字节或JSON截断时，必须先验证原对象标记，并把原始字节、SHA、对象ID和时间存入私有恢复记录，再在同一句柄写入由根标记确定的固定元数据并flush/回读。有效但身份/字段/版本冲突的JSON保持原样并拒绝；有效且一致时不重排原字节。所有其他账本/备份不动。

返回值只表示身份元数据可读。后续每个状态记录仍需自己的严格校验；不能据此说旧失败已修复、包获准、运行期健康或整机无感染。实际可信bootstrap/管理入口仍未实现，没有新增普通用户可调用的管理员执行通道。

## 不存在与读取错误

新增 ExactPathAbsentException，仅由OPEN_EXISTING调用本身返回2/3时构造。打开后最终路径、ACL、卷或身份查询返回相同数值时仍是失败/UNKNOWN，不能被catch误当不存在。清理只允许工具代码根以内的缺失路径；盘根、ProgramFiles等外部祖先不可用不计清理通过。

原始NativeErrorCode和查询阶段保留；不使用File.Exists把不可读变成不存在，也不因为“找不到路径”就报告全部payload已清理。这一调整同样需要后续故障注入/实际API验证，目前只有源码和语法证据。

## 剩余工作与验收边界

本轮未新增模拟C#行为的通过测试。只完成源码语法、文件/项目边界及原始文件状态核对；未编译、类型检查、加载C#库、调用安全API或修复真实状态。

2026-10-26源码更新：零字节/截断程序资产的owned-pending消费方已接入，联合核对创建标记、持久begin/计划、完成回执与未发布状态；卸载快照升为schema 3。前文schema 2为目录身份接入时的历史状态，旧schema不回填。该更新尚无运行资格；损坏私有回执/账本仍拒绝，不能宣布所有创建窗口都已恢复。详见 [部分写入清理边界](PENDING-WRITE-CLEANUP-SOURCE.md)。

需要受控本机验收：初始SD标记实际往返/不继承/无写权限扩大、对象碰撞、未标记与篡改标记拒绝、每个创建/回执窗口、同角色错release/错操作、状态零字节/截断修复前后原字节、有效冲突身份拒绝、元数据查询返回2/3但对象存在、外部祖先失联、部分写与发布后漂移区分。可信bootstrap、生产broker、实际admission/Job/WFP owner及用户态状态适配仍未完成。

当前批准包pin为空，原构建/运行停止条件保持。AV保持开启，不恢复退役EXE、不重复原selftest、不改日常FlClash/TUN/BFE或全局网络、不要求VM或重启。真实Claude仍DEFERRED_BY_USER，IPv6只保留阻断与必要负向测试。完整goal继续active。

依据：[ACE字符串与RC/继承位](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings)、[SID组成](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-components)、[CreateFileW初始安全描述符](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)。这些文档只支持底层API结构，不证明本设计已在本机合格。

## 后续Job角色补充

新增角色27只用于内核Job归属元数据，使用独立SE_KERNEL_OBJECT阅读器和私有Job intent；原26个文件/目录角色不变，不通过文件角色路径函数接管Job。详见 OWNED-JOB-SOURCE.md；仍无实际标记/权限资格。