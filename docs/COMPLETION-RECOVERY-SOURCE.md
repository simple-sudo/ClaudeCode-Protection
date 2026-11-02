# 完成回执的新观察恢复与状态发布源码

> 文档效力（2026-11-02）：完成回执恢复专题。重新观察不重建历史成功、不推进未证实阶段；不能凭本页自动恢复系统。P0自我保护同时保留可信用户诊断及恢复权，拒绝不可信调用者借用。
> 最新状态/授权只见[CURRENT-STATE](CURRENT-STATE.md)，正式目标与术语见[SECURITY-REQUIREMENTS](SECURITY-REQUIREMENTS.md)。以下旧状态与操作许可不自动延续。

日期：2026-10-26（America/New_York）。状态：SOURCE_IMPLEMENTED_NOT_COMPILED。新增CompletionRecovery.cs，接入原完成记录生产者及卸载读取器。没有执行该库、调用安全/文件变更API、编译或类型检查。

## 状态记录先完整暂存再发布

ProtectedState.WriteNew不再直接写最终逻辑账本名称，而是在已锁定的私有管理员目录中CREATE_NEW一个pending-record随机文件，写入/Flush(true)/按字节回读后，保存卷/对象ID，再使用同目录不覆盖移动发布到固定内部leaf；发布后回读对象ID和摘要。既有目标不覆盖，失败保留暂存文件，不以File.Exists区分缺失。

pending-record前缀被保留，普通逻辑调用不能指定；它不会匹配operation/plan/release等阅读器前缀。未完成的暂存内容不是已提交的阶段记录。该顺序旨在减少进程中断导致最终账本半写入的窗口，尚无本机故障实证，不宣称断电持久性、卷flush或所有平台原子性。初始化身份仍由原来的固定身份恢复处理；已存在的旧坏记录不会被这个发布方法自动修好。

## 只从实际完整字节重新观察

CompletionReceiptRecovery.ReobserveOperation只接受原install/update操作ID、受保护状态和实际运行期租约；没有任意文件路径/角色/hash/调用者PASS参数。沿固定CodeMarker、VersionMarker、PackageManifest及14个资产角色重新定位文件，核对原私有计划、持久begin、stage intent、角色/操作标记、最终路径、ACL/owner和实际句柄完整字节。读取的FileStream不执行程序。

文件属于另一个已验证操作时保留；源文件确实不存在只记录SOURCE_ABSENT_NO_RECEIPT_CREATED；实际字节未达到原授权完整摘要/长度、未知身份、祖先不可用或查询失败均拒绝。既有有效完成回执必须与同对象和同字节匹配，否则保留并拒绝，不能以“现在看起来正确”为由覆盖原冲突。

只有完成回执缺失、零字节或JSON语法损坏时，才生成新观察。输入回执上限8KiB；判断语法损坏时允许该字节上限内足够的嵌套深度，避免把有效但复杂的外来JSON误当截断。合法JSON但字段/版本/身份/状态冲突不属于可修复输入。

## 原始证据和新回执分开

先以新状态发布协议保存completion-before记录：原回执是否存在、原对象ID、原始字节base64、长度/SHA-256、本次重新观察的源对象ID/长度/SHA、操作/角色和新时间。原数据完整保存成功后，缺失回执才CREATE_NEW；已有损坏回执则只在同一个禁止共享写/删除且已核验的可写句柄中写入并flush/回读。

新完成回执schema 2明确使用FRESH_BYTES_REOBSERVED、RecoveryId、BeforeSHA256和ObservedAtUtc。它没有复原原完成时间或旧PASS。源码读取schema 2时必须验证before原始字节摘要、身份、缺失/语法损坏资格、来源操作/角色以及本次实际文件观察；原schema 1仍保留BYTES_VERIFIED语义，不重写旧成功。

保存after记录和逐项batch观察；异常保存失败角色、错误类型、NativeErrorCode/HResult及此前已观察项，再抛出原异常。失败记录本身写失败时保留两个异常。一次恢复中途失败可能已有若干独立新回执，相关before/after记录保留，不伪造整批成功。没有发布release、修改current、推进生命周期阶段、重启程序或授予包批准。

新回执只供完整预期字节使用；部分文件加上坏完成回执仍拒绝，不能把可能的完成后漂移降级为pending。原始receipt语法完整但冲突、超大或权限/身份不符同样拒绝。

## 验证与仍未完成

本轮29份维护C#仅Roslyn ParseText、15份PowerShell仅语法解析，显式项目文件/资源核对；没有编译、类型检查、加载项目库或运行功能测试。必须本机验证暂存/移动/回读各中断点、最终目标已存在、共享冲突、磁盘写失败、源文件锁、原始回执保存前后中断、schema 2来源篡改/嵌套冲突、缺失与查询失败区分以及AV行为。

恢复入口尚未接入生产broker。实际admission/Job/WFP owner仍只有接口；可信bootstrap、生产broker/传输、用户态状态目录和完整本机验收仍缺失。损坏stage intent、plan/operation账本、release/restage/selection发布记录与卸载清单的专用恢复仍未实现；不能用本次完成回执恢复宣称所有私有状态或中断窗口已闭合。

原构建/运行停止条件和空批准包pin保持。AV开启，新告警立即停止，不恢复退役EXE、不重跑旧selftest、不以排除/改名/重包装/关闭防护绕过；不改日常FlClash/TUN/BFE/全局网络，不要求VM或重启。真实Claude仍DEFERRED_BY_USER，IPv6仅阻断与必要负向测试。完整目标active。

依据：[File.Move不覆盖行为](https://learn.microsoft.com/en-us/dotnet/api/system.io.file.move?view=net-8.0)、[FileStream.Flush](https://learn.microsoft.com/en-us/dotNet/API/system.io.filestream.flush?view=net-8.0)。官方API说明不等于本设计、本机崩溃恢复或断电资格。
