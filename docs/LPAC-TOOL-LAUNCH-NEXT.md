# LPAC工具启动：当前真实状态与下一次验证

当前已安装589f8b3cbbd04cb4be742bb09f52e3e7 / manifest164AD85F444447B6683370309FA2EDCE2A5D000A62037FD39B1CB5FE227D04C4，保持INACTIVE。07:20:55Z固定更新和只读manifest资源检查完成；15文件摘要、受保护DACL、可信所有者、无非可信写入已独立核对，宿主单键权限未变，无新Job/profile/工作负载，无残留产品进程。

必须保留本次操作失误：从旧模板生成的安装launcher缺少显式Preflight参数，传入-Preflight被忽略，导致尚未提出这次具体安装授权问题就触发UAC并实际更新。我未自动确认UAC，但这仍违反先提出具体授权的顺序。原脚本/记录保留，修正版已实际只读返回；生成器现强制加入预检声明和UAC前return。后续资源运行没有执行，仍需单独明确授权。任何launcher不得仅凭旧模板名称假定支持预检。

## 已解决和未解决

原生trace7确认Windows启动代码读取固定SideBySide键被拒。精确单键当前包SID读取租约的安全描述符读取缺陷已修复；74c34612真实运行确认授予和闭Job后精确撤销，独立前后完整权限相同。PowerShell错误由5变为14001，仍未成功。一次已授权Windows sxstrace完成，但未给出具体缺失资源；不再重复相似跟踪，不增加registryRead、子键或通用宿主授权。

新的启动方式复用原Broker和原Job：原受限worker通过已有匿名报告管道请求编译固定PowerShell/Git操作；原所有者核对会话、序号、根身份、固定参数和清洁环境，然后在创建时原子绑定LPAC、同一零能力包和原Job，挂起检查实际令牌/映像/Job及进程线程权限，再恢复工具。开发进程仅收到SYNCHRONIZE|QUERY_LIMITED_INFORMATION(101000)及三条不继承标准流管道；不转移管理员令牌、Broker/Job/线程句柄，不在高权限下执行工具或项目代码。绑定来自原Broker原子创建，不宣称操作系统父子继承。

六产品非生成语义通过；57输入离线构建和58输入Bootstrap构建通过，后者复用原A40E232D库。固定命令/环境与有界消息拒绝检查通过；普通自有进程/管道转移实测确认访问掩码101000、四句柄不继承及三方向字节流。两个错误尺寸查询的失败保留，依Microsoft公开56字节结构修正测试后通过，未重建生产库。这些普通检查不等同于LPAC工具成功。

## 待授权：一次固定离线工具运行，一次本人UAC

work/owned-tool-control/run-launch.ps1仅调用当前安装原Broker的qualify-toolchain一次：固定PowerShell、固定离线Git、授权任务目录I/O与既有私有状态/AAP样本/Broker对象拒绝，沿原准入、监督、成果和清理所有者执行。保持相同单键、同一包SID、KEY_READ无继承的临时权限及闭Job后精确恢复；helper独立核对前后权限。

40秒主期限、1秒排空。未完成时只结束本次新建且持有句柄、映像/创建时刻匹配的确切Broker，不结束其他进程；其退出不能作为Job关闭证明。不自动重试、恢复、增加权限或开放网络。不运行输入项目代码/Claude，不更改日常AV、驱动、全机ACL、网络、FlClash或UU。工具成功也仅资格这一固定调用链，非全面宿主隐私/14项/真实网络/GPU/正式项目编译验收。

| 冻结运行输入 | SHA256 |
|---|---|
| Lifecycle库 | A40E232DB54070AE21417962DC4AEB77DE10A83FF6797696FE45164335429AA4 |
| 运行plan | 015591436995390EE2FEC809EA2F2B44946C055B84EB93E2A102F1C74CABC6A6 |
| 运行helper | 08091EDF02646AB4CA3960A8F97BFA8E48BE8FC0C5EA2E7D4B6461F5BC943966 |
| 运行launcher | 6C9609E21C58274C769459B750763D6AD9B81537218D140CAFA6367E7AA90DAC |

完整审查work/owned-tool-control/system-operation-review.json；安装证据installed-evidence，普通资格work/owned-tool-build-r1/qualification.json及work/owned-tool-fixture-r3。用户指示和AGENTS.md均要求新受保护资源运行先明确授权、本人确认UAC；这次运行尚未授权。
