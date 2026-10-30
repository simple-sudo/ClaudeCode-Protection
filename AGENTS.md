# ClaudeCode-Protection working rules

2026-10-30 trace3 used an overbroad error-setter breakpoint during state reads
and timed out before any CreateProcess entry (30247 observations). CDB ended,
but its exact owner34888/created134378064365272233 stayed suspended. Separate
human UAC authorized noninvasive stack read and exact termination; stack capture
failed (CDB rejected pv+pd), preserved as FAIL, NOT a successful stack read.
The exact owner ended04:09:54Z, no other process terminated, private state kept.
No Job closure is inferred from this exit. A separately approved windowed trace4
ended normally04:24:37Z but session648555bd01224b6191f56089deebc40d refused
OwnedProfileCleanupRequiresRecovery before child/Job; no retry or recovery.
Evidence work/create-process-trace-installed-r3/r4 and
work/trace3-owner-stop-control/evidence. Do not use the old global breakpoint,
unbounded diagnostic pipe drain, or pd+pv stack combination again.
Source now adds installed read-only recovery inspection and a separate explicit
never-started v2 recovery: complete owned creation, NO profile-job binding,
all admissions durably closed and original exact storage/task owner required.
Existing post-start recovery still requires its prior checkpoint. No missing
Job/process is promoted to never-started proof. New source is not installed;
build/artifact review and concrete human update/recovery decisions still apply.

2026-10-30 authoritative installed041374f666564e41b2731ad354479c8d,
manifest2896E57A537D998D877170C5D7EE98F3B842DAA899E8CD1688F04E767911A68E,
human UAC02:39:44Z INACTIVE; 15 hashes/protected DACLs/read-only intent matched.
508e0bd's 66-input build and ordinary prerequisite-reads/reply passed; d7201fe
Bootstrap reused exact library1C384861 without rebuilding it. Session
125ed422eaca40c5a04600ed4a93a9e8 still PowerShellCreateProcess5, empty result.
Actual LPAC self child/image policies both0 and fixed execute-open0 observed.
Strict same-pipe v3 returns these numbers and trusted owner Stop observations:
admission closed, quarantine before stop, final Job zero, stop failures0.
These do not assert private-storage cleanup or root denial requalification.
Evidence work/workspace-diagnostic-control; workflow-result SHA256
A96CFCBAB84F3709FF4437780F355239467D0CCC17CFC01E639F26729DC92C8E.
No retry/recovery, product remnants or daily UU/FlClash/AV/network changes.
Two separately human-authorized installed debugger observations are preserved.
First session1d82f229 timed out at own conhost first-chance AV; Job e026c732
closed/zero, no stop errors. This is debugger interference, not a new crash or
the original CreateProcess5. Corrected trace session35184e4d52124829b916747140b08288
completed03:51:34Z: actual worker NtCreateUserProcess returned0, then
CreateProcessW returnedfalse/5, without BasepInitAppCompatData entry. Root I/O
and four denials5 passed; Job403ae92e25984823b46e5d903011b93e closed/zero,
stop failures empty, no result. Evidence work/create-process-trace-installed-r2,
analysis SHA256F9EC03BE495146A42FD24B7EE3637FF60242E6E0AD5DFBC9967819E0E6428EED.
This confines the observed failure to post-native-creation work, not a proven
specific ACL/capability or responsible component. Do not retry unchanged or
loosen policy. A fixed numeric error-setter observation is prepared separately;
new protected/live-debug operations require their concrete human decision.
Keep synchronization commitd2407eb. The user explicitly confirms boot
2026-10-30T02:14:46.5Z was their own normal manual operation, not a new crash.
Use a fresh runtime baseline; retain all older evidence and safety boundaries.

Historical 2026-10-29 installedc37ffe49d87840bfbf50c06131205d10,
manifest2A5D02303A96DDDFF17423C7EDAEC67BD94FD5290318E41F77F1BE1B8ED4996C,
human UAC14:53:00Z INACTIVE; 15 files/ACLs/read-only intent matched.
Sessionc29aed3e57c1455ba7ae5f5ed839d7ce still native CreateProcess5.
Root workspace I/O and all four denials5 passed. Exact receipts confirm
Job3498721f05574875bdf18868af4d4a82 closed/zero, full quarantine, no stop errors.
Evidence work/lpac-cwd-control, receipt SHA25600C137823CE48BFFA13191D20749741162234156BC516FEBD8481C1037418830.
No reboot/remnants/daily-network/UU/FlClash/AV changes. No result or tool
compatibility success. Explicit launch attributes, own-token rights (already
10/Changed=false), and cwd inheritance did not repair this failure. Ineffective
token-DACL/cwd branches removed; artifacts/failures preserved. Do not retry
unchanged workloads or infer safe-software exclusion from empty event logs.
Next source uses existing same-owner tool start to query only self child/image
policy and open the fixed held executable with execute access, attaching bounded
numeric observations. It changes no policy/ACL/capability or admission grant.
Source semantic checks only; review/qualify new bytes before actual execution.
Goal remains active, no incident or full product closure. Older current-package
paragraphs below are historical.
2026-10-29 current installed d1b5cf615a7645d882ac982c14d1e2dc, manifest
1F79C28F55857F788023802635F7A0A62DACEEA4BE5CD6BD45035E4A78E42681,
human-UAC update completed14:00:44Z, remains INACTIVE. LPAC data task
641515b1ed88432d9d3816a88578dd25 reached real workspace read/write and
all four root denials: private state read/write, AAP-only fixture read,
Broker VM-read open (all AccessDenied5). Owner pre-resume LPAC mask2 passed.
Then Process.Start(PowerShell with redirected output) failed Win32 error5;
PowerShell/Git identities/workload NOT_CONFIRMED, no result released. Exact
read-only receipt confirms Job00f251370f83481391509b8d9fe53b97 closed/zero,
full quarantine and no stop errors. Evidence work/lpac-paths-control. No
reboot or daily UU/FlClash/AV/network changes. Do not repeat this unchanged
task; no auto-recovery. Source adds fixed failure labels to distinguish .NET
redirect-pipe creation/duplication from CreateProcess, and returns safe error
code/kind through the same daily pipe. This diagnostic source has semantic
checks only; qualify changed artifact before new native operation. Do not
infer LPAC PowerShell incompatibility or grant registryRead/lpacCom from error5.

2026-10-29 current installed startup revision4fe9da3d17714b949915b4b2962586ab,
manifest0337CB5D80ECEB760AC8BF96E49FD699B51A0E9E77ED2284BE4206662EFA549F,
completed human UAC inactive update13:53:27Z. Changed LPAC task
ef285eed144647bf89f7205eb8e79711 failed before tools, with structured
resource-input/InvalidOperationException, self-token query succeeded. Exact
read-only receipt confirms full quarantine and closed/zero Job33286c30,
stop failures empty. Not a successful data roundtrip. Preserve both LPAC
failures/empty outputs; no automatic recovery or unchanged retry.
Source now binds Broker-resolved ProgramFilesRoot into internal v3 resource
plan and verifies its fixed installed child image before use, avoiding worker
KnownFolder/registry/COM lookup. No caller host-path grant or blanket registry
capability. Git/task/fixture subpaths stay fixed and bytes held/verified by
original manager. Only bounded bootstrap error metadata returns to daily,
not private state/path text. Build/targeted runtime-path qualification required
before any new reviewed manual system step. Original full product goal stays.

2026-10-29 user requested UAC again and continued development. Reviewed
997d514a inactive update completed human UAC at 13:45:25Z; 15 installed files
and restricted-package RX matched, read-only Broker intent2/MISSING. Separate
human-UAC four-file LPAC operation e3d1c4a4c512440fbf253994baae2031 returned3,
resumed root exited125 before PowerShell/Git, no result. Exact before/after
receipt readback (manual UAC, read-only) confirms full quarantine, admission
closed and Job e1919105e678426ab37afa1caab1d8cd zero, stop failures empty;
parent JsonException obscured root startup detail. Boot unchanged, no product
remnants, daily UU/FlClash/AV/network unchanged. Preserve all receipts and the
first diagnostic helper's failure. New source keeps manager LPAC verification
mandatory before resume, limits child self-identity to QUERY (no admission
authority), and emits bounded structured bootstrap failure if startup fails.
No unchanged task retry/automatic recovery; qualify changed artifact first.

2026-10-29 LPAC development: source candidate
997d514a9a6445a2925edd32855e5c61 (manifest
3C0471F484A193EF5EFF77A259602BAB8DFF13313B8440C08BF2459DA7D86D18)
reuses the same resource/data owner; creation requires AAP opt-out, token/member
checks require AppContainer plus observed AccessCheck mask2 on an exact
in-memory descriptor (AAP bit1 / ARP bit2). Class46 sizing returned error87 in
an ordinary self-query; preserve it, do not infer LPAC=false/PASS/unsupported.
Ordinary policy/self AccessCheck qualification passed on library8C07FACA;
native LPAC/inherited PowerShell/Git/file denial remains NOT_RUN. No fallback
or registry/COM blanket capability, host ACL change or input project code.
Only newly created public product assets gain ARP RX. The new AAP-only fixture
is non-secret and task-owned, held/ACL checked and cleaned by the original
closed-Job owner. Keep installed ac570b47 INACTIVE until reviewed manual UAC
qualification. Actual new installation/resource steps need human decision.

2026-10-29 current installed workflow result: reviewed caller-rights repair
ac570b474e454a9a94db2310893d3892, manifest
DE88460A1F31721FC69F151B528718DC2FE89ABE66BAEA551E3AD3D8AD8815C4,
completed human-UAC INACTIVE update at 08:31:07Z. After separate human UAC,
installed ordinary daily workspace-process completed session
d57cf00754fc45c8b599617f2c5e41be at 08:31:37Z, input BA1C5764...D4138,
result AA2F0DFD...43483, four selected files unchanged. Original Broker
ProcessWorkspaceBytes/ProtectedSession/Git owner required closed Job, successful
exact cleanup and authoritative success receipt before result export. Installed
daily review/extract both 0; independent base/result/extracted bytes matched.
Evidence work/workspace-pipe-repair-control; old 90079258 refusal and empty
output preserved. No reboot/product remnants or UU/FlClash/AV/network changes.
This makes ordinary pack/process/review/extract usable for explicit DATA only;
do not repeat unchanged proof. Project compilation/test execution, complete P0
resource/network/14-item/GPU privacy and prior interrupted-session recovery
remain unqualified. No general shell/privilege or project-code launch permit.

2026-10-29 installed daily pipeline: approved human-UAC update to
90079258ef8545f19d80e2c211744367 completed 08:18:29Z, remains INACTIVE.
15 installed files matched hashes/protected DACLs; new Broker read-only intent
returned 2/MISSING normally. The authorized ordinary workspace-process attempt
at 08:20Z returned 125/IOException, preserving an empty result and all evidence
in work/workspace-pipe-control/workflow-*. No reboot; no product process left.
Do not retry that attempt or auto-recover private state. Source review plus
ordinary self-token reproduction found QUERY-only token rights cannot support
WindowsPrincipal membership checks (SecurityException); QUERY|DUPLICATE works.
Fix that bounded check and return safe phase/code/session failure metadata.
This deterministic defect is not yet proof of the hidden installed failure;
do not invent original Job/profile/cleanup evidence. New artifact installation
or another protected task still needs its concrete reviewed human system step.

2026-10-29 explicit workspace-pipeline system authorization: user approves
installing reviewed candidate 90079258ef8545f19d80e2c211744367 (manifest
429D76D9B3245DF335D879F27F8CDCC12AF954E79685B8D40BBDC9F50BDFB5FF),
then one limited daily workspace-process data roundtrip for the four selected
repository files, input SHA256
BA1C5764F54DF02B4E9266EE4C6414E28C6D8E8D18F9A07EB91A0CE4DC0D4138.
Use work/workspace-pipe-control's pinned inactive update/read-only helper,
then ordinary installed daily -> human-UAC Broker -> original fixed offline
Git/ProtectedSession -> closed result/export and exact cleanup. Both UAC
confirmations remain human-controlled. This supersedes waiting for this exact
installation/resource step, not formal project-code/network/GPU admission or
automatic retry/recovery. Preserve failures, current/old packages and private
state; keep INACTIVE and all daily UU/FlClash/AV/network settings.

2026-10-29 active-goal continuation: user renews autonomous development,
verification, repair and local commits toward usable authorized projects.
The next production slice is ordinary daily workspace-process -> one human-UAC
installed Broker -> existing data-only ProtectedSession/Git -> closed-result
export -> fresh ordinary-user bundle. A local same-user pipe transfers bytes,
never privileged host paths or arbitrary commands. Review/pin new artifacts;
ordinary IPC/output tests do not need repeated stage permission. Installing a
new package/creating a protected resource session still needs the concrete
human-controlled system step. Keep current installation INACTIVE and preserve crash evidence.
This slice does not authorize input project code, real Claude or weaken the
fourteen-item/host-privacy/network/GPU admission requirements.

2026-10-29 installed repair result: the explicitly authorized manual-UAC
inactive update to 5bc986e16e9a44ca856a1b56b90328aa completed at 07:37Z,
manifest 048E974CD4611B4DB7B577B64DAA5842C5CA02FE08D63298382BBC001FBBEC37,
operation d6e5f46005234e67b3124a7ce175cbd0. Installed Broker environment-intent
read returned 2/MISSING normally, after verified version/lifecycle inventories.
15 installed files and 5 directories passed ordinary hash/ACL readback.
Additional fence-read UAC was canceled once; preserve that failure. User then
explicitly requested UAC again, and the same helper completed at 07:43Z with
Broker exit 0: all six persistent roles matched (107465-107470), no policy or
Job mutation. No new reboot/product processes; AV/BFE/FlClash/UU retained.
Current is 5bc986e1/INACTIVE, not ecb06a. Evidence: work/names-only-control/
installed-evidence and fence-read-r2-*; source/stage/old packages retained.
Do not repeat these unchanged installation/read-only checks. Original workload,
profile cleanup and formal session/GPU/network privacy remain unqualified;
this result is real installed-path progress, not incident/root-cause closure.

2026-10-29 explicit repair-install authorization: the user now permits installing
the reviewed 5bc986e1 repair package, then ONLY the Broker read-only checks and
related follow-up. Proceed with the existing pinned install-launch/helper/plan
in work/names-only-control, human UAC, inactive update and
inspect-session-environment. This supersedes the candidate's wait-for-decision
text below; do not request the same installation permission again. No original
workspace workload, resource/session creation, automatic cleanup/recovery or
network/AV/driver/remote-software changes are included in this approval.

2026-10-29 renewed repair qualification authorization: the user explicitly
permits verification and modification of the preceding stop requirements.
Proceed with the concrete frozen names-only repair: ordinary-user offline
Lifecycle + DirectoryNames build, independent generated-artifact review, then
one pages-only and one owned-fixture run. Analyze and fix failures with bounded
targeted requalification; do not ask for this same scope again. Preserve both
crash dumps, prior failed artifacts/UNKNOWN records and existing installation.
The older blanket build/runtime stop below is historical for this authorized
scope, not a reason to leave the repair untested. This does not authorize
installing/rerunning the original incident workload as diagnosis, unrestricted
privileged execution, AV/driver/global-network/UU/FlClash changes, automatic
UAC, real Claude or remote pushes. Human UAC and specific artifact review still
apply where needed. Report qualification limits; keep the incident open until
the relevant product path has evidence of an effective repair.

Qualification result: 2173dcb's 51-input offline build succeeded with 0 warnings
and errors. Reviewed Lifecycle SHA256 05316042C9D040BA20DF007576981ABA25EBE817F4347408C00AEDF4FAAEB5CC
and DirectoryNames C89DE4F2889179774A606B58BE177A1D1CE7B867B88C0AD30949429F98A64FAB
passed pages-only and the 484-name ordinary-user native fixture, including
multi-page continuation, fresh cursors, capacity refusal and held DELETE handle.
Evidence is work/names-only-qualification-20261029-r1. No install/product entry
point or private state was accessed; this is not original-crash/product closure.
Continue repair artifact preparation toward the same installed owner. Preserve
the exact qualified library where possible; do not repeat these unchanged cases.

Final installation candidate: d38901d adds ONLY the exact current ecb06a
manifest to the existing inactive-update prior-package pins; closure/fence
checks are unchanged. The 53-input final Broker/Lifecycle/DirectoryNames build
passed, and the new final library 70EF78FEE0D73FE5FF9B23B446B15FE928EFE4DB5C8DA0B52FEF50453470B1D5
passed both qualification modes again. cf63e34 embeds release
5bc986e16e9a44ca856a1b56b90328aa / manifest
048E974CD4611B4DB7B577B64DAA5842C5CA02FE08D63298382BBC001FBBEC37.
Bootstrap was built WITHOUT rebuilding that library and holds the same bytes.
The 20-file stage and 10 PE/6 managed metadata checks passed. The historical
pre-install review is work/names-only-control/install-qualification.json; its
manual-UAC path for update-inactive then inspect-session-environment only;
no original workload, resource creation, recovery or network mutation. That
installation decision and execution are now completed above; do not ask again
for the completed qualification/installation or rebuild/retest
unchanged bytes. See STATUS for exact current package and evidence.

2026-10-29 repair continuation: the user insists on solving the crash, not
closing the incident at incomplete attribution. A concrete source candidate now
routes all Lifecycle directory inventories through the existing WindowsPathSeal
using FileNamesInformation (12), retaining independent identity/ACL/tag checks.
Matching Wof disassembly shows class 12 skips the metadata conversion branch
seen in both crashes; .NET 8's usual class 2 enters it. This is a targeted
mitigation hypothesis, SOURCE only, not a verified fix. Native fixture and
parser qualification sources are in tests/DirectoryNames. Static checks/source
repair may proceed; the later authorization above now permits this concrete
bounded qualification. Installation/original-workload scope is separate. No global
settings/driver/AV changes or reproduction of the old workload.

2026-10-29 offline crash comparison: the user explicitly authorized control of
installed Microsoft WinDbg and personally confirmed UAC. Both original dumps,
with matching public symbols, show ProtectionBroker directory enumeration,
Ntfs!FindNextIndexEntry2+0x675 -> null and
AV_Wof!WofPreDirectoryControlCallback (+0x695). This strongly supports the same
failure mechanism, not attribution to Wof/AV/hardware or a safe product retry.
Original dump hashes are unchanged; local logs and exact debugger-stop receipts
are in work/windbg-installed-20261029. Product execution hold below remains.
Do not repeat symbolic analysis without a new question or treat the historical
debugger refusal/manual-analysis plan as a current blanket prohibition.

2026-10-29 historical crash hold (later repair authorization above applies): manual-UAC inactive update reached ecb06a57929a45d1adf9dd1d8415c4a4
(manifest 851701939666F35F4E0C4323C408E00690B4CFB96165C81F5C6092AF5D8238C6),
then the correct process-workspace-data invocation has no terminal receipt.
System1001 confirms 0x1E(C0000005,0,8,0), boot 05:44:54Z. Cause/driver UNKNOWN.
Do not retry product builds, installs, runtime, fault injection or recovery
as a diagnostic. Preserve current/old packages and private state. Continue
bounded read-only incident work; dump/private-state access still needs a
reviewed human-authorized path. No AV/driver/network/UU/FlClash changes.
See docs/INCIDENT-20261029-SYSTEM-CRASH.md and STATUS. This technical hold does
not fabricate a successful cleanup or pause/complete the active user goal.

2026-10-29 installed continuation: 939f059 Broker/Lifecycle + aa864bc embedded
Bootstrap completed human-UAC inactive update to 659d76df00d14dac9c6f46a6dc611157
(manifest CB5515C9CED7D08248EA903F7EA2817B2F47D5EA952D366B31ABB775520C4264).
Daily workspace-pack/review and original SessionResources share bounded data
transfer. Fixed three-file Git processing, independent nested objects, closed
Job result snapshot, 52-entry exact cleanup and installed daily result review
passed. This is not arbitrary-project admission or broad host/network/GPU proof.
The first workspace package's old fixed bootstrap-path refusal is preserved.
Update placement now derives one exact protected root from embedded Release,
never caller paths: ProgramFiles/ClaudeCodeProtection-Update-<release>.
Reuse unchanged ordinary transfer tests; next project work needs trusted data
authorization and persistent results in the same owner, not another executor.

2026-10-28 product continuation: P0 real private data protection and enforced
network isolation are coequal; lower-priority host environment fingerprint
protection is also a formal goal. Preserve normal development and NVIDIA GPU.
Necessary privileged work must be specific Broker-owned resource operations,
never an unrestricted elevated developer shell or blanket UAC delegation.
Workspace data transfer uses ordinary-user explicit selection, not privileged
host-path reads. Keep the original session owner, no parallel executors.
See docs/PRODUCT-DIRECTION-20261028.md and docs/WORKSPACE-TRANSFER.md.
Do not stop UU remote software or alter everyday host/network/AV settings.
User continues to authorize bounded reviewed builds/tests and local commits;
real Claude, automatic UAC and remote pushes remain excluded.

2026-10-27 renewed authorization: the user explicitly permits bounded local
builds and system validation again, accepting the possibility of another crash.
The PR-intake runtime hold is historical, not a continuing blanket veto. Start
from preserved analysis evidence and a concrete hypothesis; review/pin each
artifact and execute only its bounded qualification scope, retaining failures,
exit/drain and recovery. Do not reproduce a crash merely for reproduction.
This does not clear the Kaspersky incident, bypass AV, unlock legacy build
scripts, permit automatic UAC confirmation, reconfigure daily FlClash or authorize
real Claude login/inference/sessions. Source integration is not qualification.
See docs/INTEGRATION-20261027.md and the incident record for current evidence.
The next-stage source chain is now InstalledBroker -> ProtectedSession ->
AtomicChild/SessionProxy/PersistentFence/ProtectionRuntimeLease. Reuse this owner;
see docs/PROTECTED-SESSION-CHAIN.md. Its missing trusted collectors/security grants
remain UNKNOWN and cannot issue a positive permit. This new human authorization
permits qualification, not a fabricated positive permit or blanket artifact safety.

The user's 2026-10-26 autonomous-development instruction supersedes the earlier
ban on local Git initialization/commits. Work in this existing checkout. Local,
scoped commits are authorized; do not publish, configure a remote or push.
Preserve historical evidence, backups, credentials and failure/UNKNOWN records.
The user has published the private repository at
https://github.com/simple-sudo/ClaudeCode-Protection (main). Preserve the existing
origin configuration; remote pushes remain user-managed. Do not describe the
current checkout as having no remote.

Do not make the user a routine stage-approval or message-forwarding dependency.
Choose implementation and reuse approaches autonomously. Prefer a small
production vertical slice over additional dormant classes/protocols. Do not
claim background execution when a session stops. Do not create another chat,
worktree or project copy. Use subagents only if separately authorized.

The Kaspersky incident remains unresolved. Keep all ordinary build/launch hard stops.
The user's explicit 2026-10-26 S1/S2 authorization permits only the frozen daily
CLI one-shot offline build and, after independent qualification, ordinary-user
system-proxy-baseline and offline audit. That S1 grant has now been consumed.
scripts/Invoke-S1DailyBuild.ps1 records the fixed historical attempt; it is not
a general unlock or permission to build newer sources or other projects.
The S2 .NET-host selection failure and reviewed patch-selection correction are
preserved in work/s2-offline and work/s2-offline-recovery. Both read commands
completed; their FAIL/UNKNOWN observations are not protection acceptance.
No later managed-source change inherits those artifacts' BUILD/runtime evidence.
The user subsequently explicitly authorized one offline build of the submitted
ProtectionBroker + ProtectionLifecycle slice at 8a9c4b1 (21 C# source files).
That separate grant is now consumed: restore/build succeeded, no product ran.
scripts/Invoke-BrokerOfflineBuild.ps1 records that fixed attempt, not a reusable
unlock. Its artifacts remain in work/broker-offline-build and are not approved
for execution, installation, escalation, quarantine or network/AV changes.
Subsequent explicit human authorization on 2026-10-26 says the blocked parts
may proceed toward the goal. This supersedes waiting for the same scope again:
review and qualify the concrete build/runtime and trusted-installation path,
then proceed within the tool-owned scope. It does not establish blanket
artifact safety or authorize old selftest, AV changes, global networking
changes, real Claude launch, automatic UAC confirmation or unscoped execution.
Keep ordinary legacy stops; use reviewed bounded entry points and preserve
the earlier grants/failed/UNKNOWN evidence. Read-only runtime/WFP diagnostics
must stay separate from the installed quarantine mutation path.
Do not restore the retired binary, run the old aggregate selftest, add AV
exclusions, rename/repackage to evade detection, or change AV policy. A new
alert stops validation immediately. Compile/execute blocked work must be
reported as BLOCKED, not replaced by indefinite peripheral source expansion.

Allowed static validation: scripts/Check-SourceTypes.ps1 reads existing SDK
reference metadata and performs non-emitting semantic analysis. It does not
run MSBuild/restore/analyzers/generators, emit or load a project assembly, or
invoke product/native code. This is SOURCE evidence, never BUILD/VERIFIED.
The checker deliberately supports the current simple project declarations;
unsupported build constructs must fail rather than silently disappear.

Keep FlClash Global, system proxy, TUN and BFE running without reconfiguration.
Real Claude login/inference/launch is DEFERRED_BY_USER. Prioritize IPv4 forced
proxy, direct-egress prevention, Kill-Switch, Watchdog and safe lifecycle.
IPv6 scope is blocking and necessary negative tests, not forwarding.
The user's full 2026-10-26 product guidance permits carefully controlled
system-wide timezone, IPv6, DNS and related settings as explicit advanced
capabilities when justified, impact-reviewed, authorized and recoverable.
This is not a default blanket-disable or reset policy; prefer protected-process
restrictions and preserve FlClash and ordinary use. This development slice has
not changed those system settings. See docs/PRODUCT-DIRECTION-20261026.md.
UAC remains human-controlled. Daily user maintenance must not run elevated.

Update docs/STATUS.md with SOURCE / BUILD / INTEGRATED / VERIFIED /
DELIVERABLE / DEFERRED / BLOCKED evidence and exact remaining gaps. Keep
docs/PROJECT-ACCEPTANCE.md as the historical acceptance ledger. Run the
non-emitting checker after managed-source changes; perform meaningful runtime
checks only when their safety clearance exists. Preserve original failures.
Before each commit inspect scope and credentials; keep state/logs/backups,
PID files, generated binaries and private data out of Git.

The user's latest 2026-10-27 full guidance expands the unified product goal;
see docs/PRODUCT-DIRECTION-20261027.md. Continue the actual network matrix.
Overall delivery also requires strict fourteen-item environment admission
enforced by the trusted Broker (not GUI-only or reusable old PASS), independent
system-security gates, host-sensitive file/registry/process/management-interface
isolation, usable authorized workspaces/toolchains and inherited child limits,
and representative native NVIDIA GPU computation inside the chosen boundary.
No default full VM, CPU-only substitution or unrestricted sandbox fallback.
The current raw FlClash endpoint is qualification-only; it does not establish
confidentiality against proxy-mediated access to local management resources.
Small owned CUDA/PyTorch compatibility evaluation is now explicitly requested;
review/qualify each concrete artifact and retain the same AV/UAC/Claude limits.
Keep the user's rewritten upstream README and safely merge fetched history;
do not overwrite local changes or push. Synthetic qualification cannot become
an alternate general Claude launch path. Partial network success is not full
product completion.

2026-10-27 product-throughline update: P0-A host-sensitive resource isolation and
P0-B network privacy are equal priorities; P1 device/software identity and
unnecessary telemetry are part of the product. Favor installed vertical slices.
The reviewed 5ea85b5 Broker/Lifecycle + 7fd42ba embedded-package Bootstrap has
completed a human-UAC INACTIVE update to f43484dc7fd6410086d3bc6785126793.
This is installation-only qualification, not session/network/resource clearance.
Bootstrap UpdatePinnedInactive now uses its existing fixed protected host,
embedded manifest, pinned prior packages and closed-admission lifecycle checks;
fresh install and all unqualified system/session entry holds remain. See STATUS.

2026-10-28 current installed continuation: 7fb4570 Broker/Lifecycle + d8ae593
embedded Bootstrap completed inactive update to 7532048921364d978518e2e6993a9b9e.
The fixed offline resource session, closed-Job checkpoint, separate installed
Broker profile cleanup and no-pending readback completed. This is post-closed-Job
storage recovery only, not controller-crash/reboot or formal-session clearance.
Profile v2 journals pin fresh storage identity, current human owner and durable
Job closure. Never adopt legacy/uncertain creations or delete a replaced tree.
The original r1/r2 failures and ordinary ACL-diagnostic refusal remain preserved.
User-supplied valid OpenAI signature and OpenTIP Clean are accepted as manual
investigation results for the exact Codex digest. They do not authorize AV UI,
broader exclusions, automatic UAC or unqualified product/Claude launch.

2026-10-28 Git throughline: a97a967 + 13eafd8 completed inactive update to
fc2d7c8b668c47dea505fc2f19f923a3. Fixed offline Git hash/init/add/commit/show,
same-Job/AppContainer identity, non-secret private-fixture denial, independent
Git object verification and 43-entry exact task cleanup completed. Task data
uses a fresh ProgramFiles/ClaudeCodeProtection-Task-<nonce> with a package-specific
low-integrity DACL, avoiding grants to private profile ancestors for getcwd.
Task intents/NTFS identity bind to the existing profile and closed-Job proof;
never adopt or recursively erase unknown/replaced/reparse/hardlinked trees.
Git's fixed read-only executable/DLL aliases have reviewed 4/2 hardlinks with
pinned bytes/trusted ACLs; all payload/state/deletion single-link rules remain.
The original Git r1/r2/r3 failures remain. This is offline fixed-tool scope,
not arbitrary projects, online Git, full host/network/14-item, GPU or real Claude
clearance. See STATUS for exact current evidence and remaining delivery gaps.
