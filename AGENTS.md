# ClaudeCode-Protection working rules

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
