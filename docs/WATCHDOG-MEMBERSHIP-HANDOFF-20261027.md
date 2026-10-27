# Work handoff: bounded Watchdog Job membership (2026-10-27)

## Scope and base

This change starts from GitHub `main` at `8e5b4ee15d9ff250e2858dbea3d3cee8e00bbe32`.
The private development branch is `dev/chatgpt-watchdog-membership-20261027`.
It changes only the finite installed Watchdog qualification's **post-resume**
Job membership check, not general Claude launch admission, WFP filter ownership,
FlClash settings, GPU policy, AppContainer creation, or Job termination.

Evidence status: **SOURCE ONLY**. The ChatGPT GitHub editor did not compile,
install, execute, reproduce the bugcheck, or validate the new check on Windows.
Do not assign this patch BUILD / INTEGRATED / VERIFIED merely because it is
present in a PR.

## Motivation

The installed Watchdog previously rejected a ready canary because its Job
contained the admitted Broker and an extra `System32/conhost.exe`.
The existing post-resume assertion demanded precisely one member even though
the additional observed member had the same Job and AppContainer identity.
The Windows bugcheck 0x1E during the subsequent investigation remains
**causally UNKNOWN**; this patch is not a crash fix and does not authorize
resuming dangerous runtime tests.

## New bounded contract

- **Before first resume:** `AtomicChild.ResumeQuarantined` still requires
  precisely the one suspended expected Broker PID, verified image, restricted
  token, bound Job, and committed network barrier.
- **After resume:** `WatchdogMemberPolicy.Verify` accepts either the primary
  Broker alone or Broker plus **one** extra system `conhost.exe`, only while
  the Job inventory is stable before/after handle-based inspection.
- Every member must be confirmed in the exact owned Job, carry the exact
  expected AppContainer SID, Low4096 integrity, zero capabilities, a valid
  creation timestamp, an independently queried image path, and no inspection
  failures. The primary image must match the installed Broker's pinned path;
  the only allowed auxiliary image is the Windows System32 conhost path.
- Missing primary, an extra third process, unexpected executable, foreign
  SID, token drift, disappearing member, or observation failure remains
  **REFUSED**. No process is killed by PID or executable name and no access
  is granted based on a filename alone.
- This is a narrow qualification snapshot. It is **not** continuous
  authenticated monitoring of all descendants or production authorization
  for arbitrary Claude/PowerShell/Python/Git child processes. A full
  production child-process ownership policy is still required.

## Deferred Work verification

1. Read and diff this branch against the recorded base; ensure that it does
   not overlap uncommitted local Work changes. Merge/rebase explicitly rather
   than overwriting the local checkout.
2. After crash attribution and appropriate clearance, run the project's
   bounded source semantic checker and offline build with the approved
   fixed inputs. Before clearance, use only permitted nonexecuting review.
3. Add controlled negative tests to the membership policy: primary-only,
   primary + one legitimate conhost, missing primary, duplicated/third PID,
   changed Job PID set, child no longer in Job, a foreign SID, wrong integrity,
   extra capability, wrong image, missing creation time, and an inspection
   error. All negative cases must fail closed.
4. Confirm the fixed pre-resume singleton check is unchanged, including
   refusal on unexpectedly preexisting console hosts.
5. Only after independently clearing the 0x1E investigation and system-level
   test restrictions, determine whether a *new* bounded Watchdog runtime
   qualification is warranted. Do not use this PR as implicit permission.
6. Reassess whether OS console-host identity needs a stronger executable
   provenance check on the actual Windows deployment. Exact path, token and
   Job membership are conservative checks, not code-signing proof.

## Do not infer

- No completion of the 14 environment admission gates.
- No approval for real Claude login or launch.
- No demonstrated FlClash crash recovery, physical network nonleakage,
  full proxy credential isolation, or general descendant confinement.
- No proven causal relationship between conhost and the prior BSOD.
