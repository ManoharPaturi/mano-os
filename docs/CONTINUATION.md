# Continuation after compaction

Full original mano-OS v2.1 goal remains active; docs/spec-v2.1.md matches supplied
README byte-for-byte SHA256 6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace.
Private repo https://github.com/ManoharPaturi/mano-os; checkout work/mano-os.
User authorized implementation and mostly merges, all final-head CI must succeed.
Strict main protection includes admins. CI VM development for now, no local images.
No delegated agents. No direct agent /compact; preserve notes for automatic compaction.

Previous turn made progress: PR16 merged at 91597e0c477eb2a652f513d8599ca600feefca7a.
Accepted final-head CI 38329062530 and post-merge main CI 38329419405 all three success.
Both real boot stages passed independent native stop/grant/input/TTY under process
pressure and frozen core/approval. Recovered suite: 34 pass, 0 fail, 1 pending P0-12 audit.
Verified artifact hashes; outputs contain accepted PR16 evidence. Physical provenance
null, root fixtures are not production executors. Local disk ~16 GiB free/92% used.

Current branch feat/phase0-architecture-audit. P0-12 original-spec review in
ADR0008 maps all ten Phase0 tests and P0-01..12. OS-authenticated ttyS0 fallback is
explicitly permitted by spec 3.8 where physical input cannot be validated. GUI
restricted protocols/private X11, actual app/focus, native prompt, FD/env/mount/IPC
negative probes, root restore and measurements reviewed against source/artifacts.
Stale ADR0001 and threat-model corrected. Runtime execution remains unauthorized.

New architecture audit verifies original spec hash, every required positive/negative
probe, artifact hashes/path confinement, critical GUI/PAM/stop/recovery/measurement
outcomes, first-root evidence, unchanged original disk and pressure kernel journal.
Generated architecture-audit.json records GO-for-Phase1-development only, no production
authorization, physical provenance null and later physical/installer gates retained.
Runner invokes only after recovered suite and disk-preservation comparison pass.
Local 29 tests pass incl tampered/unhashed/escaped artifacts, absent coverage and spec drift.
Need final local audit smoke, create PR, attach it, all final-head CI, merge via
scripts/merge_checked.py and post-merge main CI. Do not promote outputs before acceptance.

Next Phase1: typed broker IPC/grants/journal and operation-authorized runner before
any model-facing tools. Existing lab path resolution is race-prone and must not be
reused as production authority. Production cgroups, seccomp/Landlock, network/credential
mediation and all original later-phase tasks remain. Physical 8 GB Phase6, runtime.deb,
firmware/installer/signedISO Phase7 still required; do not shrink full goal.

Stop compatibility finding: early guest progress stalled in emulated UART kernel
info. Pacing forks and host CPU alone insufficient. Fixture now saves/restores printk,
keeps warnings/errors on UART and info in kernel journal. Real pids limits still
reached; accepted journal has fork denials but no RCU/BUG/soft-lockup. Guest: 4 GiB/two CPUs.
Both task groups, watchdog kill 50 PIDs/manual 49, epochs 0->1->2, stale grant effect-denied,
fresh PAM rearm, six actor signal/socket denials per stop and recovery TTY all verified.

Warn disk below 20 GiB/above 90%; stop new large downloads below 10 GiB. No user-data deletion.
Never rerun fresh-disk formatting scripts on prepared or recovered guests.

PR17 merged at02ec98d5b01fc4fb425256de85487162d6ed6b75 after accepted
CI38330472820 (35pass/0fail/0pending). Post-main CI38330847410 was watched.
Final review found missing separate app startup metrics; do not begin Phase1 until
this measurement gap is resolved. Current branch feat/phase0-app-startup-metrics:
real monotonic Chromium launch->control/page readiness and Writer launch->UNO
document readiness. Fresh process, not cold-cache/physical performance. Resources
include both, audit requires finite positive values and matching summary on both
boot stages; old PR17 artifacts now fail this stronger audit. Local30tests pass.
Need fresh CI, PR merge only all-success final head, then post-main verification.

PR18 merged b22ec91631f817abda548c4a82a25ce238af54a3. Accepted CI38331286546,
post-main CI38331698197 allsuccess. Startup gap closed with real both-boot metrics;
recovered Chromium control/page0.629/0.966s, Writer UNOdocument1.436s. Phase0 audit
35pass/0fail/0pending, GO-for-Phase1-development only. Outputs updated/hashed.
Current Phase1 branch feat/phase1-broker-state: strict typed action proposal parser,
private SQLite task/grant/action/event store, atomic count/intent, dispatch recheck,
replay binding, unknown after recovery, explicit verification metadata and durable
stop epoch/latch. No executor/socket/PAM integration or model route yet. Local39tests
pass incl two-connection single-use race. New recovered-guest probe forks an abrupt
writer, recovers unknown and tests six actual journal EACCES denials + unchangedhash.
Need fresh CI, create/attach PR, all-final-head checks, merge and post-main CI.
ADR0009 documents gaps and exact next work; do not claim Phase1 complete.
