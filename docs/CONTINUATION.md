# Continuation after compaction

Full original mano-OS v2.1 goal remains active. Original spec hash
6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace matches supplied README.
Private repo https://github.com/ManoharPaturi/mano-os; checkout work/mano-os.
User authorized mostly merges, only after all final-head checks pass. Strict main
protection includes admins. CI VMs for now, no local VM/model images. No subagents.
Direct agent /compact unavailable; keep this note for automatic compaction.

PRs1-19 merged. Main77e29d3af4322b433e71184a5bcc3bf4514b3fe4. PR19 accepted
CI38333478816 all3success, actual broker journal permissions/restart/latch passed.
Post-main38333924532 still running when this note was written; check authoritative
status, not intent. Watch log work/broker-state-main-watch.log and session57664.
Phase0 35pass/0fail/0pending GO-for-Phase1-development only; production_execution
unauthorized. PR18 closed missing app startup observations, no cold-cache/physical claim.

Current branch feat/phase1-authenticated-ipc: request-only SOCK_SEQPACKET handler,
connection plus per-message Linux credentials, propose/status only. Close/deny
passed FDs, inherited connection and truncated packets. CI fixture deliberately
reachable by all actors to prove caller auth, one reservation, no FD leak. ADR0010.
42 local tests pass with1 Linux-only skip; Ubuntu CI must actually run that test.
Need commit/PR attach, real Debian probe, all-current-head checks before merge.

Next: protected non-root broker systemd socket/service and lifecycle bounds,
separate request-bound PAM approval channel, FD-pinned resources, real cgroup/
bwrap/seccomp/Landlock executor, native stop integration, independent verifier,
terminal/model/LangGraph minimal agent and Phase1 golden project/policy attacks.
Existing State is trusted library; no approval/execution/verification wire bypass.
Native Phase0 stop/PAM probes are fixed disposable fixtures, not production helpers.

All later original phases remain: coding delegates, durable workflows, GUI/browser/
office integration, credentials/network/device mediation, runtime.deb, physical8GB
Phase6, signed firmware/installer/ISO Phase7. Never narrow full goal to lab subset.
Disk last13GiB free94% used: warn below20GiB or>=90%; stop new large downloads
below10GiB. Never delete user data or reformat prepared/recovered guest disks.
Outputs contain accepted PR19 broker-state evidence; no unverified IPC proof.
