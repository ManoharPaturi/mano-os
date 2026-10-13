# Continuation after compaction

Goal remains the complete original mano-OS v2.1 specification in docs/spec-v2.1.md.
Repo: https://github.com/ManoharPaturi/mano-os (private). Local checkout: work/mano-os.
User authorized implementation, PRs and mostly carrying them through to merge.
Merge only after every current-head CI passes; main protection is enforced for admins.
User explicitly chose CI VM development for now. No agents have been delegated.

Verified merged work PRs #1-15. Main 9523f9430f6aacce604fc7ed5cb86d93781dad47.
PR15 accepted CI 38322815062, post-merge main 38323225953 all passed.
Recovered report 33 pass, 0 fail, 1 pending P0-10; architecture NO-GO.
Original full spec/goal remains active; no model execution or arbitrary root API.

Current branch feat/phase0-independent-stop. Native C stopd with systemd watchdog,
human-only kernel-credential socket, fixed cgroup.kill path, durable latch/epoch,
root-lock of raw agent input runtime. Root C restart fails closed after watchdog hang.
Real bounded fork storms in two task units plus live Wayland pointer-pulse service.
Core and approval authority frozen throughout each stop. First force native stopd
hang -> systemd watchdog restart -> auto stop. Resume authority; old grant denied.
Fresh request-bound PAM rearm restores input and new scoped grant. Then real ttyS0
STOP trigger independently kills/revokes again; grant denied and TTY still usable.
Live grants are real checks/counter effects bound to approved fixture-session scope,
not production general execution. Root cgroup/epoch/input and actor denial evidence
must pass both boots. Full Phase0 audit is explicitly pending before any promotion.
Candidate unverified until final-head CI; merge only all-success current head.

Physical performance remains a Phase 6 gate. Installer/firmware boot remains Phase 7.
No production broker, core/model execution, coding delegate, .deb or ISO exists yet.

Continue with remaining Phase 0 GUI and authority experiments, then audit every
Phase 0 requirement before enabling runtime execution. Do not narrow the full goal.
Mutation guest scripts are disposable-VM-only and refuse already formatted targets.
Never rerun setup on a prepared/recovered guest. Every boot grants scoped runner KVM
access; kernel/initramfs are matching files under /boot (cloud root links are absent).

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
.venv/bin/ruff check .
bash -n scripts/*.sh
gh pr checks PR_NUMBER --repo ManoharPaturi/mano-os
python3 scripts/merge_checked.py PR_URL
PYTHONPATH=src python3 -m mano_lab.cli disk .
```

Disk: ~15.7 GiB free on Mac, above 90% used. Warn below 20 GiB; stop new large
local downloads below 10 GiB. Avoid local VM/model images and never delete user data.
No direct agent /compact tool is exposed; preserve concise notes across automatic
compaction. Goal remains active until the full specification is actually verified.

PR16 run 38326217996 failed before stop trigger. Guest kernel 6.12.111 logged
RCU starvation and two CPUs waiting in smp_call_function_many_cond after pids
limit rejection; setup stalled launching pointer service. No merge/evidence promotion.
Next candidate paces successful forks at 10ms, retains sustained rejected attempts,
and requires nonzero pids.events max counters in both worker units before stop.
This is a diagnostic change, not proof the underlying guest stall is resolved.
