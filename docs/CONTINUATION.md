# Continuation after compaction

Goal: complete original mano-OS v2.1 in docs/spec-v2.1.md, not just the lab.
Private repo: https://github.com/ManoharPaturi/mano-os. Checkout: work/mano-os.
User authorized implementation and mostly merges, only after ALL final-head CI
passes. Strict main protection includes admins. User chose CI VMs for now.
No agents delegated. No direct agent /compact tool; automatic compaction uses notes.

Accepted merged baseline PRs #1-15: main 9523f9430f6aacce604fc7ed5cb86d93781dad47.
Current PR16 https://github.com/ManoharPaturi/mano-os/pull/16, branch
feat/phase0-independent-stop. Implementation head 45d2070997c76451c42404fc0101d1dd9d684815
passed all three jobs in CI38328405772. Documentation update still needs final-head
CI before merge. Do not confuse that implementation run with approval to merge a
new head. Use scripts/merge_checked.py, then verify post-merge main CI.

P0-10 evidence: both normal and recovered btrfs boots independently run native C
stopd, systemd watchdog, human-only kernel-peer socket, durable latch/grant epoch,
fixed cgroup.kill and input-runtime root lock. Core and approval authority remain
actually SIGSTOP-frozen while watchdog and human ttyS0 stop execute. Two worker
units reach real TasksMax (nonzero pids.events max each), plus pointer input.
Watchdog kills 50 PIDs, manual kills 49. Epochs increase 0->1->2, grants change
valid->revoked->fresh PAM rearm valid->revoked, use counter stays unchanged on
denials. Pointer capability and pulses stop. Six actor socket/signal denials per
phase. Authenticated TTY remains usable; fixture account locked and core removed.
Hashes checked for all referenced artifacts in both reports. Recovered suite:
34 pass, 0 fail, 1 pending P0-12 original-spec architecture audit; still NO-GO.
Physical input provenance is null. This is a fixed CI spike, not production broker.

Earlier pressure runs stalled around serial kernel info messages (RCU warnings).
Pacing forks and explicit KVM host CPU alone did not resolve readiness. Current
fixture saves/restores console printk, retains warnings/errors on UART, sends info
to kernel journal. Accepted kernel journal has four actual fork rejections and no
RCU stall/BUG/soft-lockup messages. Linux RCU documentation identifies slow serial
console as possible stall cause; evidence supports that diagnosis, not a universal
kernel fix. Full guest diagnostics retained after serial tests, preserving newer
runner report; pulse logs cleared between boots. VM still 4 GiB, two vCPUs.

Next: merge PR16 only after final-head CI; audit every original Phase0 requirement
and stale ADR before any model-facing executor. Full later phases remain broker,
core/model runtime, coding delegates, durable workflows, devices, physical 8 GB
Phase6, .deb/ISO and firmware/installer Phase7. Never shrink the goal or invent
physical results. Do not rerun fresh-disk setup on a prepared/recovered guest.

Disk last ~17 GiB free, 92% used; warn below20GiB/above90%, stop large downloads
below10GiB. Repo+diagnostics ~100MiB. No local VM/model images, no user-data deletion.

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -q
.venv/bin/ruff check .
bash -n scripts/*.sh
gh pr checks 16 --repo ManoharPaturi/mano-os
python3 scripts/merge_checked.py https://github.com/ManoharPaturi/mano-os/pull/16
PYTHONPATH=src python3 -m mano_lab.cli disk .
```
