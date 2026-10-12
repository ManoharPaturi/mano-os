# Continuation after compaction

Goal remains the complete original mano-OS v2.1 specification in docs/spec-v2.1.md.
Repo: https://github.com/ManoharPaturi/mano-os (private). Local checkout: work/mano-os.
User authorized implementation, PRs and mostly carrying them through to merge.
Merge only after every current-head CI passes; main protection is enforced for admins.
User explicitly chose CI VM development for now. No agents have been delegated.

Verified merged work:
- PRs #1-3: 19 passing primitive probes, no failures, 9 pending.
- PR #4, run 38293373666: real btrfs-root boot, read-only/hash-preserved original disk.
- PR #5, run 38294272602: third boot from Snapper recovery clone, exact restored sentinel,
  retained changed @ root, separate snapshot store and complete security rerun.
  21 passing probes, no failures, 7 pending. Both artifact sets independently hash-checked.

Current branch: feat/phase0-resource-evidence. Collect actual VM memory/Sway/cgroup
metrics and correct Phase 6 physical performance being incorrectly tracked as P0-12.
Physical performance remains required for project completion; no VM claim substitutes it.
Architecture stays NO-GO while native prompt/recovery, GUI/browser/accessibility,
privileged Wayland protocols, authentic approval and trusted stop proofs remain pending.
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
