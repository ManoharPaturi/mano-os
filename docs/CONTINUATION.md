# Continuation after compaction

Goal remains the complete original mano-OS v2.1 specification in docs/spec-v2.1.md.
Repo: https://github.com/ManoharPaturi/mano-os (private). Local checkout: work/mano-os.
User authorized implementation, PRs and mostly carrying them through to merge.
Merge only after every current-head CI passes; main protection is enforced for admins.
User explicitly chose CI VM development for now. No agents have been delegated.

Verified merged work: PRs #1-13. Main c4ce63ab216d3ffdd659a886bb01489bcba2c5b9.
PR #13 accepted CI 38318953207. Recovered report: 32 pass, 0 fail, 2 pending
(P0-09/10); architecture remains NO-GO. Human/agent sessions simultaneously run
real Chromium/Writer/XWayland tasks. Human native widget canary/focus/active state
and request count unchanged across 335/362 snapshots, setup native signals verified,
five compositor checkpoints, and six cross-socket denials per boot (IPC EACCES).
GTK4 AT-SPI text/focus getters incomplete; native GTK observer uses the same actual
Prompt class, direct getters/signals, and trusted virtual keyboard in human CI seat.
No physical provenance, production model/broker/approval/stop authority is claimed.

Current follow-up: fix/phase0-focus-capture-timing. Before screenshot captured inside
GTK callback showed the prior frame although direct widget state was correct.
Move both captures to trusted supervisor outside GTK event loop after paint settles.
Keep all real isolation assertions; verify final screenshots and all final-head CI
before merging. Finish this evidence repair before P0-09 auth/approval work.

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
