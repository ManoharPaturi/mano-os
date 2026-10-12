# Continuation after compaction

Goal remains the complete original mano-OS v2.1 specification in docs/spec-v2.1.md.
Repo: https://github.com/ManoharPaturi/mano-os (private). Local checkout: work/mano-os.
User authorized implementation, PRs and mostly carrying them through to merge.
Merge only after every current-head CI passes; main protection is enforced for admins.
User explicitly chose CI VM development for now. No agents have been delegated.

Verified merged work: PRs #1-12. Main 47947b1898990b214ec14c37525ef10018df65d0.
PR #12 accepted CI 38314745160; post-merge main 38315316185 passed all checks.
Recovered report: 31 pass, 0 fail, 3 pending (P0-05/09/10); architecture NO-GO.
Native GTK4 prompt and real authenticated ttyS0 recovery with frozen core verified.
Prior geometry/Wayland/XWayland/browser/root recovery contracts remain passing.

Current branch: feat/phase0-cross-session-focus. Keep the real human prompt alive
while the separate agent compositor runs its actual browser, Writer pointer saves,
and XWayland app contracts. GTK4 AT-SPI text/focus getters returned empty/unfocused despite functional editable
input. Observe the actual native GTK widgets/signals in a CI wrapper of the same
Prompt class instead. A trusted virtual keyboard gives the headless human seat an
actual keyboard-focus path. Monitor an unsent canary and 50 ms snapshots, unchanged receipt count, and protected compositor focus
checkpoints. Verify distinct net namespaces and actual human Wayland/command IPC
connection denial for agent, core and worker principals. No physical-input claim.
This is one P0-05 issue; no approval/runtime/model/stop authority is enabled.
Candidate remains unverified until final-head CI passes normal/recovered roots.

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
