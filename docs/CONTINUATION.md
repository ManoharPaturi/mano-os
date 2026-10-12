# Continuation after compaction

Goal remains the complete original mano-OS v2.1 specification in docs/spec-v2.1.md.
Repo: https://github.com/ManoharPaturi/mano-os (private). Local checkout: work/mano-os.
User authorized implementation, PRs and mostly carrying them through to merge.
Merge only after every current-head CI passes; main protection is enforced for admins.
User explicitly chose CI VM development for now. No agents have been delegated.

Verified merged work: PRs #1-9, latest main 85eb00c. Last accepted run 38306024397;
post-merge main run 38306499487 passed all three checks. 27 passing primitives,
zero failures, five pending requirements; architecture remains NO-GO.
Includes real btrfs root/recovery boots, original disk preserved, cgroup OOM/stop,
restricted Wayland forged-bind denials, private authenticated XWayland namespace,
and headed Chromium locator contract with actual kernel renderer seccomp proof.

Current branch: feat/phase0-libreoffice-contract. Add Writer on restricted Wayland
with a private task D-Bus/accessibility bus, real named Save action and independently
observed mapped window plus exact ODT/PDF content. Acceptance candidate run
38308357005 passed (29 pass, 0 fail, 5 pending on recovered root). Final head must
pass again before merging PR #10. Known geometry sentinel -2147483648 is recorded
as unusable; semantic Save works, coordinate/scale mapping remains pending.
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
