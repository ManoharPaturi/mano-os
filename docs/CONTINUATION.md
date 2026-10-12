# Continuation after compaction

Goal remains the complete original mano-OS v2.1 specification in docs/spec-v2.1.md.
Repo: https://github.com/ManoharPaturi/mano-os (private). Local checkout: work/mano-os.
User authorized implementation, PRs and mostly carrying them through to merge.
Merge only after every current-head CI passes; main protection is enforced for admins.
User explicitly chose CI VM development for now. No agents have been delegated.

Verified merged work: PRs #1-10, latest main cf5b1dedc47aab42aba50d398d1683b59eb4a959.
PR #10 accepted CI 38308966866; post-merge main CI 38309367729 passed all checks.
Recovered report: 29 pass, 0 fail, 5 pending. Architecture remains NO-GO.
Includes real root/recovery boots, preserved original disk, cgroup OOM/stop,
restricted Wayland forged-bind denials, private authenticated XWayland namespace,
headed Chromium and Writer named accessible Save with verified ODT/PDF text.

Current branch: feat/phase0-accessibility-scale. Test visible Writer toolbar Save
using WINDOW_COORDS (visible/showing/enabled), controller-observed xdg-shell client
origin, logical-to-pixel transform, and actual pointer Save at scales 1 and 2.
The original hidden menu's desktop sentinel -2147483648 remains unusable.
Task worker never receives Sway command IPC or virtual-pointer authority. Initial
Sway seat cursor fixture did not save (headless seat had no real pointer capability).
The trusted controller now creates a virtual pointer via pinned protocol XML; a
restricted worker invoking that pointer fixture must be denied. Actual ODT changes must
prove both clicks; no semantic Save fallback is allowed for the geometry test.
Candidate is unverified until the final PR head passes the complete CI VM suite.

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
