# Continuation after compaction

Goal remains the complete original mano-OS v2.1 specification in docs/spec-v2.1.md.
Repo: https://github.com/ManoharPaturi/mano-os (private). Local checkout: work/mano-os.
User authorized implementation, PRs and mostly carrying them through to merge.
Merge only after every current-head CI passes; main protection is enforced for admins.
User explicitly chose CI VM development for now. No agents have been delegated.

Verified merged work: PRs #1-11. Latest main 63b4ea0cfac3edf80c2668c7681572ae7b832071.
PR #11 accepted CI 38311211301; post-merge main 38311680967 passed all checks.
Recovered report: 30 pass, 0 fail, 4 pending; architecture remains NO-GO.
Includes actual root/recovery boots, original disk preservation, privileged Wayland
bind denials, private XWayland, Chromium, Writer semantic and coordinate saves at
scales 1 and 2. Worker virtual-pointer creation denied. Full goal remains active.

Current branch: feat/phase0-native-prompt-rescue. Adds minimal native GTK4 prompt
under the separate human principal, actual accessible editable/Send contract and
request-data receipt. No execution or approval authority is wired to this UI.
Human Sway starts only the native prompt by default; recovery foot is explicit.
CI console changes from write-only logfile to logged Unix socket-backed serial.
Trusted runner authenticates the temporary human fixture via agetty/login/PAM on
real ttyS0, checks a secret challenge response/actual UID/TTY while mock core remains
SIGSTOP'ed. No PTY substitute, physical-input or full approval-service claim.
Fixture credentials are captured privately, never passed on argv/env or retained in
artifacts; serial output is redacted, fixture is cleaned and human password locked.
Runner combines the serial/native evidence into the report after guest export.
Both normal and recovered roots must run this flow. Candidate remains unverified
until final-head CI succeeds; merge only via merge_checked.py.

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
