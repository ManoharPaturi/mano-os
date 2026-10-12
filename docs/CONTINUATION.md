# Continuation after compaction

Goal remains the complete original mano-OS v2.1 specification in docs/spec-v2.1.md.
Repo: https://github.com/ManoharPaturi/mano-os (private). Local checkout: work/mano-os.
User authorized implementation, PRs and mostly carrying them through to merge.
Merge only after every current-head CI passes; main protection is enforced for admins.
User explicitly chose CI VM development for now. No agents have been delegated.

Verified merged work: PRs #1-14. Main e2f64e0fe0f1fe23a6af88567ac64f79e18fec62.
PR14 accepted CI 38319743416; post-merge main 38320287725 passed all jobs.
Recovered report 32 pass, 0 fail, 2 pending (P0-09/10), architecture NO-GO.
All real root/recovery, sandbox, GUI/scale, concurrent focus, native prompt and
PAM-authenticated real ttyS0 rescue contracts remain passing. Full goal is active.

Current branch feat/phase0-authenticated-approval. Fixed CI root authority spike:
human-only SOCK_SEQPACKET endpoint with kernel SO_PEERCRED, immutable task/op/target/
risk/expiry/nonce digest, per-request Linux PAM through fixed C helper, single-use
approval, root-only marker and journal. No arbitrary root executor or model API.
Trusted ttyS0 client displays only broker operation and tests modified digest,
wrong nonce, extra target, expiry, wrong password, valid approval and replay.
Three actor principals must hit EACCES on approval IPC, journal write and uinput.
If cloud kernel lacks uinput driver, a character-node permission test explicitly
records driver_available=false; no physical/device-behavior claim is made. Strong
OS-auth fallback follows original spec; authentication is still unverified until CI.
Temporary credentials remain off argv/env/logs/artifacts, each flow fails closed,
cleanup stops authority and locks account. Both normal/recovered roots required.

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
