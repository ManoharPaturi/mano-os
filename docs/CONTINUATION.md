# Continuation after compaction

Goal: complete mano-OS v2.1 without fabricated phase/security claims.
User authorization: build repo, use PRs and mostly carry them through to merge,
only when all CIs pass. Monitor disk and notify the user. No agents delegated.

Repo: https://github.com/ManoharPaturi/mano-os (private).
Local checkout: work/mano-os under this chat workspace.
Specification: docs/spec-v2.1.md preserved verbatim from supplied Downloads README.

PR #1 merged after all three CI checks passed. CI run 38289411969 produced
13 passing probes, zero failures and nine pending checks. PR #2 merged after all CI checks passed, run 38289976575: 16 passing probes,
zero failures, nine pending checks. Current follow-up: test/phase0-stop-proof,
actual mock-core process freeze and task descendant termination.
Next substantive Phase 0 work: btrfs-root boot/restore and GUI/security contracts. Read CI and phase status before
changing anything. Core/delegates are not wired to host execution. Preserve NO-GO
until mandatory proof exists. Root is ext4, btrfs data only; physical gates pending. User explicitly chose CI VM development for now.

Commands from checkout:

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
.venv/bin/ruff check .
gh pr checks --repo ManoharPaturi/mano-os
python3 scripts/merge_checked.py PR_URL
PYTHONPATH=src python3 -m mano_lab.cli disk .
```

Mac initial free space: about 16 GiB, 92% used. Avoid local VM/model downloads.
Latest result is live disk output; initial measurements may drift.
Use automatic context compaction/concise notes; /compact is a user command, no
assistant tool is exposed to directly invoke it. Goal remains active until actual
requested completion, or a repeatedly observed external blocker meets tool rules.
