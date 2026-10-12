# mano-OS

AI-native, prompt-first Linux with a trusted broker and isolated agent desktop.

**Status: Phase 0 lab in development. No production runtime, native prompt,
coding-agent integration, .deb or ISO yet.**

The complete original [v2.1 specification](docs/spec-v2.1.md) is preserved verbatim.
Its architecture and acceptance gates remain the product contract.

## Implemented in the first PR

- Dependency-free Python evidence and disk tools, with explicit incomplete gates.
- Patched bubblewrap lab profile: synthetic home, no host IPC or network.
- Disposable Debian 13 QEMU CI guest with 4 GiB RAM, separate identities,
  headless Sway output/capture and filesystem/IPC/device/network denial probes.
- btrfs data-volume/Snapper restore and independent systemd cgroup-stop probes.
- Hashed evidence artifacts, protected main and an all-success merge helper.

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install ruff==0.14.0
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
.venv/bin/ruff check .
PYTHONPATH=src .venv/bin/python -m mano_lab.cli disk .
```

Local tests validate the tooling. Real namespace, Sway, cgroup and btrfs probes
run in the Debian CI VM. The guest script installs packages and formats its second
disk; run it only through the disposable VM lab.

See [phase status](docs/phase-0-report.md), [operations](docs/operations.md),
[architecture ADR](docs/architecture/0001-phase0-gate.md) and
[continuation](docs/CONTINUATION.md).

## CI and merge rule

All implementation uses PRs. Required checks: `quality`, `security-lab`,
`merge-gate`. Every other reported check must also succeed. Run
`python3 scripts/merge_checked.py PR_URL` to validate checks and merge against the
current PR head. Branch protection is the final server authority.

Passing lab CI means the implemented probes passed; the architecture stays NO-GO
while physical-input, GUI security or other mandatory proof is pending. A model is
never connected to host execution before the Phase 0 gate.
