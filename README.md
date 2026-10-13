# mano-OS

AI-native, prompt-first Linux with a trusted broker and isolated agent desktop.

**Status: Phase 0 lab in development. A native prompt prototype is implemented.
Production runtime, coding-agent integration, .deb and ISO remain pending.**

The complete original [v2.1 specification](docs/spec-v2.1.md) is preserved verbatim.
Its architecture and acceptance gates remain the product contract.

## Implemented and verified in CI

- Dependency-free Python evidence and disk tools, with explicit incomplete gates.
- Patched bubblewrap lab profile: synthetic home, no host IPC or network.
- Disposable Debian 13 QEMU CI guest with 4 GiB RAM, separate identities,
  headless Sway output/capture and filesystem/IPC/device/network denial probes.
- btrfs data-volume/Snapper restore and independent systemd cgroup-stop probes.
- Hashed evidence artifacts, protected main and an all-success merge helper.
- Real btrfs-root and Snapper recovery boots with original disk hash preserved.
- Restricted Wayland globals and authenticated private XWayland namespace.
- Headed system Chromium locator and real Writer accessible Save/ODT/PDF contracts.

Writer hidden-menu coordinates remain unavailable. A visible-control scale probe
checks actual coordinate saves at scales 1 and 2; CI artifacts determine acceptance.
Native GTK4 prompt input is tested in the separate CI human session. Real serial
rescue authentication is verified on the VM serial console with a stopped mock core.
Concurrent human/agent focus and input isolation is verified in the CI VM. A fixed
request-bound OS-auth/PAM approval spike is verified in both CI boot stages. The trusted
stop/grant-revocation route passed the CI fixture on normal and recovered roots:
native watchdog and human TTY stop kill all fixture tasks, invalidate live grants,
disable input and preserve recovery while core and approval authority are frozen.
The original-spec audit maps every Phase 0 requirement to real evidence and runs
after recovered-root tests. Its passing report means GO for Phase 1 development
only; final-head CI determines acceptance. Production execution is not authorized.
See docs/architecture/0008-phase0-original-spec-audit.md for the complete decision.

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

Passing Phase 0 audit means the feasibility boundaries passed, using the specified
OS-authenticated fallback. Model-facing execution still requires Phase 1 broker
and runtime gates; physical 8 GB and installer/firmware requirements remain later.

## Phase 1 work in progress

`mano_broker` provides typed proposals, exact grants, durable action state and a
kernel-authenticated request channel under a hardened non-root service. A pending
approval queue supports public request/status without exposing nonce or confirmation.
Trusted confirmation consumes one challenge and issues one exact grant atomically.
Protected root control and native PAM authentication are verified in synthetic CI;
manual TTY/GUI and physical-input verification remain pending. Descriptor custody
and task-bound registry are verified. Live daemon provisioning/preparation is being
integrated; sandbox execution, native stop/verifier and model routing remain required.
No model command is executed. See ADR0009–0019 and accepted CI evidence for scope.
