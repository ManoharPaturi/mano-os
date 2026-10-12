# Phase 0 evidence index

Verified first lab run: [CI 38289411969](https://github.com/ManoharPaturi/mano-os/actions/runs/38289411969),
PR #1 merged, 13 passing probes, zero failures, nine pending checks.
The run used KVM and Debian 13 with a 4 GiB RAM ceiling.

OOM and GUI follow-up: [CI 38289976575](https://github.com/ManoharPaturi/mano-os/actions/runs/38289976575),
PR #2 merged, 16 passing probes, zero failures, nine pending checks.
Kernel reports `oom-kill`; the human-observer service remains active.

Current architecture decision: **NO-GO for production execution**.
CI emits `report.json`, hashed logs, a package manifest, memory observations,
mount inventory, Sway screenshot and independent-stop outputs.

| Issue | Current implementation and evidence boundary |
|---|---|
| P0-01 | Debian 13 QEMU guest at 4 GiB; root is ext4, btrfs root installation pending |
| P0-02 | Security updates and minimum patched bubblewrap/proxy checks implemented |
| P0-03 | Human Sway design template only; real native prompt and rescue TTY pending |
| P0-04 | Separate agent identity/runtime, headless output and capture probes |
| P0-05 | Foot diagnostic; Chromium/LibreOffice sandbox/input contracts pending |
| P0-06 | Accessibility packages installed; named action/coordinate proof pending |
| P0-07 | Protocol inventory; malicious privileged-protocol binding tests pending |
| P0-08 | Positive artifact plus kernel filesystem/IPC/device/network denial probes |
| P0-09 | Agent denied human runtime; authentic approval and physical spoof proof pending |
| P0-10 | Systemd stop with frozen mock core; stopd/grant/physical trigger pending |
| P0-11 | Snapper exact data restore; root/boot rescue pending |
| P0-12 | Raw VM observations; OOM containment follow-up implemented for CI; physical 8 GB measurements and final go/no-go pending |

Nothing is marked fully complete merely because its harness exists. Read the
specific CI run artifact for actual probe outcomes. CI failing blocks merges;
mandatory pending proofs block architecture promotion. These are separate gates.
