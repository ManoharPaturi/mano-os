# Phase 0 evidence index

Verified first lab run: [CI 38289411969](https://github.com/ManoharPaturi/mano-os/actions/runs/38289411969),
PR #1 merged, 13 passing probes, zero failures, nine pending checks.
The run used KVM and Debian 13 with a 4 GiB RAM ceiling.

OOM and GUI follow-up: [CI 38289976575](https://github.com/ManoharPaturi/mano-os/actions/runs/38289976575),
PR #2 merged, 16 passing probes, zero failures, nine pending checks.
Kernel reports `oom-kill`; the human-observer service remains active.

Btrfs-root boot: [CI 38293373666](https://github.com/ManoharPaturi/mano-os/actions/runs/38293373666),
PR #4 merged. Actual root `/dev/vdc[/@]`, preserved original disk hash,
20 passing probes, zero failures, eight pending checks.

Root recovery: [CI 38294272602](https://github.com/ManoharPaturi/mano-os/actions/runs/38294272602),
PR #5 merged. Actual `@recovery` boot, distinct boot ID, restored sentinel,
changed `@` retained, separate snapshot store; 21 passing probes, zero failures.

Current architecture decision: **NO-GO for production execution**.
CI emits `report.json`, hashed logs, a package manifest, memory observations,
mount inventory, Sway screenshot and independent-stop outputs.

| Issue | Current implementation and evidence boundary |
|---|---|
| P0-01 | Debian 13 QEMU guest at 4 GiB; real btrfs-root second boot implemented for CI acceptance |
| P0-02 | Security updates and minimum patched bubblewrap/proxy checks implemented |
| P0-03 | Human Sway design template only; real native prompt and rescue TTY pending |
| P0-04 | Separate agent identity/runtime, headless output and capture probes |
| P0-05 | Foot diagnostic; Chromium/LibreOffice sandbox/input contracts pending |
| P0-06 | Accessibility packages installed; named action/coordinate proof pending |
| P0-07 | Protocol inventory; malicious privileged-protocol binding tests pending |
| P0-08 | Positive artifact plus kernel filesystem/IPC/device/network denial probes |
| P0-09 | Agent denied human runtime; authentic approval and physical spoof proof pending |
| P0-10 | Systemd stop with frozen mock core; stopd/grant/physical trigger pending |
| P0-11 | Snapper exact data restore verified; root snapshot clone/third boot implemented for CI |
| P0-12 | Live VM memory/Sway/cgroup metrics implemented for CI; final architecture remains NO-GO |

Nothing is marked fully complete merely because its harness exists. Read the
specific CI run artifact for actual probe outcomes. CI failing blocks merges;
mandatory pending proofs block architecture promotion. These are separate gates.

Physical 8 GB performance remains a separate Phase 6 requirement; installer and
firmware boot remain Phase 7 requirements. VM observations cannot fulfill these.
