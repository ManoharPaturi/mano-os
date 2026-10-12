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
| P0-03 | Native GTK4 prompt and actual serial PAM/TTY rescue with stopped mock core verified in CI |
| P0-04 | Separate agent identity/runtime, headless output and capture probes |
| P0-05 | Real sandboxed app contracts; concurrent human canary/focus and socket-denial probe under CI acceptance |
| P0-06 | Real task-private accessible Save; visible-control window-coordinate/scale probe added for CI acceptance |
| P0-07 | Restricted Wayland forged privileged binds denied; authenticated private XWayland domain verified |
| P0-08 | Positive artifact plus kernel filesystem/IPC/device/network denial probes |
| P0-09 | Request-bound OS-auth fallback/PAM spike added; human-only IPC and actor uinput/journal denials tested |
| P0-10 | Systemd stop with frozen mock core; stopd/grant/physical trigger pending |
| P0-11 | Snapper exact data restore verified; root snapshot clone/third boot implemented for CI |
| P0-12 | Live VM memory/Sway/cgroup metrics implemented for CI; final architecture remains NO-GO |

Nothing is marked fully complete merely because its harness exists. Read the
specific CI run artifact for actual probe outcomes. CI failing blocks merges;
mandatory pending proofs block architecture promotion. These are separate gates.

Physical 8 GB performance remains a separate Phase 6 requirement; installer and
firmware boot remain Phase 7 requirements. VM observations cannot fulfill these.

Writer acceptance candidate: CI 38308357005 passed normal and recovered-root runs.
Actual LibreOffice 25.2.3.2 GTK3/Wayland window, private task accessibility bus,
named Save action and exact ODT/PDF text verified. Recovered suite: 29 pass, 0 fail,
5 pending; first-root suite: 28 pass, 0 fail, 6 pending before recovery validation.
AT-SPI reports the off-screen menu position sentinel -2147483648; semantic action
works, but this is no coordinate/scale proof. The final PR head must independently
pass all CI before merge. No architecture promotion follows from this contract.

Visible-control follow-up tests scales 1 and 2 using independently observed Sway
client/output geometry, actual controller clicks and exact saved ODT content.
The worker never receives compositor IPC. Read the final CI artifact for acceptance;
these probe additions do not promote the architecture or prove physical input.

Native human prompt candidate uses GTK4 in its separate CI human Sway session,
with an actual accessible editable/Send action, fullscreen window and screenshot.
The serial recovery probe authenticates via real ttyS0/getty/login/PAM, checks a
complete challenge/UID/TTY response with stopped mock core, verifies account/core
cleanup, and redacts temporary fixture material. Final-head CI determines acceptance.
Physical display/input and a broker-bound approval service remain unverified.

Concurrent-session follow-up keeps the human prompt alive while real agent browser,
Writer and XWayland actions execute. It requires focused unsent text and unchanged
request count, records focus/text events and 50 ms snapshots, and checks compositor
focus checkpoints plus denied human-socket access from agent-side principals. Final
CI artifacts determine acceptance; physical input provenance remains unverified.

Authenticated approval candidate: CI 38321824070 security lab passed both boot
stages. Real per-request PAM on ttyS0 accepted one bound approval and rejected wrong
password, modified digest/nonce/target, expiry and replay. Root-owned 0600 journal
and nine kernel EACCES actor probes verified. Cloud uinput driver unavailable;
character-node permissions tested, physical/device behavior not claimed. This is
a fixed CI authority spike; production broker and full grant lifecycle remain later
work. Final PR head must pass CI before merge; architecture remains NO-GO for P0-10.
