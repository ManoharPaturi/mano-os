# ADR 0008: Phase 0 original-spec audit

Decision: accept the isolated Sway architecture for Phase 1 development only when
this revision's recovered-root CI audit passes. No production executor exists or
is authorized by this decision. This supersedes the outdated feasibility statements
in ADR0001, not the later broker/runtime and physical release gates.

Review basis: original v2.1 specification, SHA256
`6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace`,
identical to the supplied Downloads/README.md. Sections3.6–3.9, Phase0's ten tests,
backlog P0-01–P0-12, exit rule and definition of done were checked against current
source and accepted real CI38329062530/merged main CI38329419405 artifacts.
This is an engineering review by the implementing assistant, not an independent
external security assessment. The audit runs again on this PR's actual guest evidence.

| Original Phase0 requirement | Current evidence and interpretation |
|---|---|
| 1 Debian13, btrfs root, ≤8GB, patched baseline | Actual4GiB QEMU; second/third boots from btrfs root; package floors and manifest. Original disk retained read-only and hash compared by runner. |
| 2 Prompt-only human Sway | NativeGTK4 actual editable/Send/receipt and mapped fullscreen window; separate human UID/runtime/private network namespace; genuine ttyS0 PAM rescue with core frozen. Headless CI does not prove physical display. |
| 3 Separate agent Sway, browser/Writer input/capture | Separate UID/runtime/private network namespace; restricted Wayland listener; actual headed Chromium locator and Writer Save/ODT/PDF, mapped windows/screenshots. |
| 4 Accessibility named action and coordinates | Task-private D-Bus/AT-SPI, named Save; visible enabled Save at scales1/2 with window-relative geometry and saved content. Hidden menu coordinates are unusable; no universal desktop-coordinate claim. |
| 5 Privileged protocols and malicious X/Wayland | Ordinary surface and trusted bind positive controls;16 forged privileged binds fail, raw listener replacement/access denied; X11 cookie positive, missing-cookie negative, private abstract-socket namespace and other-role negatives. |
| 6 Approval spoof | Section3.8 explicitly permits OS-auth fallback where physical provenance is unavailable. Broker-owned exact task/op/scope/target/risk/nonce/expiry digest; genuine per-request PAM on human ttyS0. Wrong password, altered requests, expiry and replay fail. Three agent-side principals hit EACCES on human approval IPC/journal/uinput node. Concurrent GUI input cannot reach human sockets or change focused canary. No physical guarantee claimed. |
| 7 Stop frozen core/input devices | Section3.9 allows trusted TTY. NativeC stopd with systemd watchdog: hung-daemon restart and human ttyS0 trigger kill all active fixture slice descendants, revoke epoch/grants and shut input while core/authority frozen; bounded process storms saturate both task-unit pids limits. Recovery TTY remains usable. Physical evdev is not available; both input paths are hidden from sandbox. |
| 8 No inherited IPC | Minimal environment, close_fds, unshare-all, synthetic home, default-deny mounts; poisoned session/auth/display environment and inheritable FD negative probes; host runtime/systemd/device/cgroup paths invisible. GUI receives only restricted agent socket; private office bus/AT-SPI and X11 cookie. No human/session/gpg/SSH/PipeWire tree bind. |
| 9 Snapper restore and terminal rescue | Exact data restore, changed root preserved, distinct boot from @recovery with restored sentinel and separate@snapshots. Authenticated TTY works with frozen core and after both independent stops. Installer/firmware boot is later, not this direct-kernel lab. |
| 10 Measurements/logs/compatibility | Kernel meminfo, processRSS/HWM, actual cgroup limits, session/app launch observations, screenshots, hashes, package manifest and failure history. Cold physical boot, model cost, product success rate and physical8GB remain unmeasured. |

The audit maps every backlog issue to explicit passing probes, rejects duplicate or
missing probes, non-audit pending entries, changed/unhashed/off-directory artifacts,
and failed critical outcomes. It records this ADR's hash. CI failures block merge;
the audit's GO concerns the feasibility architecture, not a live authorization grant.

## Chosen architecture

Maintain separate human and agent compositor identities/runtime trees and network
namespaces. Ordinary task applications use security-context-restricted Wayland;
input/capture are broker-controlled services with privileged protocols inaccessible
to workers. XWayland is task-private, cookie authenticated and network isolated.
Use request-bound OS authentication for trusted approvals until physical input
provenance is independently validated. Preserve a native protected stop/TTY route
independent of core and approval-service Python. Runtime must implement these
boundaries rather than adopting root lab setup as an agent API.

## Remaining mandatory work

Phase1 must build typed broker IPC, operation-scoped grants, authoritative journal,
FD-pinned resource resolution, production cgroups, seccomp/Landlock tests and isolated
terminal/model routing before any model can execute. Existing lab workspace path
resolution is race-prone and unsuitable for production. Input controllers must be
production mediated; fixed CI fixtures do not grant arbitrary execution authority.
Phase2 delegates and injection corpus, Phase3 runtime.deb/GUI workflow gate,
Phase4 durable replay, Phase5 credential/network/device gates, Phase6 physical8GB
measurements/hardening, Phase7 signed installer/firmware/physical install remain.

Cloud kernel lacks usable uinput driver: node permission denial is verified, actual
virtual-device creation is not. Physical provenance/display/performance and secure
firmware/install are explicit release constraints, not erased by Phase0 completion.
Porting to another compositor, changing privileged globals, approval strategy,
namespace topology or package contracts requires repeating relevant boundary tests.

## Stop test compatibility finding

Early pressure runs stalled at emulated UART kernel info output. Linux's RCU docs
identify slow consoles as a possible source of stalls. The accepted fixture keeps
warning/error output visible, journals info and restores original printk settings;
both task groups still hit kernel limits and captured journal shows real rejections.
The passing run has no RCU stall/BUG/soft-lockup. This supports a console-specific
diagnosis, not a general kernel reliability claim. KVM host CPU is recorded;4GiB/two
vCPUs unchanged. No security assertions were skipped to obtain this decision.

Rollback: revert the audit PR to restore Phase0 NO-GO. No installed host service,
model connection or protected policy is changed by this audit tool.
