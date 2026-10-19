# Task-owned PTY worker and kernel isolation gate

Phase2 needs persistent interactive terminals. Before adding public session/input
authority, establish a reusable unprivileged worker primitive inside the existing
FD sandbox. A PTY requires controlling-terminal/session behavior that the current
pipe-based runner intentionally does not provide. This change implements and
tests that kernel boundary; it does not implement the public terminal.open_pty
broker capability, input-grant journal or complete Phase2.

TaskPTY validates the same task identity, held workspace/cwd descriptors, patched
bubblewrap and Root-owned native guard as the existing runner. Allocate the
master/slave only after validation and revocation checks. Pass the task-owned
slave as exactly0/1/2; close all unrelated descriptors and keep the master only
in the unprivileged worker. Keep --new-session and all existing namespace,
network, cgroup, filesystem, Landlock/seccomp/NNP/capability restrictions.

A private sandbox command mode adds the fixed --task-pty guard switch and TERM.
The native guard requires all three standard descriptors to identify the same
character terminal owned by the effective task UID. It creates a session only
when needed, then uses TIOCSCTTY with argument0 and verifies tcgetsid. It never
forces or steals another session's terminal. Reject pipes, /dev/null and a
foreign-UID synthetic slave before executing the application. The standard
terminal.run path does not opt into this mode or acquire a controlling terminal.

Acquire the exclusively owned controlling terminal after closing3+ descriptors
and before applying the existing Landlock/seccomp filters. The application runs
after those filters and retains only its private terminal on0/1/2. Actual tests
must confirm /dev/tty, foreground interrupts, terminal geometry and all previous
protected-file/network/human-device/socket denials. Do not weaken a failed kernel
check or remove --new-session as a fallback.

The primitive provides bounded nonblocking input/read, resize, poll and explicit
close; it must be driven by an authorized supervisor in a bounded task cgroup.
Fixed input/output lifetime ceilings are64KiB each, per-operation byte bounds4096,
geometry1–200rows/1–400columns and runtime up to300seconds. Input attempts are
charged before writing, partial writes are returned explicitly and never retried.
Canonical input and signal handling remain enabled, echo and newline output
translation are disabled. PTY stdout/stderr are one combined stream, never
misrepresented as separately captured pipe streams. Output overflow closes the
session; EIO alone never establishes a process exit. Timeout/revocation/errors
close the owned process group and master; master closure is guaranteed even if
process wait fails. Native cgroup Stop remains the independent kill boundary.

The caller must journal interactive writes before effects and treat uncertain
input as unknown. That broker-level replay/expiry/session protocol is subsequent
work, not provided by this primitive. No public Root TTY/path/command helper is
added. The code never accepts a human terminal handle or inherits human display,
SSH or approval IPC. Terminal bytes remain untrusted data with no verification
or model-disclosure authority.

Unit tests cover validation-before-allocation, partial/no-retry input charging,
revocation/invalid observers, geometry/output bounds and wait-error FD closure.
The Debian CI probe uses the installed worker under the actual allocated task
UID, cap-zero/NNP cgroup and original sandbox, exercises echo/resize/EOF/interrupt,
timeout/revocation/output-limit and protected-path/network/device/socket denials.
A Root-created disposable synthetic foreign slave must be rejected; no physical
human TTY is used. A separate worker and its PTY child are frozen and included in
the existing real native Stop test while broker/launcher/core are frozen. Their
processes must exit and the core cgroup must drain before acceptance.

The test supervisor permits namespace creation before bubblewrap, matching the
existing launcher worker's setup; the sandbox native guard denies it afterward.
Production service policy is not relaxed. This is installed-worker CI evidence,
not a public broker/PAM PTY workflow, hardware input or release acceptance.

Primary Linux API references, checked2026-10-19:
https://www.man7.org/linux/man-pages/man2/TIOCSCTTY.2const.html
https://man7.org/linux/man-pages/man3/openpty.3.html
