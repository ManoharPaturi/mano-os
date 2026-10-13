# ADR0011: non-root request service lifecycle

Status: candidate until real Debian service CI. Phase1 remains incomplete.

The request handler now has a fixed-path systemd socket-activated service. It
refuses root, arbitrary CLI arguments, missing/mismatched activation identity,
multiple descriptors, non-packet/non-listening sockets, unexpected socket paths
and listeners lacking per-message credentials. The only inherited authority is
one root-provisioned request listener and systemd notification channel. No effectful
execution or approval/control endpoint is added.

Socket ownership root/ mano-request mode0660 controls admission. Only broker-issued
task identities should join that group; membership alone cannot mint a grant.
The broker runs as mano-broker with no capabilities, no-new-privileges, private
devices/tmp, restricted address families/namespaces, protected home/system/kernel
and a system-call allowlist. Limits:16 tasks,128MiB memory,20% CPU,128FDs. Root
owns source/units. StateDirectory creates broker-private runtime state0700/DB0600
under a root-owned traversal-only0711 parent. Separate root authority files remain
0600; do not recursively hand their ownership to the broker.

One request is processed at a time with a two-second I/O deadline, backlog32 and
global token budget20 burst/10 connections per second. Excess connections close
without parsing or reserving rights. This bounds resources, not fair service under
unlimited local attacker traffic. Separate trusted approval/stop channels remain
required. READY/WATCHDOG notify and six-second systemd watchdog fail/restart the
service; recover converts interrupted execution state to unknown without replay.

Fixed disposable CI installs the actual units/source, creates a non-root broker,
seeds a trusted synthetic executing record before activation, and tests worker
proposal/replay, OS socket/journal denials, actual UID/capability/seccomp state,
limits, slow-client timeout and SIGKILL/restart preserving unknown state. It restores
parent permissions/removes only its own fixtures. This seed is not a production
approval path, and no user host service is installed.

Post-main PR20 exposed an existing stop observer race: a killed PID disappeared
between /proc existence and read, raising ESRCH. The observer now treats only ENOENT/
ESRCH as reaped, or Z as zombie. Live states still fail; permission errors propagate.
Empty-cgroup, stop latch/epoch, grant revocation and removed input remain mandatory.
A regression test covers ESRCH/ENOENT/live/zombie/permission-error cases.

Next: separate request-bound PAM approval with exact operation/argument binding,
resource descriptors and real sandbox execution/stop/verifier integration before
minimal model/terminal tools and the original Phase1 golden task/policy gate.
All original later v2.1 physical/installer/release gates remain required.
