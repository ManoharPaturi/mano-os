# Native independent emergency Stop

The native mano-stopd service has one fixed activated human socket, one fixed
root-owned human UID policy, and one fixed launcher cgroup directory. Its one-byte
S protocol accepts no task IDs, cgroup paths, commands or grant fields. Both
connection and per-message kernel credentials must match the human; inherited
connections, passed descriptors and truncated/extra packets are denied.

Stop writes a root-owned persistent latched state before iterating only task-
plus32hex directories under mano-launcher.service. It writes cgroup.kill for each,
leaving the manager control group untouched. The scope is capped at64 directories.
Directory ownership, no-follow opens and cgroup2 filesystem identity are checked.
The helper executes no shell/Python/process-kill command and needs no Linux
capabilities. Systemd supplies protected filesystem/StateDirectory access, syscall
filter, NNP, small memory/PID limits, and an independent watchdog.

The kernel describes cgroup.kill as killing all descendant processes and handling
concurrent forks/migrations: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#core-interface-files
Writing the kill file is a submitted kill operation; the VM test independently
checks populated0 before accepting drain completion.

The disposable broker/PAM test now starts a real PAM-approved task that forks a
child, establishes a new session and signals readiness. It checks malformed human
packets do not trip the latch and the task UID cannot connect. It freezes both the
actual broker and launcher PIDs, requests native Stop from the human, verifies root
reply credentials, cgroup drain, persistent latch and that both Python services
remain frozen. It resumes services before cleanup. Compilation and VM acceptance
are pending; local Python tests cannot prove this native/kernel behavior.

This PR establishes the native termination backend only. The persistent latch is
not yet consumed by launcher admission/start or broker grant/restart state, and
PAM-bound rearm is not implemented. Report native_stop_grant_latch_integrated=false
until that coupling is implemented and tested. Physical keyboard/TTY provenance
remains null, and the full emergency-stop contract is not complete from this PR.
