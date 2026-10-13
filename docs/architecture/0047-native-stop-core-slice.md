# Native Stop covers reasoning processes

All transient core steps now run in the root-managed mano-core.slice, with an
aggregate512MiB/128task/50percentCPU ceiling. Systemd's hyphen hierarchy places it
under /sys/fs/cgroup/mano.slice/mano-core.slice. The independent native Stop service
requires that slice before startup so its fixed read-write cgroup mount is present.

Human Stop attempts both the existing launcher task-group kills and a recursive
cgroup.kill on the core slice, including when the durable latch write fails. It
checks root ownership, no writable group/other mode, cgroup2 filesystem and no-follow
FDs. No caller supplies a PID or cgroup path, and no KILL/SYS_ADMIN capability is
added. Authenticated rearm also requires the core slice to be unpopulated.

The installed VM fixture starts an actual task-UID core process with a detached
child in the slice, freezes both plus the Python broker/launcher, then invokes
native human Stop. It requires an empty core slice and both original processes
exited-or-zombie within the same3second deadline. Broker/launcher must still be
frozen while Stop succeeds. Existing grants, recovery and rearm checks remain.
Actual enforcement is pending exact-head CI; no physical input claim follows.
