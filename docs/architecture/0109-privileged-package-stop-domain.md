# 0109: Independent Stop for a privileged package domain

Before adding package execution, extend native Stop beyond unprivileged task
workers and the reasoning core. Reserve `mano-package.slice` as a fixed domain
for future privileged package controllers and workers. The shipped slice is
empty: this change adds no package service, socket, Root grant or apply API.
The existing launcher, its permissions and sandbox remain unchanged.

Native Stop latches authority first, then writes `cgroup.kill` for the whole
package slice as well as the existing task and core domains. Killing the whole
slice includes a future package controller and descendants in separate process
sessions; a coordinator cannot be left outside a task-only kill path. Native
rearm also requires the package slice's `cgroup.events` to report empty. The
path is compiled in, not supplied by a caller. Root ownership, no symlink, mode
and cgroup-v2 filesystem checks remain. The old core check is shared internally
with the new fixed domain, not turned into a public path-taking operation.

Stopd requires the package slice before startup and receives its specific cgroup
write path. Its Linux capability set remains empty. Runtime disable/removal
stops the package slice along with existing domains. Future privileged jobs must
join this domain before effects and independently check armed state and fresh
approval; an empty slice is not an execution or install authority.

The guarded disposable Debian probe creates a transient Root-UID service in this
slice with two processes, one in a separate session. The fixture writes only a
private nonsecret `/run` canary. It has an empty effective capability set, no new
privileges, private network/devices/temporary mounts and read-only cgroup mounts;
an actual attempted host-cgroup write must fail with EROFS. Pin exact identities
with pidfds and confirm kernel T for both Root processes, broker and launcher.
With other Stop domains empty, native PAM rearm must refuse the populated Root
domain. The independent human Stop client must kill both Root processes and
drain the domain while the Python controllers remain frozen. Verify pidfd exit,
unchanged canary, surviving native Stop daemon/Root observer, stale rearm refusal,
fresh PAM rearm after drain and no automatic worker restart. End latched.

Repeat the same Root fixture against the installed runtime after the clean
stock-Debian reboot; only the CI test driver is copied, not product source or
configuration. Preserve all earlier isolation/package/recovery and six fresh GUI
gates. Local tests cannot establish this Linux/kernel/native behavior.

This validates UID0 process Stop coverage with a controlled, capability-empty
fixture. It does not prove containment of a hostile fully privileged process,
arbitrary maintainer scripts, uninterruptible kernel I/O, package transactions or
the complete privileged apply/recovery workflow. Those remain separate gates.

Primary contracts: [kernel cgroup.kill semantics](https://docs.kernel.org/admin-guide/cgroup-v2.html)
and [Debian 13 systemd execution protections](https://manpages.debian.org/trixie/systemd/systemd.exec.5.en.html).
