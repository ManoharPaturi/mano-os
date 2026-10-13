# Private activation transport

The launcher activation validator requires the root process, matching LISTEN_PID,
exactly two descriptors named prepare/control, fixed AF_UNIX SEQPACKET listener
paths, SO_ACCEPTCONN and SO_PASSCRED. It marks them non-inheritable and removes
activation environment fields. Unknown descriptors, paths or names fail closed.

The minimum-capability launcher has SETUID/SETGID but no DAC override. Since O_PATH
resolution still checks search permissions, root cannot re-pin cwd beneath the
broker-owned private workspace using broad root permissions. Admission therefore
performs that read-only native resolution as the fixed broker owner in a strictly
single-threaded metadata section, restores the original effective UID in finally,
and only then returns or replies. No task argv or callback runs during this section.
The existing BENEATH/no-symlink/no-mount-crossing and exact cwd inode checks remain.
The trusted broker principal already owns this directory; no DAC capability is added.

Kernel v6.12 commit_creds clears the changing task's own parent-death configuration
on credential changes. It does not modify child signal configuration. The fixture
tests that a running supervised child survives another admission metadata operation.
Primary source: https://github.com/torvalds/linux/blob/v6.12/kernel/cred.c

The disposable actual service now receives root-created systemd activation sockets
owned by the broker with mode0600 in a root-owned parent. A persistent broker UID/GID
process sends real directory rights, starts and polls its own job, reads bounded
output and cancels prepared/running jobs. It verifies activation creator UID0 and
every reply's kernel sender UID0 plus the actual service PID. Instance/action/owner
bindings and all earlier controller/child tests remain required. The native resource
library and guard are installed only inside this guarded disposable fixture.

This is real broker-process transport with operator fixture request/grant IDs. It
does not establish that the broker journal checked grants/epoch before start.
Production daemon activation, actual journal/lease coupling, independent stop and
recovery remain separate gates. No host listener or model connection is installed.
Fixture-wide watchdog time increases only to accommodate the added wire cases;
per-job deadlines, preparation TTL and cleanup limits remain unchanged.
