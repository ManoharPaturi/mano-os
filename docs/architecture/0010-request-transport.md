# ADR0010: kernel-authenticated request-only transport

Status: candidate until final-head CI. Phase1 remains incomplete.

The core request channel uses local AF_UNIX SOCK_SEQPACKET messages. A trusted
listener must enable SO_PASSCRED before accepting/queueing requests. The handler
checks SO_PEERCRED against each message's kernel SCM_CREDENTIALS (PID/UID/GID).
This rejects connections inherited or passed to another process. Unprivileged
caller identity comes from the kernel, never request fields. Tasks must still use
separate broker-provisioned identities; a shared UID is not a per-task isolation
boundary. Privileged credential forgery/root compromise is outside this boundary.

Only propose and status are exposed. A proposal can reserve an already approved
grant, but cannot issue a grant, start execution, stop/rearm, change policy or mark
itself verified. Status requires matching task/caller/boot and returns a small
public result without arguments, grant details or private evidence. This module's
in-process dispatch function is trusted code, not a standalone authority endpoint.

Packets are bounded to64KiB, preserve message boundaries and reject truncation,
extra envelope fields, malformed/deep JSON and unexpected ancillary data. Received
SCM_RIGHTS descriptors are closed and denied, using MSG_CMSG_CLOEXEC; excess/truncated
rights are closed by Linux. A two-second connection timeout bounds one request.
A dropped response does not undo a journaled reservation; exact replay returns the
original state rather than executing again. The handler never executes commands.

CI proves a worker can propose/replay/read status over a real pathname socket;
agent/core/human identities, cross-caller status, forged UID, self-verification,
grant minting, stop control, inherited connection, passed FD, oversized/malformed/
deep JSON all deny. The public CI socket is deliberately0666 to test authentication
independently of filesystem permissions. This is a fixed root-controlled fixture,
not production provisioning. Exactly one reservation remains and no received FD
leaks. Local Mac tests skip only the Linux transport test; Ubuntu CI runs it.

Next gate: protected systemd socket/service provisioning under a non-root broker
principal, connection rate/concurrency bounds and fail-closed lifecycle; a separate
trusted request-bound PAM approval channel; resource registry/FD pinning; actual
sandbox/cgroup/seccomp/Landlock execution, native stop and independent artifact
verification. Do not treat this handler as a production daemon or completed Phase1.

Reference: [Linux UNIX-domain socket credentials and descriptor semantics](https://man7.org/linux/man-pages/man7/unix.7.html).
