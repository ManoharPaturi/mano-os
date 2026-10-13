# Private launch admission

The library receives a bounded AF_UNIX SEQPACKET launch envelope with exactly
two SCM_RIGHTS O_PATH directory descriptors. Its connection and per-message
kernel credentials must match exactly, including PID, and the sender must be the
named non-root broker. Inherited connections, root/model/task senders, truncated
packets, unexpected ancillary data and extra descriptors are rejected. Received
rights are closed on every error; successful admission owns them until close.

The target must be a locked allocated task account: unique private primary group,
only mano-request supplementary group, non-login shell and no home. No root,
human or broker target is accepted. The workspace must have the broker owner,
task primary group and private 2770 mode. Both FDs must be non-inheritable O_PATH
directories. The existing typed ActionRequest parser accepts terminal syntax;
extra environment, options or host path fields are not added by this protocol.

The native openat2 resource resolver re-pins the approved relative cwd under the
held workspace and compares device/inode to the supplied cwd FD. An outside or
replaced cwd fails closed. The workspace root may have been renamed because
resolution starts from its descriptor. A renamed nested cwd whose old relative
name no longer resolves is deliberately denied at this boundary; no path fallback
is used. Every future launch must use the admitted descriptors, not re-resolve
submitted paths after admission.

This admission library is not installed as a service and does not launch code.
It authenticates the broker transport and validates syntax/identity/descriptor
binding, not the action journal's grant or current epoch. Broker authorization,
one-shot action custody, root lifecycle/cgroup supervision, credential dropping,
stop/revoke and independent verification remain required before effects. Synthetic
IDs in the fixture are metadata only and do not establish any execution grant.

The disposable VM fixture tests a real root receiver and real broker sender,
positive two-FD transfer, thirteen denials including inherited broker connection,
cwd substitution and wrong peer identities, and zero descriptor leaks. Host socket
permissions are intentionally permissive in that fixture to exercise kernel
credential validation independently of DAC. No production listener is created.
