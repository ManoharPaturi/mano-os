# ADR0018: narrow root descriptor provisioning receiver

Status: candidate until Linux/real Debian CI. This receiver is not yet wired to
production broker listeners or the public preparation path.

Provisioning accepts one matching kernel-authenticated root connection/message and
one SCM_RIGHTS O_PATH directory FD. MSG_CMSG_CLOEXEC protects received descriptors.
Truncation, missing/multiple/unknown ancillary data, handed connections, non-directory
or non-O_PATH descriptors deny; every received descriptor is closed on error.
There is no root pathname, resource ID, FD number, environment or command in JSON.

Packet fields are version/operation and human UID/caller UID/mode/classification.
Root is a trusted operator, not proof of human PAM consent. Directory must be owned
by the receiving broker principal, grouped for the caller's resolved non-root
primary group and exactly0770 or2770. Other-access, mismatched owner/group or unknown
account/schema deny. Registry mints fresh ID, creates private task state and binds
that task immediately. Failure closes/removes partial registration. Root descriptor
selection and UID policy are still trusted provisioning responsibilities.

This does not make task-created files readable by the broker: namespace/DAC/ACL or
properly delegated FD access remains needed. It is not arbitrary privileged command
execution, a data snapshot, an executor, or proof that public intents use live leases.
Trusted daemon/socket/installer integration and propose-to-registry routing remain next.

Debian probe drops to a real temporary non-root principal and receives root FD
messages through a socket deliberately0666 to test authentication beyond DAC. It
requires exactly one task/resource and checks per-request FD deltas for no leaks.
Cases: valid directory, no/multiple FD, file type, non-O_PATH, world access, wrong
owner/group, injected pathname, invalid mode cleanup, unprivileged sender and root
connection handoff. State/fixtures/library/account are disposable and removed.
Linux unit tests cover schema/role/owner/privacy/cleanup/task binding; Mac skips them.

No local service or root change is installed. All previous VM/PAM/descriptor/stop
suites remain required. Then runtime integration, sandbox/cgroups/seccomp/Landlock,
native stop/verifier/prompt/minimalmodel and original Phase1 golden gate. Full original
v2.1 and physical/installer/release requirements remain active.
