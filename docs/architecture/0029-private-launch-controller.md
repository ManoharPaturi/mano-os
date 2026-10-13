# Private launch job custody

The controller adds a fresh per-instance ID and random job handles around the
accepted supervised child. It retains at most 64 records. Each record binds its
action ID, preparing broker Peer and an open pidfd for that process. Control must
match the instance, job, action and exact owner; a dead original owner cannot be
replaced by PID reuse. Sweep cancels jobs when their owner dies and polls deadlines.
Shutdown closes records and owner pidfds.

The control schema permits hello/start/status/cancel/read_output only. Sender UID
and GID must be the named broker, never root or a task identity. Kernel transport
wrappers use the existing strict connection/message credential receiver; control
rejects passed rights, while prepare requires the admitted two directory FDs.
The admission object now carries the preparing Peer for custody transfer.

Status never contains full output or an independent-success assertion. Its fixed
effect_verified field is false. Output reads accept stdout/stderr, integer offsets
within 64 KiB and lengths 1–4096; bytes are returned as base64 in bounded chunks.
Completed child reports release duplicate base64 buffers, bounding retained data.

An authenticated start is a trusted broker assertion. It is not proof that the
broker actually checked its journal/grant/epoch; that coupling is the next gate.
No production activation sockets/listener or public model execution operation is
installed. The root service fixture uses explicitly synthetic operator Peer
metadata to exercise the dispatcher against real supervised children. Unit guards
test owner/instance/action/dead-pid and extra-field denial, wrong actor identities,
and bounded output. Kernel broker transport coverage remains the separate admission
fixture; this change does not claim an end-to-end broker authorization test.
