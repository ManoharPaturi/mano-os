# Approved broker PTY sessions

`terminal.open_pty` is an explicit PAM-approved capability with exact argv, pinned
workspace/cwd, deadline, geometry and input-byte budget. Existing permission
profiles do not implicitly include it. Approval preparation has no application or
PTY effect. The broker commits executing before private start. The Root launcher
retains broker PIDFD/instance/job/action ownership, places a blocked child in its
limited cgroup, then drops to the allocated task account. Only that worker opens
and owns the master/slave. The native guard and all standard RUN boundaries stay.

Public `pty_status/read/write/resize/close` require the native task UID, owned
action and current boot. New input requires live executing action, exact grant,
epoch, expiry and unlatched Stop. Each attempt commits its key, digest, private
operation identity and full attempted-byte charge before delivery. Known partial
writes are explicit. Duplicate keys return saved acknowledgements without worker
contact; changed payloads deny. Lost delivery/acknowledgement cancels the job,
marks unknown and cannot be automatically resent. Restart revokes process-local
authority and marks outstanding input intents unknown. Rearm cannot revive them.

Limits: two active sessions, 32 retained sessions, 64KiB combined output,
1..4096-byte writes, at most64 control attempts (the final slot reserved for close),
and at most64KiB approved lifetime input. The worker independently enforces input,
output and deadline ceilings. Private packets are bounded8KiB; one-second input
acknowledgement deadline, bounded nonblocking sweeps, cgroup kill and owner death
prevent unresponsive Python from restoring authority. Native Stop remains a
separate process and drains frozen workers/descendants.

Combined terminal bytes are untrusted and have no automatic ANSI rendering,
provider disclosure, artifact verification or separate stdout/stderr claim. Reads
use an append-only offset and prefix SHA-256, bounded to4096 bytes. Outcome and
history are saved before action settlement; uncertainty remains explicit.

The local SDK requests approval, proposes an approved open, writes explicit keys,
reads cursor-bound bytes, resizes and closes. Model planning, interactive human UI,
physical input provenance, delegate integration and complete Phase2 remain later
acceptance gates. CI tests actual installed task-UID SDK/native PAM flow, replay,
TTY identity/resize/EOF, and native Stop with frozen public PTY descendants.
Local tests inject lost acknowledgements, changed handles, partial writes, Stop
between commit/delivery, scope, budget and expiry. Those tests do not establish
physical-machine behavior or full v2.1 completion.
