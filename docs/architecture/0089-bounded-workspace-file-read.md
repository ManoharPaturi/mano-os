# Bounded authorized workspace reads

The broker already accepts exact `files.read` approvals and pins beneath-only
regular workspace inodes. Previously a production read stayed at intent: only
terminal and model actions had schedulers. Execute one read per service tick,
after its acknowledgement, using that original descriptor without resolving its
submitted pathname again. Keep writes, health and GUI execution separate.

Require the current task, caller, resource, boot, exact grant and arguments,
live profile provenance, epoch and unlatched Stop. Journal executing before
capture. Reuse the native nonblocking read-only pinned-inode reopen and Linux
memfd seals, with a stricter 32 KiB read ceiling. Reject oversized, unlinked,
hardlinked or concurrently changing files; never return a truncated success.
After capture, observe native Stop again and recheck grant/profile expiry before
atomically committing done plus the immutable artifact bytes and SHA-256. All
temporary descriptors close. Exceptions after start settle to unknown, before
start to failed; the deque never automatically retries an action.

`file_result` is a read-only public chunk operation with exactly task/action IDs,
offset and length (up to 4096). It discovers only a unique completed read artifact
belonging to the authenticated native caller and current boot. Existing durable
artifact integrity and range checks apply. No new grants, filesystem read,
execution, verification or network access occurs during retrieval. Saved results,
like existing artifacts, remain readable after Stop within the same boot; Stop
prevents new capture. Capture retains `effect_verified=false`; this is byte
custody, not a verified task outcome. File contents remain untrusted data.

The existing global eight-artifact lifetime quota is preserved. This prototype
does not implement bulk files, streaming, artifact eviction or arbitrary host
access. A full store fails before read start. Persistent results share existing
SQLite custody; no additional plaintext result log or source bytes in diagnostic
events are introduced.

Tests cover real Linux pins/seals, exact boundaries/empty bytes, rename versus
unlink, immutable retrieval, scope/ranges, Stop before/during capture, expiry,
storage rollback and closure. The installed guest adds a real allocated task
request using a PAM-approved profile, reads its actual terminal-produced file,
checks bytes/hash and wrong-caller/range/replay denial. The earlier manual
executing/unknown restart fixture now explicitly uses a write proposal (which
still has no executor); its actual native PAM, pin and restart assertions remain.
An automatically scheduled read can no longer be used as an artificial held-intent
fixture. No physical, live-provider, broader file-write or release claim follows.
