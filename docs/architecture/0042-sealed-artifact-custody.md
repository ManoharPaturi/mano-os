# Sealed artifact byte custody

Trusted capture requires a done action from the current boot and its live
Registry resource bound to the original task/human/caller. Only a canonical
workspace-relative path is pinned with the existing beneath/no-symlink/no-device
policy. The native adapter reopens the held O_PATH regular inode through its own
fixed proc-FD reference and checks device/inode/type/single-link identity; no
model pathname or descriptor enters this adapter.

Capture copies at most8MiB into a close-on-exec memfd, rejects source metadata or
size changes while copying, applies WRITE/GROW/SHRINK/SEAL seals, checks them and
hashes the sealed bytes. Store retains at most8 artifacts (64MiB byte ceiling).
Metadata binds artifact/action/task/boot, source device/inode, byte count and SHA256.
FDs close on all error/close paths. Source rename/mutation does not alter the
captured copy; capture does not promise an atomic filesystem snapshot.

Linux seal semantics: https://man7.org/linux/man-pages/man2/F_ADD_SEALS.2const.html
The native DSO remains root-installed and read-only; no writable development
fallback is introduced. Linux unit tests exercise actual native pins, source
mutation, write/truncate denial, intent/wrong-boot/path/hardlink denial and oversize
FD cleanup. The installed-launcher VM creates a real task output, captures it
from its persistent broker process, mutates the source, and checks sealed bytes,
hash and denied mutation. Actual Linux enforcement is pending CI.

This is process-local custody only. Durable artifact persistence, public retrieval,
production broker-filter coverage and independent outcome verification remain
required. Capture always returns effect_verified=false and does not call journal
record_verification. No full task success or full version claim follows from a
sealed hash alone. Original minimal-agent/golden/later OS gates remain required.
