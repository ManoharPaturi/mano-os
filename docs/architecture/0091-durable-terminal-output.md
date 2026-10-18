# Durable bounded terminal output

The launcher already captures stdout/stderr and exposes owned private output
chunks. The broker previously discarded that access after journaling the exit
code, leaving the core unable to inspect a failed test's actual output. Reuse
the authenticated private launcher protocol; do not introduce a new execution,
filesystem, shell or credential interface.

After an explicit finished outcome, validate return code/reason and fixed64KiB
per-stream sizes. Retain the exact instance/job/action handle and collect at
most one4096-byte chunk per scheduler tick. Require bound replies, finished state,
exact chunk length and EOF. Recheck the same outcome every tick. Keep the action
executing until both streams are captured, native Stop is observed again and
grant authority is rechecked. Atomically persist bytes/hash metadata and the
done/failed exit transition. Unknown/lost/malformed output or interrupted capture
settles unknown and discards partial process-local buffers; never rerun a command
to reconstruct missing output. Initial quota failure occurs before launcher
preparation and any effect.

A separate private SQLite terminal_outputs table stores at most64 results with
two bounded64KiB blobs, matching the existing retained-launcher-job scale and
avoiding consumption of eight general artifact slots. Shared public constants
also define the runner's real stream cap. No automatic eviction/deletion occurs.
State startup creates the table without changing existing grants/actions. Legacy
or missing custody is explicitly null, never fabricated empty-success output.
Atomic storage failure preserves unknown effect rather than publishing done.

Public terminal_output returns metadata or explicit null for an authorized exact
terminal action; terminal_output_read returns bounded chunks. Both bind native
caller/task/action/current boot. Durable row/exit state, stream lengths and hashes
are verified on every read. Wrong caller/action/task/boot/range denies. Captured
history remains readable after Stop in the same boot, as existing artifact
history does; retrieval issues no grant and executes nothing. Root has a matching
protected metadata query; it derives the caller from the current-boot task.

Metadata includes actual return code and runner reason. Nonzero commands retain
useful output and remain failed. Output-limit termination is explicitly marked;
timeout/revocation remain separate reasons. Byte custody always has
effect_verified=false and never implies independent semantic task verification.
Raw terminal output is untrusted data, not instructions, markup or terminal
control to execute. Never send it to a model automatically or include raw bytes
in privileged diagnostic events or human journal summaries.

The SDK validates stable metadata, exact chunks/EOF and full digests before
returning binary bytes to an explicit local caller. It paces chunk requests below
the existing10requests/s broker budget; transport failure never retries execution.
The core graph keeps metadata-only terminal_output references, including failed
commands, and refreshes them on journal replay. The Root lifecycle discards core
metadata and reconstructs it through protected action/custody queries. Existing
terminal completed/verifying/failed semantics remain separate from availability.

Tests cover atomic multi-chunk failed results, immutable history/reopen, binary
and empty streams, output-limit marking, scope/ranges/corruption, metadata/hash/EOF
spoofing, quota denial before effects, Stop during capture, lost reply/no retry,
storage rollback and core metadata-only replay. The installed guest adds actual
native-PAM task execution exiting7 with7000 binary stdout bytes and8000 stderr
bytes; the SDK must retrieve exact bytes under that task UID, with wrong-caller
denial and replay canary preservation. The fresh stock Debian package probe
checks known stdout/stderr hashes via the packaged core before and after reboot.
Provider calls and physical/release acceptance remain outside this evidence.
