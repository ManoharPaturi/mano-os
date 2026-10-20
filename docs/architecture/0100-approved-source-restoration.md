# 0100: Separately approved source workspace restoration

A `workspace.restore` grant binds the source checkpoint action/SHA-256, a fresh
before-checkpoint action/SHA-256 and its private directory-layout SHA-256. All
references are immutable broker custody. The before checkpoint belongs to the
current destination task/boot; source ownership must match the same human. A
source may be from another task or older boot, but that does not grant the caller
permission to read it. Only the protected native human view exposes the computed
file operations, original source task/boot/classification and destructive scope.
Public pending responses retain only approval ID/state/grant. Fresh native PAM
consent is mandatory; Auto/Full profiles cannot authorize restoration themselves.
The grant binds exact immutable inputs; custody/layout are revalidated before use.

The checkpoint Git decoder reads bounded canonical object data without extracting
an archive, invoking Git, loading config or executing source code. It validates
member paths/types, bounded decompression, object hashes, modes/tree limits and
exact canonical regeneration. SHA-256 remains the integrity boundary. New
checkpoint captures also retain private directory/excluded-entry layout for exact
before-state comparison; older source snapshots remain usable. A fresh before
capture with layout is required. Required source parent directories are restored;
empty source directories outside Git are not claimed as preserved. Current extra
empty directories can be explicitly removed. Ancestors of excluded `.git` entries
are protected, and Git metadata/private staging are never restoration targets.

One trusted unprivileged broker restore job runs at a time. It retains original
workspace/parent pins and rejects other in-flight destination actions. New actions
for that destination cannot interleave until restoration settles. Capture checks
the live source tree and layout against the approved before checkpoint before
staging and again before the first destination effect. A 60-second ceiling is
further capped by the grant timeout/expiry. Retention is eight attempts; free space
must cover 64 MiB plus 12 MiB staging/journal reserve. Existing source/file/directory
and approval-plan limits remain enforced.

New fixed C functions run as the broker UID with no capabilities. They create
private staged regular files with only fixed 0660/0770 modes, publish at most
2 MiB via descriptor-relative rename, create directories with fixed permissions,
and unlink/rmdir only validated leaves. No user-selected root path, arbitrary
flags, chmod/chown, root service or permission-bypass exception is added. Symlink
paths, mount crossings and unsupported source files are rejected by the existing
beneath-only resource library. The prior 32 KiB WRITE interface is unchanged.
Executable bits are preserved; original ownership, ACLs and full permission modes
are not promised by Git source checkpoints.

The broker stages one 64 KiB chunk per tick, then performs one fixed operation per
tick, keeping status and Stop checks responsive. Each destination operation gets
a durable intent before mutation and acknowledgement only after directory fsync
and authority recheck. Stable retained parents define original inode authority;
a changed current parent path is rejected before acting. Whole-workspace restore
is destructive over its displayed directory entries. This is not an atomic
multi-file transaction, and concurrent changes cannot be promised preservation.
A failure or lost acknowledgement stays `unknown`, retaining known/uncertain
step states; it never automatically retries or guesses success.

After all steps, a separate read-only capture checks the complete regular-file
set, bytes and executable bits against the saved SHA-256, plus the expected
remaining directories and excluded Git entries. A successful receipt records
`postcondition_verified=true` for that captured state, while
`current_content_verified=false`, `effect_verified=false`, and
`atomic_filesystem_restore=false` prevent broader or perpetual verification claims.
Generic action verification remains zero. Cleanup touches only the job's own
unpublished private tokens; cleanup failure retains and logs private staging.
Broker recovery marks interrupted step intents unknown. SDK status/results bind
the original proposal digest and expose no automatic resubmission authority.

Local tests use temporary files and mocked native calls to check exact bytes,
mode bits, directory/file swaps, deletions, Git metadata protection, stale-before
refusal, Stop, lost acknowledgement, layout corruption and older-boot same-human
consent without reviving old grants. Actual C/kernel behavior remains a CI gate.
The installed CI probe must prove native PAM, binary/text/exec restoration, extra
file/empty-directory removal, independent final readback, replay canary, and a
freshly authorized transfer to another task UID whose old-source direct read was
denied. A Root observer freezes the broker after a partial restore; independent
native Stop must leave it unknown, prohibit remaining effects, and preserve the
partial-workspace hash across broker restart and historical replay. All earlier
RUN/PTY/MCP/READ/WRITE/feedback/package/reboot probes remain required.

Older-boot provenance is unit-tested; actual poweroff-to-restore is not claimed
by the same-boot or broker-restart witness. That integration and the full original
v2.1 phases 0–7 remain open. No model call, implicit source disclosure to a model,
Git remote operation or host credential handoff is introduced.

Linux syscall references used for descriptor-relative behavior, group inheritance
and atomic replacement of a single directory entry (not a whole restore):
https://man7.org/linux/man-pages/man2/mkdir.2.html
https://man7.org/linux/man-pages/man2/rename.2.html
https://man7.org/linux/man-pages/man2/openat2.2.html
