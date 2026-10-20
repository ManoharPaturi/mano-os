# 0099: Bounded, approved Git source workspace checkpoints

`workspace.checkpoint` separately approves the complete source root and explicit
excluded names `.git` and `.mano-write-staging`. Permission profiles never mint
this grant automatically. A checkpoint preserves regular-file bytes and their
executable bit. Existing repository metadata, hooks, config, attributes/filters,
remotes, index and history are not imported as authority. Attributes remain raw
source blobs. The broker never executes Git to capture a workspace.

The resource registry pins the exact workspace root using the existing beneath-
only native library. Capture walks bounded directory FDs without symlink or mount
traversal, seals each regular single-link inode and rechecks identities after
reading the tree. Links, special files, changed/replaced entries and exhausted
limits fail without publishing a checkpoint. Stop/grant/epoch/boot/deadline are
checked while walking and before the SQLite transaction. Individual file reads
are stable; a multi-file point-in-time filesystem snapshot is not claimed.
Empty directories, permissions beyond the executable bit, ACLs and Git metadata
are outside this source checkpoint, as in Git source trees.

Fixed ceilings are 64 files, 16 directories including root, 128 visited entries,
12 path levels, 512 UTF-8 path bytes, 2 MiB raw source, 4 MiB exported archive,
five seconds capture time and eight lifetime retained checkpoints. The FD limits
fit the broker's existing 128-descriptor ceiling. The private SQLite table stores
one deterministic bare Git repository archive per completed action, with a 32 MiB
maximum retained payload. Capture requires 64 MiB free plus three archive budgets
for data/journal staging. Exhaustion denies new capture; it never deletes saved
user work or silently evicts a checkpoint. Broader operator retention management
remains future work.

Blob/tree/commit objects are encoded directly using Git's documented format,
with deterministic synthetic author and commit data. No existing Git commands,
filters or hooks run during encoding. SHA-1 is only the interoperable Git object
identifier; SHA-256 binds the complete archive as the custody/integrity boundary.
An object-ID collision within a checkpoint fails rather than overwriting bytes.
The exported bare repository contains only fixed config/HEAD/ref and generated
loose objects; file names live in Git trees, not archive member paths.

The public SDK binds status to the original proposal digest. Scoped metadata and
16 KiB chunks require the original caller/task/action/current boot and completed
capture. It checks receipt identity, byte count, EOF and final SHA-256. Source
bytes never enter model context automatically. Historical result retrieval and
idempotent proposal replay return original custody; lost/unknown operations never
recapture the possibly changed workspace automatically. Capture/outcome are atomic
in the journal. Stop during capture leaves no published checkpoint.

Validation includes native Git `fsck --strict --full`, tree/blob inspection and
exact original byte/mode recovery after workspace mutation. Installed CI tests use
native PAM and the public SDK, keep malicious workspace config/hooks/attributes
unchanged and unexecuted, reject symlink escape, test caller/task scope/replay and
prove native Stop revokes an unexpired pending checkpoint approval even while a
Full profile is active. Git reference commands run as the unprivileged Task UID
against the generated repository with a fixed empty environment/config, never
as Root or against workspace-selected metadata.

This is source checkpoint capture/export/inspection. In-place restoration with
separate destructive-effect approval, deletion reconciliation and independently
verified postconditions remains a subsequent integration. It does not roll back
emails, remote pushes, package operations, credentials or other external effects.
The original Phase 2 and full phases 0–7 goal remain incomplete.

Primary Git object documentation:
https://git-scm.com/book/en/v2/Git-Internals-Git-Objects
https://git-scm.com/docs/git-fsck
