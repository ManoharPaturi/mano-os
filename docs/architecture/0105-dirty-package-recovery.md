# 0105: Clean saved authority when the live package journal is dirty

PR120's explicit Root-only recovery helper required the live dpkg journal to be
clean before preparing a recovery clone. That prevented recovery preparation
from a previously verified clean snapshot when a failed change left a dirty
live journal. Preparation writes only a fresh fixed clone, so it must distinguish
source authority from the current state being recovered.

Keep `create` unchanged: require a clean live dpkg journal, hold all existing
package-manager locks and validate the captured status/layout/read-only source.
For `prepare-boot`, retain Root controlling-terminal admission, locks, fixed paths,
private storage, UUID/provenance/status/hash/fstab/retention/space constraints and
no overwrite/delete/reboot/boot selection. Require the saved read-only snapshot's
dpkg updates directory to be empty. Observe whether the trusted fixed live updates
directory is nonempty; preserve it byte-for-byte and record only a dirty boolean.
Do not parse, repair, clear or otherwise modify live package state.

This is not permission to prepare from a dirty saved snapshot or while a package
manager holds the live locks. The operator still chooses a separate recovery
boot. The changed source root, its journal and the immutable source remain intact.
Other mounted filesystems and external effects are outside Root snapshot recovery.

CI extends the real signed sl-change/recovery proof with an explicit deterministic
opaque journal file after the successful package change. Snapshot creation must
refuse it; clean-source clone preparation must succeed; the recovery boot must
have the exact before-state and empty updates directory while the changed source
retains the journal's exact hash. Witnesses state dirty_live_journal_fixture=true
and actual_dpkg_interruption=false. This proves admission and preservation with
dirty state, not actual interruption of dpkg, interrupted maintainer scripts,
agent-driven apply or full package-management completion. Those remain required
future integration tests. All prior security/package/stock/source recovery and
six fresh raw GUI gates remain mandatory for the final commit.

Local 467 tests run,46 Linux-only skips, Ruff/compile/shell/diff pass. Native CI pending.
