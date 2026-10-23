# Package attempt custody across interruption and recovery boot

Status: prerequisite for the Phase 5 privileged package executor, not execution authority.

A lost acknowledgement cannot establish whether dpkg or a maintainer script ran.
Repeating that action can repeat external effects. Record a write-ahead intent
outside the root subvolume before starting any package effect, and preserve an
uncertain outcome for explicit operator recovery.

`mano_runtime.package_attempts` uses the fixed private
`/.snapshots/.mano-package-recovery/attempts` directory on the separately mounted
snapshot subvolume. Linux Root custody, the existing supported btrfs layout and
coherent package-manager locks are required. A fresh current-boot checkpoint must
match the current root layout and package database; its subvolume identity,
read-only property and saved package database are rechecked before reservation.
An exclusive attempt directory, immutable intent and directory/file fsyncs reserve
an ID even if a write fails or the caller loses the reply. No incomplete intent is
silently repaired. No existing attempt is removed, overwritten or reused.

Reconciliation appends only an `unknown` observation. It never starts a command,
repairs dpkg, selects a boot target or retries an effect. Unknown attempts block
new attempt IDs as well, preventing a caller from repeating the same action under
a new name. This first state machine deliberately has no success transition or
operator-clear API; those require the future executor's verified postconditions
and explicit recovery policy. Retention is bounded and requires operator review.
Corrupt, partial, foreign or overshared custody blocks processing.

Package-manager POSIX locks are process-wide. A second context opening and
closing the same file could release an outer context's lock. Reject nested or
concurrent in-process lock scopes before opening any additional descriptors.

The disposable Root CI driver records an intent before the existing controlled
package changes, rejects duplicate reservation, interrupts actual dpkg/postinst,
then records an unknown outcome without retry. It proves a denied nested scope
leaves the outer lock held against another process. After a real boot into the
clean recovery clone, the same intent/outcome must remain in persistent storage,
with its original boot identity and no replacement acknowledgement. Existing
source dpkg journal and payload preservation checks remain required.

Local tests cover state/format and failed-write behavior with mocked Root/layout
boundaries; they are not Root custody or power-loss proofs. CI's request digest
describes the controlled fixture and is explicitly not native PAM approval.
This module has no public endpoint, CLI, service or package grant. Actual broker
apply still needs exact fresh native PAM consent, independent current resolution,
verified archive acquisition, honest space admission, same-scope checkpoint and
commit, constrained execution in the native Stop domain, postcondition checks,
and service/Stop/crash reconciliation. No production maintainer-script, physical
input, arbitrary power-loss point or full privileged-apply acceptance is claimed.
