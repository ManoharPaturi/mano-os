# Approved package apply integration (draft; runtime protection incomplete)

packages.apply_install is distinct from the read-only packages.plan_install
capability. Its only arguments are an owned forecast action ID and exact plan
SHA256. The Broker recovers that successful durable forecast, rechecks current
catalog inputs, and binds the complete plan, system Root/maintainer-script risks,
fixed Debian acquisition sources, conffile policy and resource limits into the
existing native PAM view. Workspace profiles cannot approve this capability.
Dispatch requires a separately approved native approval record, not just a grant
created through a trusted library call. Grants remain single-use and bounded.

The asynchronous Broker worker sends one typed packet to a Root-owned private
SOCK_SEQPACKET listener. The per-connection service authenticates both connection
and message credentials as the separate Broker identity, pins its PID, validates
boot/deadline/native Stop generation and request/plan digests, and starts inside
mano-package.slice before any effect. The trusted controller has SYS_ADMIN for
namespace/snapshot setup and NET_ADMIN for loopback configuration in the new
private network namespace. SETPCAP is available only for the fixed native guard
to remove bounding capabilities and lock securebits. The guard accepts only the
bounded controller set, disables and locks UID-0 privilege restoration, drops all
setup capabilities from the bounding set, and explicitly sets permitted, effective,
inheritable and ambient sets to the six dpkg capabilities before fixed Python.
The Python boundary witness independently reads all five kernel capability sets
and securebits after exec. Each set must equal 0xdb and securebits must equal43.
Unexpected initial privileges or failed transitions refuse execution. The
controller explicitly preserves SETUID through ambient inheritance so its fixed
exec chain retains the required identity capability; the native guard clears
that ambient state before constructing the worker policy. The Broker remains the trusted grant
issuer; the Root helper does not invent a parallel approval policy or PAM issuer.

Acquisition re-resolves the current complete plan under package locks, derives
locations from the Root-owned signed catalog in a fixed worker, accepts only
fixed official Debian HTTPS pool URLs without credentials, proxies or redirects,
and bounds exact lengths/SHA256, scan totals and staging inventory. Existing
archives must pass the same sealed custody checks. Partial staging remains for
operator inspection. This is explicit acquisition authorized by the apply view,
not a silent read-only forecast download. It is not a paid/provider operation.
A conservative free-space reserve is admission policy, not a measured peak-space
guarantee. ENOSPC or other uncertain failures cannot imply completion or replay.

Before a snapshot or acquisition, unresolved attempt history blocks effects.
The Root helper then uses the coherent lock/checkpoint/intent sequence, hands
the backend lock to a constrained child, and regains it before postconditions.
APT's PackageManager orders the full dependency solution, installs/upgrades/
removes/configures it and writes package marks. The child rechecks that its full
solution equals the approved forecast before effects. It has only sealed archives,
private PID/network/IPC/mount/cgroup namespaces, a read-only root with fixed writable
mount ancestors, masked human data/credentials/approval IPC, protected mano code
and policy, including bundled runtime dependencies and shared session files, and
only the fixed dpkg ownership/identity capability subset. Service configuration directories
/etc/systemd and /usr/lib/systemd are read-only as complete trees, including
future override names and global drop-ins. Protecting existing mano unit files
alone would allow new drop-ins to change trusted execution on restart. The native
preflight requires read-only filesystem flags and actual EROFS from attempts to
create fresh names in both parent and system-unit directories. Existing mano
administration wrappers in /usr/sbin are protected too. The native approval view
explicitly says service-configuration changes are not allowed. Packages requiring
those writes need a separately mediated service-management path; this helper
must not silently relax the protected trees for compatibility. That broader
capability and its compatibility evidence remain part of the unfinished project. The child checks kernel
read-only mount flags for installed runtime infrastructure before APT runs. A native
fixed-command seccomp guard denies namespace escape, mount, ptrace, keyring,
network, kernel/device administration and related operations. clone3 is denied
with ENOSYS so libc can fall back to legacy clone; all legacy namespace-creation
flags remain denied. A real bounded thread must start and join in the boundary
preflight before APT executes. Memory and PID limits remain unchanged. Package scripts
cannot supply a different guard command or public argv. Namespace preflight must
prove the expected restrictions before APT commits; the Root parent validates
that witness and requires all package descendants to drain before completion.
Payload contents and arbitrary maintainer-script semantics are not inferred from
package database postconditions. Compatibility and adversarial tests are pending.

The existing database verifier checks exact before/after transitions and preserves
write-once history. The Root helper refreshes the package catalog before returning
a credential-authenticated receipt. Worker streams are bounded to 1MiB total
and retained separately in Root-only operator custody outside restored roots
(directory0700, files0600, exclusive creation, at most32 attempt directories).
They are untrusted diagnostic data, never SDK results or authority records.
The Broker journal receives only structured fixed diagnostics; disposable CI may
export logs of its own controlled test attempt. A missing/invalid reply, lost Broker, revoked
or expired authority, Stop, worker failure or uncertain outcome never retries.
The public SDK exposes scoped status/result queries, not Root paths or raw logs.
Legacy installation review objects remain read-only and cannot apply themselves;
the separate apply capability always needs its own fresh native approval.

Operator recovery is an explicit foreground Root-terminal operation:

- acknowledge-attempt ATTEMPT CHECKPOINT requires a clean current database matching
  a verified read-only checkpoint and the exact typed acknowledgement. It preserves
  the original unknown record and records the operator decision separately. It
  does not assert that every payload/external effect was reversed or permit replay.
- retire-checkpoint CHECKPOINT requires its own exact typed confirmation. It
  archives active metadata without deleting the snapshot or losing explicit
  recoverability. The existing active-record and total Snapper limits remain.

These operations grant no model or Broker recovery override. Partial/corrupt
history still fails closed; every attempt ID remains reserved.

Validation at head bd7aa20: exact-head CI39991219242 passed quality, security-lab
and merge-gate. The disposable Debian VM completed a public-SDK/native-PAM-to-Root
cowsay install on btrfs. Independent archive inspection checked the full package
database transition, request/plan/acquisition binding, native boundary, 54 artifact
hashes and 45 regression flags. Six fresh GUI originals were viewed; one pending
numeric field clips its final digit. These are headless CI observations.

The next fixture compares installed cowsay bytes/mode/ownership against the exact
signed archive and exports both for independent inspection. A separate guarded
CI-only fixture observes and freezes actual UID0 dpkg plus the package controller,
Broker and launcher, invokes native Stop, verifies package pidfd death/domain
drainage, and checks unknown persistence after Broker restart and replay denial.
It includes explicit CI-administrator dpkg install/purge of only the same signed
sl fixture, then typed Root-terminal acknowledgement preserving unknown history.
This repair is not a product automatic repair or evidence that all effects were
reversed. A second fixture runs after installation of the built runtime package,
using only installed SDK modules, normal human terminal/PAM approval (including
cancellation before password), and the packaged Root apply service on btrfs. It
installs the signed sl plan, preserves raw before/after database evidence, and
retires checkpoint metadata explicitly without deleting snapshots. This exercises
installed apply before the existing runtime reinstall/removal lifecycle checks;
it does not prove a fresh-image btrfs installation or physical input provenance. Losing the controller reply during Stop is covered by that scenario;
a separate second fixture kills the pinned frozen Broker while the Root package
controller and dpkg remain frozen. It requires Root-domain drainage through the
production service dependency without pressing Stop, followed by restarted
unknown/no-replay checks. This covers caller death before a reply; losing a reply
after successful commit remains a separate requirement. New fixtures
require their own successful native CI and artifact inspection before acceptance.

Stop during actual work, restart/lost-ack behavior, packaged apply lifecycle,
broader compatibility/adversarial cases, and final independent fresh artifact/UI
acceptance remain required before merge. This draft is not product or
release completion. The original v2.1 phases and deferred physical gates remain.

Primary API references:
- https://apt-team.pages.debian.net/python-apt/library/apt_pkg.html#apt_pkg.PackageManager
- https://manpages.debian.org/trixie/bubblewrap/bwrap.1.en.html


The first interruption fixture run (CI39997472282, head1f81e0c) stopped before
applying because its single-package assumption was wrong: the signed sl solution
also installs libncurses6. The fixture now uses that complete plan, seals/checks
all archives, and its explicit CI-administrator recovery installs then purges only
the fresh approved fixture packages. Every database package/version/state must
match the original afterward; all-effects reversal is still not asserted.
It refreshes the catalog explicitly after manual repair before the next scenario.
The installed-runtime fixture and independent verifier also inspect the complete
solution instead of assuming the requested program is its only change. The signed
cowsay payload comparison from that failed run was independently verified; that
partial success does not make the failed run or draft merge eligible.


CI40000069898 at f4ac43e reached native systemd read-only preflight and the
approved cowsay install. Its Stop fixture reached explicit repair/database checks,
then failed when creating the clean recovery checkpoint without a controlling
terminal. The fixture now uses the same genuine Root-TTY harness as other operator
commands; the production terminal guard is unchanged. Partial Stop progress is
exported before administrator repair so later fixture failures retain its earlier
observations without claiming that recovery finished.

A CI-only diagnostic inventories actual mapped system-file paths, inode/device,
ownership/mode and SHA256 of the constrained controller. The outside privileged
CI observer separately inventories itself and PID1; production service capabilities
are not widened for diagnostics. It reads neither process memory nor credentials.
This is an incomplete dependency inventory, not proof that all Python imports,
future subprocess dependencies, loader search paths or trusted files are protected.
The shared system interpreter/library/helper protection finding remains unresolved.


The first mapped-file inventory failed in CI40002396890 before package execution:
it incorrectly equated /proc/maps device numbers with stat(). Linux proc maps
prints inode superblock s_dev, whereas Btrfs getattr uses the subvolume anon_dev.
The corrected diagnostic opens each kernel map_files handle and checks that
handle's fstat identity against the named file and mapped inode before hashing.
It retains both reported device numbers without falsely requiring equality.
It also rechecks the descriptor for repeated mappings/roles, not merely the name.
No extra production capabilities are granted; inability to open the required
mapped handle remains an error. Ordinary unprivileged tests reject another inode
with identical bytes, changed metadata and a different mapped inode. These do
not substitute for the pending actual Btrfs/kernel run.

Primary sources:
- https://code.googlesource.com/linux/torvalds/linux/+/8abc1c8badc11c859bb4ba43211611347e59c55c/fs/proc/task_mmu.c
- https://code.googlesource.com/linux/torvalds/linux/+/acda701bf1e8233f982164c8ddbedc055427212d/fs/btrfs/inode.c
- https://man7.org/linux/man-pages/man5/proc_pid_map_files.5.html


CI40004535234 next exposed a naming difference before package work: /proc/maps
prints padded addresses such as 00400000-00420000, but kernel map_files lookup
rejects leading zeroes. The collector now parses bounded, increasing 64-bit hex
ranges and formats canonical unpadded names before opening the mapped handle.
The exact failing range and malformed/path-like inputs are regression-tested;
missing mappings or identity mismatches still fail rather than falling back.
Kernel lookup source: https://github.com/torvalds/linux/blob/master/fs/proc/base.c


The first completed Stop and independent Broker-death witnesses were retained by
CI40010080992 and independently inspected. Both observed real dpkg, drained the
package domain, preserved unknown/replay denial after restart, and completed
explicit operator acknowledgement. The overall run later failed when packaged
apply tried to refresh into an already full four-catalog store.

The test administrator now restores the original APT marks under coherent locks,
using an exclusive staged file, fsync and atomic publication, in addition to
restoring the fixture package versions/states. The fixture reuses a current
catalog only after its full existing validation succeeds; stale status/marks
still require explicit refresh. It deletes no catalog or journal history and
changes no retention limit. This remains explicit CI repair, not product repair.

The Root transaction now owns the existing refresh lock and reserves a free slot
before acquisition/checkpoint/package effects. It retains that lock through
postcondition catalog publication. Full retention, concurrent refresh, nested
reservations and publication without a reservation fail; Stop/death releases the
kernel-owned lock. The four-catalog ceiling remains unchanged. This prevents a
known-full store from allowing installation then failing only at final refresh.
Temporary-file tests verify actual lock exclusion/CLOEXEC/exception release and
refusal before acquisition; native lifecycle acceptance is still required.


The next CI-only scenario targets loss after database commit rather than during
unpack. It observes a real durable verified.json, freezes the authenticated Root
controller/Broker/launcher before catalog publication, checks via read-only SQLite
that the Broker is still executing with no recorded acknowledgement, then kills
only the pinned Broker. It requires service-bound Root drainage without Stop,
Broker unknown after restart, preserved Root completion history and replay denial.
Raw before/after package databases are exported for independent plan comparison.

The fixture explicitly repairs its own signed sl/libncurses6 installation/marks
and retires only checkpoint metadata afterward. The saved Root completion record
is then historical; it does not assert that the installation is still present or
all payload effects were reversed. It uses no production pause hook, journal
editing, extra service capability or automatic retry. This fixture is prepared
locally and still requires exact-head native validation before any claim.


Existing Debian Python path protection now binds the mandatory interpreter
/usr/bin/python3.13, /usr/lib/python3.13, /usr/lib/python3 and /usr/local read-only,
as well as existing /etc/python3 and /etc/python3.13 directories. Mount anchors
prevent substitution of the directories above these binds. Missing required paths
refuse namespace construction. Before package effects, the constrained worker
requires read-only filesystem flags and EROFS from interpreter write-open and
fresh directory creation in every protected module tree. The authenticated Root
parent requires the new exact boundary flag. Upgrading these protected runtime
paths requires a separately mediated runtime update; package scripts cannot relax
these mounts. Native compatibility evidence for this change is pending.

This protects existing paths, not a complete trusted execution closure. Missing
Python zip search entries, shared ELF dependencies, dynamic loader configuration
and helper dependencies still need protection and adversarial validation. The
successful-commit reply-loss fixture has separately passed CI40057602757 and
independent full database/record inspection; explicit administrator repair does
not turn its preserved completion record into current installation verification.
PR134 remains draft until the remaining runtime/compatibility gates pass.
