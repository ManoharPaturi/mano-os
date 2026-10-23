# Approved package apply integration (draft; native validation pending)

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
mano-package.slice before any effect. The Broker remains the trusted grant
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
only the fixed dpkg ownership/identity capability subset. The child checks kernel
read-only mount flags for installed runtime infrastructure before APT runs. A native
fixed-command seccomp guard denies namespace escape, mount, ptrace, keyring,
network, kernel/device administration and related operations. Package scripts
cannot supply a different guard command or public argv. Namespace preflight must
prove the expected restrictions before APT commits; the Root parent validates
that witness and requires all package descendants to drain before completion.
Payload contents and arbitrary maintainer-script semantics are not inferred from
package database postconditions. Compatibility and adversarial tests are pending.

The existing database verifier checks exact before/after transitions and preserves
write-once history. The Root helper refreshes the package catalog before returning
a credential-authenticated receipt; a missing/invalid reply, lost Broker, revoked
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

Validation at this draft: local protocol/authorization/failure/operator tests and
static checks pass. Native C compilation, actual APT API behavior, successful
Broker/native-PAM-to-Root execution on btrfs, package namespace probes, Stop during
actual work, restart/lost-ack behavior, packaged lifecycle, and independent fresh
artifact/UI acceptance are required before merge. This draft is not product or
release completion. The original v2.1 phases and deferred physical gates remain.

Primary API references:
- https://apt-team.pages.debian.net/python-apt/library/apt_pkg.html#apt_pkg.PackageManager
- https://manpages.debian.org/trixie/bubblewrap/bwrap.1.en.html
