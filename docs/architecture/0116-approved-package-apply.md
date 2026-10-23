# Approved package apply integration (draft; interruption validation pending)

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
only the fixed dpkg ownership/identity capability subset. The child checks kernel
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
reversed. Losing the controller reply during Stop is covered by that scenario;
independent reply loss without Stop remains a separate requirement. New fixtures
require their own successful native CI and artifact inspection before acceptance.

Stop during actual work, restart/lost-ack behavior, packaged apply lifecycle,
broader compatibility/adversarial cases, and final independent fresh artifact/UI
acceptance remain required before merge. This draft is not product or
release completion. The original v2.1 phases and deferred physical gates remain.

Primary API references:
- https://apt-team.pages.debian.net/python-apt/library/apt_pkg.html#apt_pkg.PackageManager
- https://manpages.debian.org/trixie/bubblewrap/bwrap.1.en.html
