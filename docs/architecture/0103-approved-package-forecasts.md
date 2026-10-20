# 0103: Signed-input, separately approved package forecasts

`packages.plan_install` takes only sorted unique Debian package names (1–8) and
an exact current catalog ID. It takes no argv, source URL, package path, version
selector, environment or install option. A native PAM grant binds that request
to its existing task/resource/caller/boot/epoch and budgets. Auto and Full profiles
cannot issue it. The protected approval view says that this authorizes a forecast
only, with no installation, network or maintainer scripts.

An explicit Root-only `mano-package-catalog` command creates an offline snapshot.
It downloads or installs nothing. Its initial policy is Debian13/amd64 main from
the official trixie, trixie-updates and trixie-security indexes. It checks gpgv
signatures against the Debian archive keyring, signed identity and validity dates,
and the decompressed Packages SHA256/length from each signed Release. Caller APT
configuration, mirrors, credentials and hooks are not inputs. Root-owned versioned
catalogs retain compressed indexes, signed metadata, status, extended state and
keyring with bounded hashes and a canonical manifest ID. Four retained catalogs,
128MiB input aggregate and 1GiB staging free-space floor bound disk use. Refresh
uses a fixed lock, immutable version directories and atomic active publication;
there is no automatic deletion. Catalog lifetime is at most one hour or earlier
signed expiry. Changed dpkg status/journal, index identity or trust key invalidates
new approvals/dispatch. The operator must refresh deliberately.

The existing launcher/cgroup/deadline/independent Stop lifecycle executes a fixed
installed Python-APT solver as the allocated task UID. Its normal network-off
sandbox receives only the selected read-only catalog and the fixed solver file;
workspace and cwd are read-only. `/etc` is empty, Python isolated mode ignores
workspace import/config attacks, and host auth/session/provider sockets and
credentials stay absent. The solver constructs a private temporary APT root,
hashes inputs before/after, resolves dependencies without update/fetch/commit,
and captures bounded exact package/version/hash/architecture changes. Forecasts
report removals, download bytes, net installed bytes and catalog-time free space.
Peak installation space is unmeasured (`null`); the host archive cache is ignored.
No quantity implies current applicability or sufficient peak space.

The broker rechecks authority/catalog after process output, validates the typed
result and binds it to the existing durable output custody before marking done.
Result/replay is historical and scoped; it never re-runs the solver automatically
or grants install authority. Failure/Stop/lost acknowledgement remains failed or
unknown. No model call/disclosure is implicit.

The typed core and private Root reconciliation return `package_plan_ready` with
a custody receipt, rather than installation or goal completion. The provider's
strict proposal contract can reference an exact catalog ID supplied explicitly
in the human prompt; it does not discover/disclose host inventory automatically.
This is serialization/contract support, not acceptance of live model execution.
The proposal follows the official [function-calling contract](https://developers.openai.com/api/docs/guides/function-calling)
and [structured-output constraints](https://developers.openai.com/api/docs/guides/structured-outputs).

This is one integration toward Phase2 environment/package support, not completion
of privileged package management. Applying a plan still needs a narrow Root
helper, fresh exact consent, independently re-resolved current inputs, sufficient
peak-space checks, before-change snapshot, guarded effects and actual recovery.
Do not turn a forecast or a signed package description into execution authority.

Validation must include actual signed catalog creation and native PAM/public SDK,
independent apt-get simulation agreement, failed unknown package, no dpkg/workspace
effect, config/import injection, stale-input refusal, kernel isolation and native
Stop with frozen broker/launcher/solver followed by restart/no replay. Stock-package
proof is repeated before/after real reboot. Local mocks alone do not accept this.
All previous security flags, package, poweroff-source recovery and raw GUI pixel
gates remain mandatory before merging the exact final head.

Primary interfaces: [Python-APT Cache](https://apt-team.pages.debian.net/python-apt/library/apt.cache.html),
[package marking](https://apt-team.pages.debian.net/python-apt/library/apt.package.html),
and [APT configuration](https://manpages.debian.org/trixie/apt/apt.conf.5.en.html).

Debian 13 compatibility: the fixed host trust input is
`/usr/share/keyrings/debian-archive-keyring.pgp`. Debian's `.gpg` name is a
symlink to that file; no symlink exception is granted to the catalog reader.
The immutable snapshot retains its internal `debian-archive-keyring.gpg` name
for APT/gpgv. See the [Debian keyring installation source](https://sources.debian.org/src/debian-archive-keyring/2025.1/Makefile/).
The first PR CI run (39442986898) failed closed at that symlink before any
package solver launched; the failed artifact is retained. Local checks after
this correction: 452 tests, 46 Linux-only skips; native acceptance is pending.

The second run (39445095664) passed keyring custody but rejected the cloud
image's mirror+file index identity. Only the two fixed Debian cloud mirror-list
filename aliases are additionally recognized; duplicate matching identities
remain an error. Signed suite/origin/hash/freshness checks still apply. Snapshot
filenames normalize to the fixed official URI, independently of the host's
mirror-list transport. Original host input identities remain in the manifest
for stale-input checks. Local checks: 453 tests, 46 Linux-only skips; guest
acceptance pending.

Run39447006196 passed keyring/signature verification and rejected the signed
security Components label. Debian security's signed Release declares
`updates/main`, while its signed SHA256 index path is
`main/binary-amd64/Packages`. The validator now requires `updates/main` for
trixie-security and `main` for the two other fixed suites. The signed index
hash path and all signature/freshness checks remain required. Primary input:
[Debian trixie-security InRelease](https://deb.debian.org/debian-security/dists/trixie-security/InRelease).
454 local tests, 46 Linux-only skips; actual guest acceptance pending.

Run39448926739 reached the worker after signed catalog creation. The existing
native Landlock policy allows read/execute beneath /usr but denies unlisted
top-level paths, so top-level solver/catalog mounts were inaccessible. Mount
the exact solver and catalog read-only at `/usr/lib/mano-os/package-solver.py`
and `/usr/lib/mano-os/package-catalog` inside the already masked implementation
directory. The normal sandbox still exposes no implementation modules. Landlock
and seccomp rules remain unchanged. Actual native mount/Stop acceptance remains
required. Unexpected non-JSON worker stderr now has a bounded CI-only diagnostic.

Run39450820576 reached the solver's cache stage. Python-APT rootdir initialization
creates `var/lib/apt/lists/partial` even without update/fetch; symlinking the
whole lists directory to the immutable catalog incorrectly denied that mkdir.
The private root now has its own lists/partial scratch and individual read-only
catalog-file symlinks. Config directories are private and created before APT
configuration/import to avoid missing host /etc warnings. No host config, mutable
signed inputs, network or nativeguard permission changes are introduced.
A regression checks scratch writes cannot alter the catalog tree. 455 local
tests pass, 46 Linux-only skips; actual guest acceptance remains pending.
Primary implementation reference: [Python-APT Cache source](https://salsa.debian.org/apt-team/python-apt/-/blob/main/apt/cache.py).

Run39452513187 passed earlier private-root initialization but Python-APT's
`dpkg_journal_dirty` property enumerated the missing private `var/lib/dpkg/updates`.
Create that empty private directory alongside the other scratch structure. The
actual host dpkg journal still must be empty at catalog creation, authorization,
dispatch and result acceptance; this does not bypass that independent check.
Local 455 tests/46 skips and static checks pass; guest acceptance pending.

Run39453988077 progressed through package-plan assertions and reached native
Stop. The probe read process State immediately after asynchronous SIGSTOP;
wait up to two seconds for kernel-confirmed T and revalidate argv/UID/executable
before inspecting mounts. Confirm both authorities stopped before invoking the
independent Stop client. This changes only the observation protocol, not the
product Stop path or guard. Add package-plans.json to the explicit host evidence
export for independent acceptance. No final native/stock/GUI acceptance yet.
