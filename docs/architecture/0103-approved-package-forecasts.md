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
