# Independent Root package calculation inside coherent locks

Status: prerequisite for privileged package apply, no new execution authority.

The broker's durable forecast and its installation-review hash are observations.
Root must calculate the transaction again from current trusted inputs before
accepting a later, separately approved package change. A hash alone cannot prove
that the selected versions or dependency changes are currently applicable.

`mano_runtime.package_resolution.current_plan` is a Linux Root-only context. It
requires the supported recovery-capable btrfs layout, validates the full bounded
forecast schema, observes armed native Stop, and takes the existing coherent
package-manager locks. It validates current Root-owned catalog/status/index/keyring
custody, runs a fresh solver process, then validates custody and Stop generation
again. It yields only if the complete calculated forecast exactly matches the
supplied forecast. No changed candidate, archive hash, removal or byte delta is
silently substituted. Locks remain held until the context exits.

Independent means a new Root-controlled process/cache and fresh current-state
observations, separate from the earlier unprivileged task's stored result. The
read-only APT calculation implementation is shared; this is not an independent
solver algorithm. The normal task CLI still refuses Root and still uses its fixed
catalog mount and sandbox. A private calculation function accepts the trusted
catalog path selected by Root custody. Neither path calls update, fetch or commit.

The Root worker uses the fixed system interpreter/module, a checked Root-owned
source prefix, fixed working directory and explicit environment. Ambient APT_CONFIG,
proxy, workspace Python import and hook configuration are not inherited. APT gets
an empty private configuration tree and the pinned signed catalog files. Output
is bounded and redacted on failure. Root eligibility and typed request validation
are repeated in the worker. No listening socket or setuid program is introduced.

CI checks actual dependency and installed/no-change forecasts, a valid but altered
byte-delta forecast, a stale active catalog and corrupt catalog input. While the
context is held, another actual process must fail to acquire the dpkg lock. A
hostile ambient APT_CONFIG requests the wrong architecture, yet the clean worker
must reproduce the exact approved forecast. After native Stop, the Root context
must refuse. Installed-runtime checks on pristine ext4 before and after real reboot
require unsupported-layout and unprivileged-caller denials. Local tests cover
generation races, lock lifetime, schema mismatch, custody recheck and environment
construction; they are not native Root evidence.

The yielded receipt is not a bearer token, PAM consent or installation authority.
Its lock field describes the yielding context, not a promise that locks remain
held after it exits. Public installation review still reports Root validation
false because it does not invoke this privileged context. Full apply must integrate
fresh exact native PAM, archive verification/download authorization, truthful space
admission, same-scope checkpoint/commit, constrained execution in the native Stop
domain, postconditions and durable Stop/crash/boot outcomes. This change performs
no package effects and makes no production maintainer-script or physical claims.
The calculation child is currently a trusted Root subprocess, not a sandboxed
broker-facing service. Stop refusal/generation checks do not prove cancellation
of a frozen calculation child. Before exposing a privileged executor to broker
requests, its process custody, minimal capabilities, private IPC/filesystem view,
resource limits and membership in the native Stop domain must be enforced and
tested. Existing launcher/task sandbox permissions are unchanged.
