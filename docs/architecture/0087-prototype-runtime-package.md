# Debian13 amd64 prototype runtime package

The runtime must install without the lab's manually copied modules and private
core virtualenv. Build mano-runtime0.1.0~prototype1 for Debian13/CPython3.13/amd64,
with the Python modules, five native adapters, hardened systemd units, fixed PAM
policy, human Sway session, Root administration wrappers and default-disabled
provider/pricing/controller/egress configuration. No API key or human UID is shipped.
It is an unsigned prototype, not the complete original runtime MVP/release gate.

Core execution uses system Python with a package-owned /usr/lib/mano-runtime/vendor
path. The41 dependency versions match accepted PR102's actual Debian evidence;
binary wheel hashes come from their exact PyPI release metadata. Builds use an
already-downloaded hash-checked wheelhouse with no index or dependency resolution.
No source builds or runtime pip bootstrap occur during package installation.
Dependency CLI scripts and build-local direct URLs are excluded; RECORD files,
timestamps and tar ownership are normalized. Source revision/epoch and a payload
hash manifest are shipped. Repeated-build verification is scoped to the same guest
source/wheels/toolchain with separate staging directories, not a hermetic compiler
or independently signed source-provenance claim.

First install refuses existing manual runtime files rather than overwriting them.
Postinst preflights existing service identities/groups, uses fixed sysusers definitions
for locked non-login private identities, validates them and creates only fixed
private directories. It reloads systemd without starting or enabling the runtime.
Root package code runs with a fixed Python path, safe-path mode and cleared ambient
environment. Unsafe account collisions fail without repurposing existing accounts.

The explicit Root-terminal mano-runtime-setup HUMAN enrolls an existing login
identity. It creates a private durable UID policy or requires an identical safe
existing file; it never silently rebinds it. It appends only the fixed human group.
--start starts the fixed runtime target now; --enable explicitly enables that target
for later boots and starts it. The controller timer stays separate and disabled.
A new optional Wayland session entry does not replace the user's default session.
Group membership requires a fresh login. Physical onboarding is not proved in CI.

Before reinstall/upgrade/removal, stop the controller timer and, when active, request
native Stop under the configured human identity. Then stop the fixed services and
core slice. Removal disables the runtime target; reinstall retains explicit enable
state. Credentials, human policy, workspaces and journal data are retained. Existing
Root configuration remains authoritative; package lifecycle never grants rearm.

The actual guest witness builds twice and compares bytes, moves the old lab core
and vendor paths aside, installs with dpkg, verifies all installed payload hashes and
ownership, disabled defaults, no key and inactive services/sockets. It exercises Root
TTY enrollment, pipe/conflicting-human denial, explicit target enable, installed GUI
submission/profile/PAM, and an actual LangGraph mock-plan workspace effect through
package-owned wrappers. Effect_verified remains false. Same-version reinstall must
preserve edited conffile bytes, UID policy, task data and explicit enable state while
old profile authority remains unavailable and Stop stays latched. Removal must stop
services, remove code, disable the target and retain policy/data. Physical input,
paid provider execution, broader workflows and full release acceptance remain open.
