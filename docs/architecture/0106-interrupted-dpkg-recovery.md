# 0106: Actual interrupted dpkg with controlled maintainer script

Replace the opaque dirty-journal fixture in the recovery lab with a real dpkg
transaction interrupted at a controlled maintainer-script checkpoint. This is
CI validation of existing Root recovery behavior; no production install endpoint,
Root permissions, broker capability, network path or Stop authority is added.

The disposable Debian/QEMU driver creates a tiny unsigned all-architecture fixture
.deb from test-only control/preinst/postinst files. Its preinst and postinst refuse
non-Root, missing disposable marker, non-QEMU/KVM and missing fresh runtime marker.
The payload is a fixed binary file beneath /usr/share/mano-recovery-interrupt-ci.
The postinst writes its PID then waits for a release marker the driver never creates.
These fixture files are not shipped by mano-runtime. The existing signed sl package
change is retained independently; the interrupted package itself is unsigned CI data.

Run real /usr/bin/dpkg --install in a new process group with a status FD. Observe
its exact executable/argv, direct postinst child, Root UID, process group and unpacked
payload. Pin dpkg/postinst with pidfds, stop both and require kernel T. While they
still hold package-manager locks, Root recovery preparation must refuse. Then
SIGKILL only this fresh known process group and require dpkg return -SIGKILL.
Require its real status stream and persisted update journal to show this fixture
half-configured. Never synthesize/edit the journal or invoke dpkg repair. Capture
bounded regular single-link Root journal-entry hashes/sizes and payload/package SHA.

The earlier clean read-only snapshot must still prepare a clone once locks are
released. Snapshot creation with the dirty live journal must refuse. The separate
actual poweroff/recovery boot must have the exact before-state dpkg database,
empty updates, absent signed sl and absent interrupted-fixture payload. The old
source root retains its changed status, both payloads and exact real journal-entry
inventory. All previous native approval/Stop/package/stock/source restore and six
fresh raw GUI gates remain required before merging the exact final head.

Witness actual_dpkg_interruption=true and dirty_live_journal_fixture=false mean
real dpkg/maintainer lifecycle interruption with controlled unsigned fixture code.
They do not mean a real production package's maintainer scripts, arbitrary kill
points, agent-driven apply, production Stop during privileged effects, firmware/
physical recovery or complete package management are accepted. Witness explicitly
records product_stop_invoked=false and unsigned_ci_package=true. Product-gated
Root apply and its interruption/reconciliation matrix remain required work.

Local467tests/46Linux-onlyskips and Ruff/compile/shell/diff pass. The new interruption
is Linux disposable-CI only and has not yet passed native final-head evidence.
Primary behavior: [Debian dpkg state/journal recovery FAQ](https://wiki.debian.org/Teams/Dpkg/FAQ),
[dpkg package states](https://manpages.debian.org/trixie/dpkg/dpkg.1.en.html).
