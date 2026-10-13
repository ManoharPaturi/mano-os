# Protected provider service boundary

A socket-activated, per-connection mano-provider job runs under a separate locked
system account. Only the broker UID can connect to its root-created mode0600
socket; the packet receiver additionally compares kernel connection and message
credentials. Public broker and provider packet reception share the same strict
ancillary/truncation/connection-identity validator in mano_protocol.

The job has zero capabilities, NNP/seccomp, a strict read-only system, hidden user
home, private devices/tmp/network, Unix-only address families, 128 MiB memory,
eight processes, 20% CPU and 32 file descriptors. RuntimeMaxSec=35 and a one-second
stop timeout provide an outer process limit independent of Python. The job belongs
to mano-core.slice so the existing native Stop path drains it. There is no restart
or queued retry in this service.

systemd LoadCredential supplies a fixed Root-owned policy and key through private
credential files; the key never appears in an environment variable, argument,
health reply or log. The loader pins the directory and files, checks ownership,
modes/link count/size, and rejects symlinks or caller-selected credential names.
Startup checks require the managed identity, Root-owned cgroup and exact limits
before socket or credential access. These checks supplement kernel enforcement.

This initial service exposes only broker health and reads a synthetic credential
in CI. It denies model dispatch even if policy enabled is true. PrivateNetwork and
Unix-only address families also prevent API egress. Registry model execution stays
disabled. Activating actual planning still requires authorized job association,
bounded reply custody, cost reservations, a permitted network profile and full
cancellation/live API tests; this service is not that completed integration.

Unit tests cover private file hazards, peer denial before key access, no key in
replies, disabled dispatch and profile-first startup. The disposable VM requires
actual socket activation and systemd credentials, kernel denial for untrusted
accounts and the Root credential source, a frozen job terminated by systemd with
timeout/SIGKILL at its bound, and native Stop draining a frozen provider together
with frozen core and detached child while broker/launcher remain frozen. No actual
API key, model request or physical stop input is used. Final-head CI must establish
these installed-service claims before acceptance.

[Official systemd credential design](https://systemd.io/CREDENTIALS/) documents
LoadCredential and service-private credential delivery. Units target Debian's
systemd v257 and are verified in that guest, not installed on the development Mac.
