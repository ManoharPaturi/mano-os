# ADR 0001: keep production execution disabled until Phase 0 proof

Status: accepted for development; compositor architecture remains unapproved.

The supplied v2.1 README explicitly orders feasibility/security before runtime.
The current host is an ARM Mac with low spare disk capacity, not Debian hardware.
Run real Linux probes in a disposable remote QEMU guest instead of weakening
sandbox boundaries or downloading local multi-gigabyte VM images.

The lab profile is not a production broker: it has no grants, authoritative
journal, seccomp/Landlock stack, resource-authorized execution API or model route.
The lab uses separate task identities, no inherited host sockets and no network.
Its workspace resolver rejects symlinks but is not race-proof; a production
broker must pin resources with file descriptors and broker-owned mount topology.

The cloud image currently has ext4 root. A btrfs data-volume experiment does not
prove root rollback. A root-installed prompt, approval authentication, restricted
Wayland globals and real physical stop/input provenance remain mandatory.
Systemd cgroup stop is a verified primitive only after its VM probe succeeds.

No phase promotion or unrestricted delegate execution occurs until all Phase 0
proofs pass. Root privileges in setup are confined to the throwaway guest and do
not represent agent authority. Do not install the guest script on a real host.
