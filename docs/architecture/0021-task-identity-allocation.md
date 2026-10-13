# Distinct task identities

The root administrative allocator accepts no caller-supplied names, UID/GID,
shell, home, password or useradd flags. It mints a random mano-task name and
uses fixed useradd options for a unique primary group, locked password,
non-login shell and absent home. The only supplementary group is mano-request,
which grants connection access to the public request socket, not another task's
workspace or private broker channels. UID and primary GID separation is checked
against the live account database after allocation.

A root-owned private non-symlink lock serializes allocation. Contention fails
closed without waiting indefinitely. Allocation refuses after 64 mano-task
accounts, including retained or partially created accounts. It never deletes
accounts or recycles IDs: safe retirement requires a separate proof that all
task processes, descriptors, cgroups and grants are gone. Failed policy checks
retain the created account and surface an error. This intentionally trades
bounded capacity for avoiding premature authority reuse.

The disposable VM fixture now uses two actual allocated identities for its
workspace tests. It checks separate UID/GID, locked password status without
reading password hashes, nologin/no home, exact supplementary group membership,
real flock contention with no new account, and cross-task kernel denials.
The fixture deletes only its own accounts after child commands finish and all
workspace descriptors close. Runtime teardown and quota exhaustion recovery
are not established by fixture cleanup. No host install or model execution.

This remains a root operator Python API, not a setuid command or root execution
endpoint. Next work must launch the approved operation inside a task sandbox,
using fixed filesystem profiles, minimal environment/FDs, cgroup limits,
seccomp/Landlock and live stop/revoke authority before Phase 1 completion.
