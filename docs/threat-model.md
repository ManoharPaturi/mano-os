# Threat model and current proof limits

## Assets and adversary

Protect real user files/input/desktop, broker policy/grants/secrets/journal,
physical devices, host startup paths, network destinations and recovery controls.
Assume the entire planner, repository, model response, coding delegate, MCP server
and GUI application can be malicious. Root compromise is outside this model.

## Lab tests implemented

The sandbox executes a positive file creation and reads the exact artifact before
negative assertions: invisible host policy/journal/home/session/control/device
paths, denied read-only system writes, no host-auth/session environment, no
inherited sentinel FD, and no outbound connection. The host policy and journal
sentinels must stay unchanged. The agent service principal cannot traverse the
separate human runtime. Systemd stops the task slice while a mock core is frozen.

These are scoped experiments on a disposable guest. A Python predicate is not a
security boundary; actual denial depends on kernel namespaces, mounts, process
credentials and cgroups. Tests must fail if the positive command never executes.

## Unproven release requirements

- Protected broker IPC authentication, revocation, grant binding and journal.
- Authentic human approval through OS authentication or independently trusted input.
- Real physical stop and user TTY recovery, including process storms.
- Restriction of privileged Wayland globals for sandboxed malicious clients.
- Sandboxed browser/GUI apps, accessibility isolation and cross-session focus tests.
- Production resource enforcement, seccomp and Landlock defense in depth.
- Root btrfs rollback, secure updates/boot, dependency signatures and 8 GB hardware.

No credentialed external request, raw hardware operation or model execution is
implemented. Do not infer safe authority from these omissions: they are explicit
future gates before capabilities can be enabled.
