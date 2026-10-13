# Runnable core entry point

mano-core / python -m mano_core.cli runs one persistent broker-reconciled cycle.
It requires the managed non-root Linux task account, zero effective/permitted/
inheritable/bounding/ambient capabilities, NNP/seccomp, a root-owned service cgroup
inside mano-core.slice and exact256MiB/32task/50percentCPU limits before reading
checkpoint data or making broker requests. These are startup checks on an
OS-enforced profile, not a replacement for that profile.

The CLI accepts a bounded UTF8 JSON context/plan envelope on stdin. Unknown fields,
duplicate keys, nonfinite values and oversized packets are denied. Context includes
only task/resource/key/prompt; the explicit --mock model accepts only args/reason.
The checkpoint directory is operator-selected. No raw grants, authentication,
caller UID or host command execution is accepted from input. The normal user login
cannot run this entry point as an unrestricted core.

Current provider mode is explicitly deterministic --mock. A real provider must be
connected before real-model acceptance; the CLI never silently substitutes a mock.
The installed VM golden workflow now uses this entry point for all persistent
steps, retaining native PAM, restricted executor, proposal-bound journal status,
file predicate and replay tests. Its current-head CI evidence is required.
Prompt routing/task creation, installed long-lived service management, real provider
and broader workflow integration remain required for the full original version.
