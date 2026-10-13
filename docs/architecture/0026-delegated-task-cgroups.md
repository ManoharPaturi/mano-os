# Delegated task cgroup custody

The root service library operates only in the fixed mano-launcher.service cgroup.
It requires Linux, root, cgroup v2, protected root-owned ancestors and cpu/memory/
pids delegation. The manager starts alone, moves to a control child, then enables
controllers for task children. No caller-selected cgroup path or budget exists.

The initial compiled profile permits two active task groups and retains at most
64 used action IDs. IDs cannot replay after creation failure or successful close.
Each task has memory.max 128 MiB, pids.max 24, cpu.max 20000/100000 and group OOM
handling. The manager control has 64 MiB, eight processes and the same CPU quota.
The outer service fixture caps the entire hierarchy at 320 MiB/64 processes/60%.
These are initial narrow limits; broader development profiles remain later work.

Attachment accepts only the manager's own unreaped blocked root child, verified
by kernel PPid/Uid/cgroup metadata. It must occur before credential dropping and
task execution. The caller must not reap the child before attachment, preventing
PID reuse. Arbitrary PIDs and already unprivileged processes are not migrated.

Task closure writes cgroup.kill, waits at most five seconds for populated=0 and
removes only its own empty task group. This handles descendants in other sessions
without a CAP_KILL signal privilege. Manager closure removes tasks, disables its
own delegation controllers, moves itself back and removes its empty control node.
No generic user cgroup cleanup or kernel-wide PID kill is implemented.

The real disposable service fixture has only CAP_SETUID/CAP_SETGID, NNP and a
protected filesystem. It places a blocked child into the limited group, then
drops to the existing fixture worker identity and forks a detached sleeper.
The manager must kill both via the owned cgroup, survive, remove the group and
reject action reuse, concurrency overflow and arbitrary PID migration. There is
no task argv execution or installed production root launch endpoint. Actual
service/permission/delegation behavior must pass CI before acceptance.

Next: connect admitted allocated identities and held FDs to supervised launch,
one-shot action/start handshake, independent stop/revoke and crash reconciliation.
The cgroup library alone does not establish journal authority, artifact verification
or the emergency-stop path. No model-facing command endpoint is enabled here.
