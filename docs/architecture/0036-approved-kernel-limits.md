# Approved task resource ceilings

The broker derives private launch limits from the durable grant budget, clamped
to the existing launcher maximum of 128 MiB, 24 processes and 20 percent CPU.
Smaller approved budgets now become smaller kernel limits. The public action
schema does not accept these fields; the private authenticated broker envelope
carries the validated three-integer limits. Unknown keys, booleans, zero/negative
values and values above launcher ceilings are rejected before execution.

LaunchAdmission carries the frozen typed limits into Child and Manager.create.
The root manager writes memory.max, pids.max and cpu.max in the fresh owned task
cgroup before attaching the blocked child. It reads each value back and rejects
memory above budget, mismatched PID limits or CPU quota/period above budget.
Kernel page rounding may lower a tiny memory budget; it must never increase it.
Existing memory.oom.group, action reuse, concurrent quota and teardown remain.
Legacy private operator fixtures that omit limits retain the original ceilings;
production Executor always supplies grant-derived limits. There is no model limit
or cgroup path override.

Portable tests cover grant/ceiling clamping including tiny budgets and reject
malformed private limits. The actual delegated-service VM probe checks a lower
64 MiB/16-process/10-percent group and executes journaled terminal work with that
lower grant over the real private transport. Enforcement remains pending CI.
This change does not add native independent Stop, artifact verification, physical
performance results or completed golden tasks.
