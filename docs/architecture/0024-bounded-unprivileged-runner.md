# Bounded sandbox command handling

The trusted unprivileged runner compiles the accepted descriptor/kernel guard
profile, passes exactly workspace/cwd FDs, clears the parent environment, uses
DEVNULL stdin and reads separate output pipes without blocking. Each stream has
a fixed 64 KiB capture limit. Deadline accepts only integer seconds 1–300. No
model-chosen environment, descriptors, mount flags or output budget is accepted.

Trusted launch code must supply a revocation observer returning a boolean. It is
checked before compilation, before launch and during execution. Timeout, output
overflow or revocation terminates the owned outer process group. Extra output is
not accumulated. Even if the task closes its pipes early, deadline/revocation
checks continue until it exits. Cleanup waits at most five seconds. A reaped PID
is never used to signal a process group after normal completion.

Bubblewrap creates a new inner session/PID namespace. Killing the outer group
must trigger its die-with-parent/PID-init cleanup, not merely close the pipes.
The real VM test requires cgroup process membership to return to its baseline
after normal, noisy, forked, pipe-closing and actively revoked commands. A before-
launch revocation must have no PID or workspace effect. This establishes the
tested lifecycle; no generic arbitrary-descendant cleanup guarantee is inferred.

The baseline is the two known live fixture controllers, not an arbitrary PID
snapshot. Post-main initially failed after a normal command, without recording
the PID difference. A subsequent diagnostic run passed, so that original failure
does not establish whether a PID was missing or added. The observer now requires
all other processes to exit before the first test as well as after each command.
A synchronized short-lived fixture child proves that a PID sampled before it
exits is not mistakenly treated as a permanent controller. The same exact PID-set
comparison, five-second cleanup deadline and actual descendant checks remain.

ProcessResult contains reason, exit code and bounded output bytes. Completed
means process exit, including nonzero exit codes. It does not mean an effect was
verified, rolled back or safely retryable. Terminated operations may have changed
workspace files; broker journal and independent verifier integration are separate.

The observer's polling is not atomic launch authorization or an independent
emergency stop. Production integration still needs a narrow trusted launch
protocol, task cgroup ownership, live broker lease/start/epoch checks, stop/revoke,
unknown-effect reconciliation and independent verification. No public broker
execution endpoint or model is connected by this change. CI remains required.
