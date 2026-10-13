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

ProcessResult contains reason, exit code and bounded output bytes. Completed
means process exit, including nonzero exit codes. It does not mean an effect was
verified, rolled back or safely retryable. Terminated operations may have changed
workspace files; broker journal and independent verifier integration are separate.

The observer's polling is not atomic launch authorization or an independent
emergency stop. Production integration still needs a narrow trusted launch
protocol, task cgroup ownership, live broker lease/start/epoch checks, stop/revoke,
unknown-effect reconciliation and independent verification. No public broker
execution endpoint or model is connected by this change. CI remains required.
