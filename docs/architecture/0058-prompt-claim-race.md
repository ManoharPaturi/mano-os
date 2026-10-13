# Preserve the winning prompt creator

Atomic prompt claim permits one creator. Previously, a losing factory invocation
caught the denied claim and unconditionally requested an uncertain transition.
If the winner was still creating its task, the loser could change that state to
unknown and prevent the winner's attachment. No duplicate task was authorized,
but a legitimate creator could be interrupted.

The factory now marks uncertainty only after receiving a successful claim for its
exact prompt ID. A rejected or lost claim creates nothing and changes no prompt
state. A claim committed with a lost acknowledgement remains creating until
operator reconciliation or broker recovery marks it unknown; no automatic
reallocation is introduced. Later provisioning failures after an acknowledged
claim retain the existing uncertain-state cleanup.

A regression test uses the actual SQLite journal and protected dispatcher. It
injects the second factory call during the winning allocation, requires the loser
to be denied without changing creating_task, and verifies that one allocation
can attach and persist the original context. This tests the protocol interleaving;
the allocator is mocked and is not a physical concurrency/performance claim.
