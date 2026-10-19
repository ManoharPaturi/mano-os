# Durable recorded developer test/fix workflow

The broker stores an immutable bounded workflow definition, task/resource binding,
boot, epoch and native Stop generation. Root operator registration grants no
execution rights. Up to16 definitions contain2..8 prospective WRITE/RUN steps,
ordinary expected exit codes and exact output digests, followed by a successful
test with a predeclared exact-file artifact predicate. Every effect still traverses
the existing task-UID core, broker authorization, descriptor custody and sandbox.
This first workflow mode uses explicit recorded mock plans under Supervised mode.

The stable key `developer-WORKFLOW-ID-INDEX` binds each step. The broker derives
progress afresh from original action proposals and immutable write receipts or
integrity-checked terminal captures. Checkpoint claims and core stdout cannot
advance the workflow. A known failed test advances only when its expected exit,
ordinary completion reason and both captured stream hashes match. Unknown effects,
unexpected output, Stop, another boot or lost resource authority halt progression.
A permission-mode change revokes this recorded Supervised workflow; it does not
silently broaden its final-test consent semantics.

The protected query looks up pending approval identities against the exact recorded
proposal. Before native PAM approves the final test, the Root operator declares
its expected artifact through the existing verifier. Once the final exit/output
match, a sealed artifact is captured from the actual retained resource and checked
against that original predicate. Exit0 or a write-publication receipt cannot
establish verification. Verified artifact identity is taken from the broker's
original evidence, with data hash/size checks. Reopening core checkpoints or the
operator process cannot blindly replay old effects. An already verified snapshot
is historical: later file changes do not silently rewrite or re-verify it.

`python3 -m mano_broker.developer --recorded` accepts a registration object
`{managed,request_key,workflow}` or one bounded step request `{workflow_id}`. It
uses fixed Root-only broker control and the existing isolated core lifecycle,
never a shell, caller-selected service/socket or direct app execution. New public
write planning and provider `propose_file_write` remain non-authoritative proposals;
core output exposes publication metadata as `write_published`, never goal completion.
The Root lifecycle independently reloads receipts from protected broker custody.

Recorded observations contain metadata only. No failed-command output is sent to
a provider, and no provider key or paid call is needed for this workflow. General
model-driven repair still requires explicit bounded feedback-disclosure approval;
versioned coding delegates, dependencies/MCP, Auto/Full workflow expansion, physical
input/performance and complete v2.1 release remain later acceptance gates.

Tests cover definition/key conflicts, changed or unknown outcomes, known-failure
selection, artifact-only verification, lost registry/boot/Stop/rearm and no-effect
replay. The installed VM runs actual native PAM, four distinct effect approvals,
isolated Python tests, checkpoint reopening, source correction, sealed exact-file
verification and a replay canary. Native Stop interrupts a running workflow test;
restart/rearm cannot execute its later write. These are recorded fixtures, not a
claim that a live model autonomously devised the correction.
