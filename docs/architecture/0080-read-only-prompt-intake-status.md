# Human prompt intake visibility

The human GTK surface retains the acknowledged prompt and shows a fixed queue
label, selectable request ID and task ID once allocated. Check request status
uses the existing protected native human route, operation06, to read exactly that
prompt's id/state/task_id. Neither a submission nor a status refresh approves an
action or reports verified completion. Workspace ready explicitly states that
execution status is unavailable in this view.

The client rejects unknown fields/states, malformed IDs, an unexpected task ID
before task_created, missing task ID afterward and a reply for a different prompt.
Untrusted response text is never interpreted as markup or rendered as a label.
The four labels cover received, creating_task, task_created and
unknown_task_creation; uncertain creation requires operator review.

Submission and status calls use separate bounded single-inflight workers, posting
completion to the GTK UI thread. Refresh is disabled without an acknowledged
selection and while another refresh/submission runs. Each selection has a revision;
a stale slow reply cannot replace a newer selection, including the same ID selected
again. A status failure preserves the last acknowledged state and never resubmits.
No approval/PAM, Stop, policy, provider activation or grant route is added.

Unit tests cover reply validation, identity substitution, fixed labels, stale
revision rejection, previous-state preservation and exactly one read-only RPC.
The guarded Debian GTK/AT-SPI fixture submits once, reads synthetic task status,
checks actual visible/accessibility text, verifies the main loop ticks during a
slow lookup and checks receipt count stays unchanged. That fixture proves native
UI behavior with injected local data; it is not a live broker integration claim.
Separately the installed broker VM invokes the production status client as the
native human through the actual protected socket before and after task allocation.
The existing authenticated-human/wrong-role probes remain required.

CI acceptance requires read_only_intake_client_actual_native_transport in the
broker report and responsive_during_slow_status in human-prompt.json. Inspect the
hashed human-prompt.png for layout. No physical keyboard, live model execution,
full approval/task UI or independent completion claim follows from these tests.
