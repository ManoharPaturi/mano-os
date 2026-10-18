# Protected human task journal visibility

A new native operation07 accepts exactly one prompt ID. The Root native adapter
supplies its configured, kernel-authenticated human UID; the packet cannot supply
a UID, task selector, boot ID or query limit. The Root-only broker control route
checks prompt ownership/current boot and the attached task's human/boot binding.
Operation06 intake compatibility and PAM approval view/confirmation are unchanged.

One consistent journal read returns intake status, total action count, the latest
16 action IDs/capabilities/states/verification bits, and at most64 approval records
with IDs/capabilities and effective pending/approved/expired/revoked states. More
than64 records denies; the normal lifetime quota already bounds the table. Replies
exclude arguments, model reasons, prompt text, grant IDs, nonce/digest challenges,
passwords, API keys and artifact contents. No record is created or consumed. The
approval schema initializes with State instead of a lazy approval-helper write,
so the first empty snapshot is read-only too.

The human may inspect historical status after Stop: executing work becomes unknown
and pending approvals revoked through existing journal reconciliation. A completed
action with no independent verification remains done/effect not verified. A stored
verification bit refers to the broker's specific predicate evidence, not proof the
entire user goal is complete. The snapshot does not assert process liveness or
controller/model completion. There is no GUI confirmation or grant authority.

The GUI validates fixed fields, enums, lengths/counts, unique IDs and the exact
selected prompt/task. Newer selections invalidate slow replies. It renders plain
text in a bounded scrolling region, labels the displayed/total action counts and
shows approval IDs for review through the trusted terminal. A failed read retains
the last acknowledged state; it never resubmits or retries an effect.

Unit tests cover first-read/no-approval initialization, no database changes,
cross-human/old-boot/mismatched-task/nonroot denial, secret-field redaction,
expiry/revocation, bounded newest-first actions, malformed replies, no retry,
stale selection and task substitution. The guarded Debian VM must prove the actual
production client/native route with pending approval, done-unverified action,
independently verified predicate, wrong-role/cross-human/malformed denial and
Stop unknown/revoked state. Required flags:
human_task_snapshot_pending_done_scope_and_redaction and
human_task_snapshot_stop_unknown_and_revoked.

Separately the GTK/AT-SPI fixture injects local synthetic task/approval data and
checks visible text, one submission, slow-read responsiveness and screenshot
layout. This proves native UI behavior, not an integrated live model or physical
keyboard. Inspect the final-head hashed screenshot before merging. Full policy
profiles, interactive trusted approval/task UI and all later v2.1 gates remain.
