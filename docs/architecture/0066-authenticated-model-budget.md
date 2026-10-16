# Authenticated task model budgets

The typed model.set_budget capability asks for exact money_micro_usd and total
tokens, bounded positive integers. It contains no model credentials, URL or
execution command. Its existing protected native approval view displays the
limits and binds the task, human, resource, nonce, boot, epoch and expiry.

Approvals.approve issues and consumes a dedicated one-use budget grant inside
the same journal transaction as applying the limits. Public requests can ask
for approval but cannot apply the budget. Registry refuses public dispatch of
the budget capability; the consumed grant cannot fund a model or terminal action.
Initial limits or monotonic increases require a fresh exact authenticated grant.
A rejected lowering rolls back both the new grant and approval consumption.
Uncertain model attempts continue counting against the task's reservation total.

The guarded disposable VM probe exercises native PAM wrong-password denial,
exact successful limits persisted to the private journal, challenge replay
rejection and public budget dispatch denial. Acceptance requires actual final
CI flags native_pam_task_model_budget and
budget_grant_replay_and_public_dispatch_denied. Until then it is unproven.

This connects approval to the accounting ledger; paid dispatch remains disabled.
A trusted price/context reservation policy, provider job association, installed
egress/cancellation integration and live billing verification remain required.
