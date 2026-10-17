# Original provider job custody

ProviderJobs prepares a paid attempt and saves a fresh nonce with its exact
request digest, task, action and boot in the same transaction as pricing and
budget reservation. Only a trusted executor can claim the job once. Claiming
rechecks action state, current grant epoch/expiry/revocation and Stop, then
revalidates the saved price policy against the current trusted wall clock and
commits dispatching before returning the bounded private generate envelope.
A policy that expired while a prepared job waited cannot authorize a send.

The expected sealed response binding comes from the private saved job, never
from core/model fields. The authenticated descriptor receiver supplies bytes to
the original priced completion path. Result custody, budget settlement and job
completion share one transaction. Wrong bindings, repeated claims or stale work
cannot complete another job. A failed/uncertain receipt marks the original action
unknown and retains its full budget; recovery cannot authorize a second dispatch.

This is broker-internal execution custody, with no public mutation endpoints,
socket opening, provider call or network-policy activation. It depends on the
priced-reservation and sealed-handoff PRs. Production Registry continues denying
model.plan until the protected installed executor, generation policy/credentials,
permitted fixed egress, native cancellation and actual end-to-end provider/billing
verification are connected. Synthetic custody tests do not prove paid execution.
