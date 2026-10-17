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

The companion provider job_request.authorize validator checks the broker peer,
enabled fixed provider/model/output policy, strict envelope and ActionRequest,
original digest/task and current boot before returning only disclosure arguments.
It performs no credential read or network call. A combined test passes the real
broker claim envelope through this provider validator. The installed main entry
remains health-only; this validator alone does not authorize activation.

job_request.execute joins the validator to exactly one fixed HTTPS helper call
and one sealed response. It validates the private connection before the call and
never retries failures. A Linux component test joins actual job preparation,
claim envelope, provider validation, sealed socket transfer, original priced
result custody and settlement. Only the HTTPS response is mocked. This is not
an installed service or live API proof: main remains health-only, with the current
AF_UNIX/private-network profile, until provisioning/egress/activation gates pass.

provider_client.run is the trusted broker's fixed socket transaction. It requires
separate broker/provider identities and root listener credentials before creating
any reservation. It prepares, claims and sends one bounded packet, then consumes
the sealed receipt under the original provider UID/GID. Send or receipt failure
marks an unresolved original job unknown without refund or retry. The connection
has a 40-second receive bound in addition to the provider's independent 35-second
unit deadline. No caller-selected path, endpoint or provider UID enters the wire.
This helper is not registered for public model.plan dispatch yet; the installed
service and generation route remain disabled pending the activation gates.
The private claim packet now carries the authoritative grant monotonic expiry
and price Unix expiry. The provider checks its own current clocks immediately
before the actual helper invocation and requires at least35 seconds remaining
under both. This covers its fixed35-second hard-kill unit lifetime; a component
contract test binds that assumption to RuntimeMaxSec and KillSignal. Delayed
startup/queued packets, malformed numeric deadlines and too-short grants deny
before an API call. Installed activation must retain this exact protected unit
profile and supply the current kernel boot; main still does not route generation.
