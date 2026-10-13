# Durable model attempt custody

ModelStore is a trusted broker-internal helper, not an execution service. Before
network dispatch, an exact authorized model.plan intent can transition to
executing and reserve one durable attempt in the same SQLite transaction. Repeat
reservation is denied, and a lifetime quota bounds stored attempts. No HTTP or
credential code is present; production model preparation remains disabled.

A completed response must pass the public Responses schema for the original
model and output ceiling. The broker persists only the validated plan, bounded
usage counts and raw-response digest, with a digest of the complete stored result.
Raw reasoning and unused response fields are discarded. Completion records a
successful model operation, with verified still false; it does not establish
that the proposed terminal task succeeded. Stop, revoked/changed epoch, a missing
reservation or a changed action binding prevents completion.

Same-task/current-boot reads derive caller UID from the kernel public transport.
They verify result custody and return saved data without issuing another model
call. Wrong callers/tasks/boots and corrupted results are denied. Reservation,
completion and uncertain mutation are not exposed on public IPC. Broker recovery
or Stop changes an executing attempt to unknown; an explicit uncertain receipt
does likewise. No state automatically resends the request. Malformed responses
leave the active attempt for the trusted executor to mark uncertain or reconcile.

The Responses wire parser moved to mano_protocol so trusted custody need not
import untrusted core implementation. Core compatibility exports remain. Unit
tests exercise the actual journal and public dispatcher, restart and Stop,
idempotent reservation, private mutation denial, caller scope and corruption.
These are synthetic in-process outcomes, not a live provider or network proof.
Protected service credentials, task-scoped TLS egress, job/reply association,
dispatch cancellation, durable cost reservations and real API tests remain gates.
