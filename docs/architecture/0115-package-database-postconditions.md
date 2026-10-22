# Durable package database postconditions

The package-attempt journal previously kept every attempt unresolved. An executor
needs to distinguish a settled, verified package database transition from an
interrupted or uncertain effect before allowing a later separately approved job.

The private Root library now exposes complete_locked(attempt_id, request_digest,
plan). It requires the caller's active backend-held package lock scope, the exact
original request and current boot, a matching read-only before-checkpoint, and a
clean dpkg journal. It parses bounded before/after status bytes, requires exact
approved candidate versions in fully installed state, settled removals, and no
state/version changes outside the plan. It checks all requested versions and
rechecks the current status digest before publishing a write-once verified.json.
An exit code alone is insufficient. It checks database states/versions, not all
package payload bytes or arbitrary maintainer-script effects.

A verified record is a historical observation with execution_authority_verified
and maintainer_effects_verified both false. It is never approval or proof of the
system state after a later boot/rollback. Reconciliation preserves it unchanged.
Only well-formed verified history allows a different attempt ID; every ID stays
reserved permanently within the bounded retention limit. An existing unknown,
partial, malformed or foreign outcome cannot be promoted or overwritten and
blocks new attempts for operator recovery. No action is automatically replayed.

The disposable CI fixture will forecast the signed Debian sl candidate using the
real catalog, record intent against the original checkpoint, reject premature
completion and completion during backend handoff, run dpkg under the existing
frontend protocol, and verify the actual database transition. It then starts the
existing interrupted-dpkg attempt. A real recovery boot must preserve both the
verified history and the unknown attempt while restoring the pre-sl database.
Before/after status artifacts permit independent transition checks.

This adds no public apply endpoint, no new PAM grant, no new Root execution
service, and no product Stop/hostile-maintainer-script claim. The complete apply
integration still requires fresh native approval, a narrowly authenticated Root
executor, isolation, acquisition/space admission, child drainage, payload and
registry postconditions, and Stop/crash/operator recovery. The trusted Broker
remains the grant authority. Native evidence is pending exact-head CI acceptance.
