# 0108: Current-input, exact-plan installation review

`PackagePlan.review_install()` queries the broker's `package_install_review`
operation with only the live task/resource, captured action ID and exact plan
digest. The broker reads its own durable, successful forecast output; it accepts
no client-supplied package list, plan body, argv, source, path or installation
option. Current task/caller/boot/resource custody and the original action scope
must agree. Recheck the operator's active catalog, host status, signed-index
identities, trust anchor and expiry using the existing catalog validator.

Return the complete captured plan (including explicit removals, archive hashes,
download bytes, net installed size, and unmeasured peak space), bound to its
digest, current boot/epoch/Stop generation and at most 60 seconds of wall-clock
lifetime, never beyond catalog expiry. Hash that complete review body. Observe
Stop both at request admission and after the input checks; reject an intervening
epoch/generation transition. The SDK validates the complete response and expiry.
Existing output hashes prevent corrupt durable custody from becoming a review.

This is a read-only review description, not fresh apply consent. It creates no
grant, action, reservation, snapshot, process, download or package effect, and
does not consume another forecast grant. It explicitly reports
`install_authorized=false`, `apply_available=false`, `package_locks_held=false`,
`root_resolution_verified=false`, `current_applicability_verified=false` and
`fresh_apply_approval_required=true`. A review digest is not a bearer token or
authentication. A historical forecast remains readable separately when current
review becomes unavailable. Re-querying does not execute the solver again.

This is an integration step toward the spec's narrow privileged package helper.
A future apply path must independently lock/re-resolve current Root state,
verify exact approved archives, establish a sufficient space policy and a
before-change snapshot, obtain separate native PAM consent for the exact final
review, and integrate privileged effects with independent Stop and durable
crash reconciliation. None of those requirements is satisfied by this review.
The input check is point-in-time; package state can change after it returns.

Validation: local live-state/SDK tests exercise scope/digest/contract/custody
tampering, stale catalog, lost resource and a Stop during input validation.
Guarded Debian native PAM/public SDK tests review the dependency and installed
forecasts, reject wrong caller/task/resource/action/digest/additional fields,
and reject review after active catalog substitution. The packaged SDK repeats
review before and after real stock-Debian reboot. Native/package/recovery and
all six fresh raw GUI gates remain mandatory on the final CI head. Local mocks
are not native evidence. No production permission or launcher-policy changes.
