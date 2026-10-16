# Trusted model pricing reservations

A trusted executor can begin an attempt through begin_priced. The immutable
PricePolicy binds an exact model, an explicit revision, expiry, configured input
context bound, output ceiling and integer micro-USD rates per million tokens.
The core cannot provide these fields through a public mutation endpoint.

The broker reserves the full configured input context plus the exact approved
output ceiling. It ignores cache discounts and rounds the combined price upward
using integer arithmetic. Wrong model, stale policy, invalid bounds or insufficient
task budget deny the request before an attempt starts. Price binding, aggregate
budget reservation, original attempt start and the price audit event share one
transaction. Unknown effects retain the full reservation and never auto-resend.

This is a conservative accounting mechanism under an operator-verified price and
context policy, not evidence of actual provider prices or billing enforcement.
Synthetic tests use invented rates explicitly labelled synthetic. Before paid
activation, provisioning must supply verified model/context/rate metadata, control
policy freshness and clock provenance, bind the installed executor to this entry,
validate provider usage against the reserved bounds and verify actual billing.
No live prices, provider configuration, credentials or paid calls are introduced.
Production model preparation remains disabled.

The original complete price policy is stored with the attempt. finish_priced
validates input/output usage against those saved bounds, validates the complete
Responses contract, and settles using the original rates in the same transaction
as result custody. Excess usage leaves the attempt unresolved with the full
reservation; no retry or refund is inferred. Later policy edits cannot change
the saved quote. Journal recovery still changes interrupted attempts to unknown.
