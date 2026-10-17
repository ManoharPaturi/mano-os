# Root-gated model scheduling in the installed broker

The broker now constructs the bounded provider worker and gives its Registry a
trusted pricing-policy check. A model proposal must match the Root-loaded enabled
pricing metadata before consuming an exact human-approved grant. A disabled or
mismatched quote creates no action, reservation or queued provider dispatch.

A fresh authorized proposal queues one model action and returns intent immediately.
Subsequent broker ticks poll at most two active provider transactions and start at
most one queued action. The broker's SQLite connection stays on its original
thread. Terminal scheduling and protected control continue through the existing
loop. Replays cannot queue another invocation. Stop before launch fails the queued
intent; dispatch uncertainty remains unknown without automatic retry. Shutdown
closes provider transactions and discards queued authority before releasing the
remaining broker resources.

Regression tests exercise real Registry/grant preparation with a synthetic trusted
worker: scheduling after reply, no replay, disabled policy preserving the grant,
failed launch, Stop and shutdown. They do not establish installed positive provider
execution. The Debian VM additionally approves a real native PAM model grant and
checks that the shipped disabled pricing snapshot denies execution without using
that grant or creating provider jobs. Required new witness:
installed_disabled_model_policy_preserves_grant.

Default pricing and provider generation remain disabled. The provider unit still
permits only Unix sockets. Real provider activation needs independently verified
price/model metadata, protected key provisioning and a constrained network policy;
none of those gates are bypassed by scheduler wiring. The recurring core planner
still requires integration and live-provider acceptance remains incomplete.
