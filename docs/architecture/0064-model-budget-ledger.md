# Durable model budget reservations

A task budget belongs to the original task/human/boot. Trusted authenticated
approval code can set initial integer limits once: micro-USD and total tokens.
Limits cannot be replaced or increased through this API, and no public IPC
operation configures, reserves or settles them. Integer arithmetic avoids money
rounding ambiguity; bounded positive values reject bool, float and overflow.

ModelBudget.begin reserves conservative maximum money and tokens and starts the
original ModelStore attempt in one outer SQLite transaction. Expired grants,
replays, missing budgets and exhausted aggregate limits leave no reservation or
attempt. All attempts under one task count against the same limits. Unknown,
Stop or crashed calls retain their full reservation: absence of a response is
not evidence that no bill was incurred. Reservations survive journal reopening.

Trusted settlement requires a completed, bound model result, usage tokens equal
to the saved provider usage and measured money no greater than the reserve.
Settlement is once-only; unknown effects cannot release budget. Higher-than-
reserved usage fails closed and keeps the reservation for explicit reconciliation.

This is an internal accounting primitive, not a financial ceiling proof for a
live provider. Production model preparation remains disabled. Before activation,
wire authenticated budget approval into the native human view, bind a trusted
price schedule and exact model/context limits to conservative reservations,
reserve through this path before network dispatch, and validate live billing.
ModelStore remains the lower-level custody primitive for synthetic outcomes;
all future paid execution must use the budgeted entry point. No provider prices,
real credentials, paid API calls or model-quality claims are introduced here.
