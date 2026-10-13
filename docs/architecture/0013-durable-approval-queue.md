# ADR0013: durable broker-owned pending approval queue

Status: candidate until final-head CI. PAM/control transport integration remains next.

Core may request approval for a typed operation within its registered task/resource.
The broker binds a protected pending record to task, exact arguments, caller/human
identity, classification, expiry, boot and stop epoch. A broker-minted nonce and
operation digest identify the view to be displayed through a protected human channel.
The caller receives only approval ID, state and eventual grant ID; no nonce/view or
confirmation method is exposed on the public socket. Model explanation is explicitly
reason_untrusted and supplies no authority. Rendering must use escaped structured data.

The confirmation API is trusted-only: authenticated_human_uid must come from the
separate PAM adapter, not a JSON assertion. Confirmation rechecks exact nonce/digest,
human identity, time, boot, epoch and stop latch. It atomically creates one exact
operation grant and consumes the challenge in one outer SQLite transaction. Internal
nested mutations use unique trusted savepoints; a failure after grant insert rolls
back both insert and consumption. Two independent DB connections cannot confirm twice.

Requests bind idempotency keys to exact proposal digest. Conflicting replays deny;
identical replay returns prior status without minting authority. Records survive
restart. Each trusted task has a lifetime limit of64 approval records, including
expired ones, so waiting for expiry cannot reset storage quota. No records are deleted.
This conservative policy will require explicit profiles for longer workflows; it is
not an implicit Full Access bypass. New confirmation grants use count1,256MiB,32pids,
20%CPU and at most300-second timeout, within the approved operation's60-second expiry.

Tests cover identity/resource/schema conflicts, private views, valid exact grants,
nonce/digest/human/time/boot/stop denials, replay/restart, lifetime quota, two-connection
consumption race and a failure after grant insertion. Real non-root service CI checks
public request/status, denied self-approval and pending-state persistence after SIGKILL.
Existing VM/stop/credential/exact-target tests remain required.

This queue is not proof of PAM authentication. No root control listener or production
human authentication helper is wired yet. Next: separate protected control and human
PAM channels, root-owned user mapping, broker-owned UI view and confirmation receipt.
Then pinned resources, sandbox executor/native stop/verifier and the original Phase1
minimal agent/golden task gate. Full original v2.1 scope remains active.
