# Request-bound native rearm through PAM

Emergency Stop remains on the protected human socket and executes only native
code. Rearm uses an additional root-only native control socket; PAM runs in the
existing approval service, so password authentication cannot block the Stop daemon.
The native control listener validates root connection/message credentials and
rejects ancillary descriptors; untrusted task/core/broker UIDs cannot use it.

A view issues a random32-byte, one-use challenge bound to the current latched
generation and a60-second monotonic expiry. Every newer Stop invalidates it.
The human approval socket gains bounded typed rearm view/confirmation packets.
The confirmation password is authenticated with PAM before the root control
request is sent, and native buffers are wiped. No model-selected paths/commands
are accepted. The human TTY client exposes mano-approve --rearm and describes
that new tasks may resume while old permissions remain revoked.

The native daemon consumes the challenge, verifies current generation/expiry,
and requires all managed task groups unpopulated before publishing a newer armed
state through the existing atomic protocol. The broker persists the last native
generation. Observing a newer armed generation revokes old authority and settles
uncertain actions before clearing its latch, including when Python was frozen
through Stop and rearm. Decreasing generations fail closed. Restart/proposal alone
cannot rearm, and old grants are never restored.

Portable tests cover bounded packets, malformed/bool/overflow fields, rollback
and a broker missing the intermediate Stop generation. The VM exercises native
PAM rearm wrong-password/nonce denial, newer-Stop invalidation, replay denial,
broker-frozen rearm, old-grant denial and fresh PAM-approved terminal completion.
Native compilation and integration acceptance are pending CI. Expiry and live
populated-group denial need additional explicit VM cases; no full Stop/performance/
physical/golden acceptance is claimed. Synthetic CI password stays in memory.
