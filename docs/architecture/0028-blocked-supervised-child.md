# Blocked supervised child lifecycle

The trusted root service API composes admitted directory FDs, fixed cgroups,
allocated-account credential dropping and the accepted unprivileged sandbox
runner. It re-parses terminal syntax before allocating, duplicates its own rights,
forks a blocked child and places that child before signaling credential setup.
The child closes unrelated FDs, drops and verifies credentials, then validates
sandbox construction before sending READY. No caller task argv executes at READY.

A separate one-shot start call requires a trusted authority callback returning
exactly True. Prepared children expire after five seconds; expiry and false or
throwing callbacks cancel without program start. The callback is also followed by
a deadline check. This is an API integration point, not a broker grant/epoch
implementation. The operator fixture supplies its own authority; synthetic request
IDs are not declared authorized broker grants.

The child waits on the private start pipe, then runs argv only as the allocated
identity with held mounts, native guard, fixed environment and bounded streams.
Its structured report uses base64 for at most 64 KiB per stream and a fixed 192 KiB
parent report limit. The parent drains before and after reaping to handle the final
write race. An independent parent deadline covers a hung child/compiler. No
model stdout is interpreted as control or verification metadata.

Closure uses the owned cgroup kill operation, waits for population zero, reaps only
the owned child and releases its FDs. Allocation failure also removes its new empty
group and closes partial rights. Before-start cancellation is not-started. After-
start cancellation, malformed reports or child loss are unknown; file effects may
exist. Finished means an observed process result, not independent verified effects.

The real delegated fixture now executes fixed operator programs as the allocated
task: blocked-before-start marker, start replay denial, false/expired start without
effects, both full 64 KiB streams, active cancellation with an observed marker, and
invalid-FD allocation cleanup. Existing credential, detachment, group and quota
checks remain. The service filesystem allows the private workspace parent; the
untrusted command sees only its admitted directories inside the sandbox.

No production listener, public broker execution operation, model connection or
independent artifact verifier is enabled. Actual kernel broker authorization,
grant/start journal coupling, emergency stop, crash reconciliation and golden
agent tasks remain required before the Phase 1 gate.
