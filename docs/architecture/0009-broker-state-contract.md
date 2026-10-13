# ADR0009: trusted request/grant/journal foundation

Status: candidate until final-head CI; Phase1 remains incomplete.

The core proposes actions through a strict bounded UTF8/JSON contract. Extra
fields, duplicate keys, caller identities, self-issued action IDs, environments,
approval flags and verification assertions are rejected. Broker task/grant/resource
IDs bind proposals; relative paths are syntax-checked, not considered securely
resolved. The later runner must pin resources with descriptors and enforce actual
mount topology. `protocols/broker-action-v1.schema.json` describes the wire shape;
`ActionRequest.parse` additionally enforces UTF8 byte budgets/canonical paths/NUL rules.

SQLite stores trusted task identities, classification, boot identity, mode, grants,
count/resource budgets, revocation epoch/latch and journal transitions. BEGIN IMMEDIATE
reserves grant use and intent atomically; DELETE journal/synchronous EXTRA retain
committed state across abrupt process termination. Expiry/revocation/boot is checked
again at dispatch. Idempotency keys bind the exact canonical proposal; conflicts
fail, replay returns the existing authoritative action with no fresh reservation.
Running work recovered after writer exit becomes unknown and cannot be redispatched.

A zero exit code records done but verified=false. Verification is a separate
trusted transition requiring artifact identity/hash metadata. This is not yet an
independent artifact verifier: artifact custody and content checks belong to the
executor/verifier gate. Client proposals cannot set any of those result fields.

All mode names are represented, but this initial core requires explicit trusted
approval for every grant and permits only inspect/file/terminal capabilities.
Mode-specific automatic issuance and wider scopes remain Phase1/later work. Unknown
network, credential, device, persistence, human-desktop and root capabilities deny;
Full Access adds no bypass. Grant scope currently selects one broker-owned resource,
with classification/identity/boot bound by its immutable task. Network/external
rights have no supported capability here, so no such effects are authorized.

The state API is called only by trusted broker components. It is not an untrusted
wire endpoint and does not authenticate a Python caller by itself. Production IPC
must derive UID/PID via kernel peer credentials and expose only propose/status to
core; issuance, verification and stop/control remain separate trusted channels.
Provision state under protected root-owned ancestors; the leaf must be broker-owned
0700 and DB0600, with symlink paths rejected. The library is not a filesystem/path
custody proof for arbitrary state locations or a installed daemon.

CI validates schema forgery, identity/resource/capability/timeout/expiry/count
mismatches, dispatch after revocation/expiry, concurrent single-use reservation,
zero-exit separation, restart unknown handling, replay conflicts and durable latch.
The recovered Debian guest also tests abrupt writer exit and actual read/write
EACCES from agent/core/worker against a root-owned journal, checking unchanged hash.
It does not execute a model action or pretend to prove the full broker/runtime gate.

Next: kernel-authenticated IPC and trusted request-bound approval integration;
resource registry/FD pinning; cgroup/bwrap/seccomp/Landlock runner; native stop
integration; result/artifact verifier; isolated terminal and model/AgentRuntime.
Golden project creation/testing and protected-policy attacks gate Phase1 completion.

References: [Python sqlite3 transactions](https://docs.python.org/3.13/library/sqlite3.html)
and [SQLite PRAGMA durability](https://www.sqlite.org/pragma.html).
Rollback: revert this PR. Only disposable CI/test DBs are created; no host service,
model route or privileged command executor is installed.
