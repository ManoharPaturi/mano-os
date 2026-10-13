# Persistent LangGraph checkpoints

Session uses the upstream SqliteSaver3.1.2 with LangGraph1.2.15. It opens only an
agent-owned0700 directory and0600 regular single-link file, rejects symlink
components and root execution, checks file identity, disables trusted SQLite
schema and pickle fallback, and uses empty dynamic-module allowlists. Task/resource/
operation-key/prompt are fixed across reopening. AgentRuntime always queries the
broker journal even when a saved graph status claims completion.

SQLite uses FULL synchronization, a1024-page database ceiling, small automatic WAL
checkpoint intervals and a1MiB value limit. This guards checkpoint database growth;
it is not an OS disk quota or a power-cut recovery claim. The broker action journal
is separate and remains the authority for side effects. Agent checkpoint contents
never authorize a grant or override unknown effects.

Local tests close and reopen the real saver, preserve a pending approval/proposal,
reject changed scope, and reconcile a stale graph against an unknown journal action
without another proposal. Broad permissions, file symlinks and hard links are denied.

The VM golden task runs each step in a fresh transient non-root service. Each
process opens the same private checkpoint, making process restart part of the
actual task-UID socket/PAM/runner/verifier flow. The transient service sets zero
capabilities, NNP, syscall filter, no namespaces, read-only system and workspace-only
writes, Unix-only sockets,256MiB/32tasks/50percentCPU,128FDs and an8second deadline.
The process itself reads back cgroup and credential/filter constraints. A separate
old-response replay case still uses the saved pre-action state to check idempotence.
Actual VM acceptance remains pending final-head CI. This transient test service is
not yet the installed long-lived prompt/core service or a real-model integration.

Recovery also binds each journal status to a broker-generated SHA256 of the exact
original proposal (grant ID excluded). AgentRuntime compares this with its saved
proposal before interpreting verified/done. A valid older action ID from the same
task cannot complete a different operation. The public digest exposes no command,
grant or arguments. A regression test simulates an older verified journal action
and swaps its ID into a different keyed proposal; completion is denied.
