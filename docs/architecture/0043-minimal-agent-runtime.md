# Minimal LangGraph agent cycle

The original specification selects LangGraph. AgentRuntime uses its StateGraph,
not a substitute workflow engine, with a single bounded cycle and an injectable
LangGraph checkpointer. Dependency: langgraph1.2.15 (PyPI metadata checked live).
Model input contains only the human prompt; model output must contain exactly
args and reason. Scope, operation key and broker identifiers come from the task
context. The existing strict broker schema validates initial and replayed plans.

The runtime only requests approval, polls it, proposes the same keyed operation
once approved and queries action status. It cannot create grants, authenticate
PAM, execute a process or mark evidence verified. done plus verified=false means
verifying; unknown means unknown_effect. An old graph status never overrides a
fresh journal response. A lost action-ID response is reconciled by the broker's
existing idempotency key, without a new operation key or effect retry.

Tests use actual LangGraph and actual State/Approvals/IPC dispatch with a mock
model and synthetic peer metadata. They cover awaiting-grant, exact proposal
replay, running/done-unverified/unknown, forged authority output, traversal and
checkpoint scope changes. InMemorySaver demonstrates checkpoint plumbing only.
Persistent checkpointer ownership/restart tests, actual socket task-UID execution,
prompt integration, independent outcome checks, real/cloud model adapters and
golden project tasks remain required. This module is not yet an installed core
service or a complete autonomous coding agent.

Primary API references:
- https://docs.langchain.com/oss/python/langgraph/graph-api
- https://docs.langchain.com/oss/python/langgraph/persistence

## Actual public transport and VM golden project (acceptance pending)

BrokerClient uses only the fixed root-activated request socket. It validates the
actual broker service UID/GID in each kernel message, truncation/rights/envelope
checks, and holds a pidfd so replacement requires explicit client reconstruction.
Private capture/authentication/verification operations are unavailable. No effect
request is automatically retried on socket failure.

The disposable guest installs the pinned LangGraph stack in a separate root-owned
venv. The installed-code probe runs AgentRuntime under an actual allocated task UID,
requests approval, authenticates the human through native PAM, and asks the broker
to create calc.py/test_calc.py and run a real unittest inside its restricted runner.
No file should appear before approval. A result marker is independently observed;
status remains verifying. Replaying a lost action-ID checkpoint returns the same
journal action and preserves a deliberately changed marker, proving no rerun.
This is a deterministic mock-model golden case; actual VM enforcement and all
previous security probes must pass CI. No real model, durable graph restart or
semantic task-completion claim follows from this one case.
