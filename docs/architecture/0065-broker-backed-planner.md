# Broker-backed core model planning

BrokerPlanner uses only public broker IPC. It holds no provider key, provider
URL or network client. An operation key deterministically selects the same
model-disclosure approval after core restarts; changed prompt/model/output limits
under that key conflict with the original journal entry. No model request can
be proposed until its separate exact model.plan approval is granted.

The core polls the authoritative model action and verifies its task, ID and
original proposal digest. Intent/executing/unknown/failed states remain explicit
planning states in the LangGraph checkpoint. Unknown results never trigger a
new model attempt. A completed result is read through bounded digest-checked
chunks and validated as a terminal proposal. The usual independent terminal.run
approval is still required; a model grant does not permit shell execution.

This connects existing core and broker contracts. It does not enable production
model execution: Registry still refuses model.plan preparation. The installed
credential service, paid reservation/approval integration, task/job association,
permitted egress and live provider tests remain activation gates. Tests use the
real graph, journal, approval library and public dispatcher with synthetic
broker-internal model completion. They do not claim installed or paid execution.
