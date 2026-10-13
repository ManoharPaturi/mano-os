# Provider response boundary

The first provider adapter implements the OpenAI Responses function-call wire
contract behind an injected authorized relay. It has no endpoint, credential,
network client, process launcher or approval authority. The configured model is
explicit; response model substitution is rejected. No model default is guessed.

A request contains only the human prompt, fixed developer guidance, a strict
propose_terminal schema, and a bounded output-token setting. Storage and streaming
are disabled, tool choice is fixed, and parallel calls are disabled. The proposed
function is data: this adapter executes no returned call. Only args and reason
can become an AgentRuntime plan. Task/resource/grant identities come later from
trusted runtime context and broker approval.

Responses are byte-bounded and strict JSON. Completed status, model identity,
usage integer consistency, configured output ceiling and exactly one completed
expected function call are required. Refusals, incomplete responses, additional
tools, malformed JSON, extra plan authority fields, environment injection and
invalid workspace paths fail closed. The same public ActionRequest validator
checks terminal arguments. Reasoning text and unused response fields are not
forwarded or logged. Transport failures propagate after one relay call.

Tests use recorded synthetic Responses packets and mocked relays. They prove
wire validation and proposal handling, not a real API call, token billing or
semantic plan quality. store:false is a request setting, not a zero-retention
claim. Reported usage is not a hard financial ceiling. Protected relay service,
credential custody, task-scoped disclosure authorization, durable call budgets,
network policy, Stop cancellation and live provider tests remain required before
production integration. The installed CLI remains explicitly mock-only.

Contract sources checked on 2026-10-14:

- [Official OpenAI function calling](https://developers.openai.com/api/docs/guides/function-calling?strict-mode=disabled)
- [Official Responses migration and storage settings](https://developers.openai.com/api/docs/guides/migrate-to-responses?api-mode=responses.html)
