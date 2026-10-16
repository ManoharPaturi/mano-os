# Exact model disclosure approval

model.plan is a distinct typed capability. Its arguments contain only provider,
model, the exact prompt, and max_output_tokens. The first provider is the fixed
OpenAI integration; no caller-selected endpoint, authentication header, key,
environment or redirect policy is accepted. Prompt bytes and output tokens are
bounded, and model identifiers use the same validator as the provider adapter.

Existing approval binds these exact arguments to the task, resource, human,
current boot/epoch, expiry and one use. Increasing output tokens or changing
prompt/model requires another approval. Terminal permission conveys no model
disclosure authority. Native PAM displays the exact capability and arguments.

The production Registry rejects this capability before consuming a grant or
creating an action because the protected provider executor is not installed.
This deliberately keeps outbound calls disabled while the remaining relay,
credential, network, Stop and durable-call accounting work is implemented. The
process-local journal API can record authorized intent in tests but performs no
network operation. No cost ceiling or live provider behavior is claimed.

Unit tests cover exact-argument grant binding, idempotent intent, invalid fields,
credentials/endpoints, budget increase and the production preparation guard. The
VM witness requires actual native PAM approval of the exact disclosure followed
by production execution denial. It uses a synthetic model name and makes no API
call; this is not model availability or financial authorization evidence.
