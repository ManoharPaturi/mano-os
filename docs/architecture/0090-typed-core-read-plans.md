# Typed core workspace reads and result references

The broker's production read executor is available, but the core and provider
contract previously permitted terminal plans only. Share a strict public plan
validator across the provider, core CLI, LangGraph cycle and trusted operator.
It supports terminal.run and files.read, with the original args/reason terminal
shape retained for checkpoint compatibility. Optional capability is a constrained
selector, never a grant or caller identity. Reject every extra authority field,
unsupported capability and invalid action argument before requesting approval.

The Responses contract exposes two strict function schemas: propose_terminal and
propose_file_read. Tool choice is required and parallel calls are disabled; the
parser still independently requires exactly one recognized, completed call and
validates its arguments with the shared action schema. The function name, not a
model-selected authority field, supplies the read capability. Existing terminal
responses remain valid. Usage/model binding, no-retry, fixed endpoint, separate
disclosure/spending approval and disabled-by-default policy remain unchanged.
No real API key or paid request is used for this implementation's tests.

After its own file approval and broker journal completion, the core retrieves
immutable file_result chunks. Validate task/action/path, stable artifact identity,
boot, size up to32KiB, source inode/device, explicit false verification, exact EOF,
bounded progress and SHA-256 across the complete bytes. Binary and empty files
are valid. Retrieval errors do not retry execution. The SDK helper returns bytes
to its local caller; the LangGraph cycle retains only artifact metadata in its
private checkpoint and stdout. It never interprets bytes as instructions or
forwards them to a provider. Any later model disclosure remains separate.

Use read_ready for an available snapshot. It is distinct from verified terminal
completion and from the user's overall goal. Requery the journal and result on
checkpoint replay, discard forged/stale read metadata and never rerun the action
or model. Unknown/failed/running states clear a stale read reference. The bounded
controller settles this one cycle at read_ready without claiming a full workflow.

The Root lifecycle adapter discards core-reported read metadata and reconstructs
the status/reference using the existing protected inspect_action binding plus a
new Root-only inspect_file_read query. That query has exactly task/action IDs and
returns metadata from a unique completed current-boot read; existing durable byte
integrity checks run inside the broker. It creates no action or grant. Neither
query is available through the public request interface. The core has no authority
to verify an effect, approve its own read or change the managed task context.

Tests cover both function contracts and mixed/forged plans, separate model and
file approvals, real LangGraph/journal replay, bounded multi-chunk binary custody,
empty/boundary results, altered metadata/hash/EOF, no progress, transport failure,
protected operator reconciliation and controller state. The installed Debian
probe runs the installed core CLI under its actual allocated task UID, requests
native PAM read approval, opens a new private checkpoint process on each step,
reaches read_ready and preserves the original snapshot after source mutation and
replay. Provider response fixtures remain synthetic; installed read/PAM/CLI are
real CI VM paths. No live-provider, physical-input or release claim follows.

The prepared service probe uses the installed production core CLI. The separate
fresh-stock Debian package probe additionally runs typed core reads and checkpoint
replay before and after the actual reboot, using only the .deb and its native
PAM-approved workspace profile. Export only read metadata/hash and explicit false
disclosure/verification claims. The prepared probe also mutates the source to
prove immutable replay; the stock probe preserves the reboot data-retention
sentinel and checks the packaged result hash instead.

Official API contract reference (checked2026-10-19):
https://developers.openai.com/api/docs/guides/function-calling
Required tool choice, parallel_tool_calls=false, explicit strict schemas and
additionalProperties=false are documented there. Local validation remains the
authority boundary regardless of provider-side schema enforcement.
