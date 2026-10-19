# 0097: Separately approved captured execution feedback

The default planner discloses only the human prompt. Repair planning may explicitly
select one original failed terminal action through feedback_action_id in the fixed
core model configuration. This selection grants no disclosure or execution authority.

Feedback includes the complete stdout and stderr streams, readable UTF-8 text,
base64 bytes, sizes, SHA256, original action/boot and nonzero normal return code.
Combined streams contain 0..4096 bytes; a known nonzero exit with empty captured
streams is valid, while missing custody is never treated as empty output. Missing custody, binary text, larger
streams, success, output limits and unknown outcomes are rejected without truncation.
The broker reconciles the snapshot against its private terminal custody before
pending approval, fresh authorization and the one-shot model attempt. Cross-task,
cross-caller, cross-boot and self-consistent invented logs cannot become feedback.

The model.plan grant binds the exact prompt, feedback and output-token ceiling.
Existing native PAM approves this separate disclosure. Auto workspace permissions
never approve model disclosure. Reading captured output locally is not permission
to send it to a provider. Changed bytes or approval replay cannot authorize a new
attempt; unknown attempts retain the existing no-retry rule and pricing reserves
the configured full input context as before.

The provider request frames approved feedback as untrusted user data, with explicit
readable text, size, hash and return code. Action/boot identifiers and duplicate
base64 representations stay in broker approval custody and are not sent to the
model. Text inside the log cannot alter the developer role or authorize an effect.
Any returned single strict READ/WRITE/RUN proposal still needs its own broker grant;
a successful model response is not artifact verification.

Validation combines negative custody/transport tests and recorded provider response
contracts with an installed core/PAM VM witness. The VM selects the real captured
failure from the recorded developer workflow, checks exact readable bytes in the
native approval, rejects forged sources and PAM replay, then verifies the existing
disabled/mismatched provider policy denies dispatch with zero provider jobs/model
attempts and no grant use. This is not a live provider call or model-driven repair
proof. Those remain separate outstanding v2.1 requirements.
