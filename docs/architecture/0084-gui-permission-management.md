# Human permission management without GUI confirmation authority

The prompt's Permissions button is enabled only for an acknowledged request with
a provisioned task. A modal window is bound to that exact prompt/task/selection
revision. It reads native operation09 status, shows recorded mode and availability
for new automatic grants, and offers bounded Supervised/Auto/Full Access requests
through operation08. Scope stays workspace-only, with no network or automatic
model spending/disclosure. Exhausted counts do not cancel issued/running work;
the window directs the human to independent Stop for revocation.

Selecting a radio option changes only the proposed request. Duration/count/timeout
are bounded by the shared profile schema; Full Access clamps duration to300s.
Requesting creates a pending approval. The window displays its ID and a fixed
human-terminal review command. No password or confirmation widget exists, and no
confirmation, rearm, execution or model route is called. Actual PAM stays in the
protected human terminal, where broker-owned terms are reviewed independently.
An already-approved idempotent response is labelled historical and asks for a
status refresh rather than claiming current authority.

Status and request operations run off the GTK main thread through one single-
inflight worker. A validated initial status is required before requesting. On an
uncertain request, the exact args/key remain; controls lock and an explicit same-
request retry is offered. Changing limits cannot silently create another request.
Wrong prompt/task or malformed responses preserve the last acknowledgement.
Closing the window or changing the parent selection makes late replies inert.
The server may retain an already submitted pending challenge; closing the window
neither approves it nor claims to cancel it. Backend ownership/live-runtime/PAM
checks remain authoritative regardless of GUI state.

Pure view-model tests cover missing initial status, exact uncertain retries,
argument changes, task substitution, malformed fields/bounds, unsolicited replies
and historical approvals. Existing worker tests retain single-inflight/UI-thread
completion semantics. Real Debian GTK/AT-SPI tests must open the window, edit spin
values, clamp Full Access duration, select Auto, request once, observe pending-only
state, verify no password field and responsive ticks during slow read/request,
close during a second slow read, reject its different late status, and preserve
the original submission count and cross-session focus canary.
Reports are atomically published by the synthetic fixture.

The UI fixture injects local synthetic status/request data, explicitly labelled in
human-prompt.json. It is not a full GUI-to-live-broker claim. The production native
clients and PAM/Stop/restart path retain their independent installed VM witnesses.
The new human-permissions.png is included among referenced artifact hashes.
Final-head acceptance must verify its hash and visually inspect both the prompt
and modal screenshots. Physical keyboard, broader host/network scope, integrated
trusted approval UI, paid-provider and original release gates remain unfinished.
