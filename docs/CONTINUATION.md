# mano-OS continuation

Original v2.1 phases 0–7 remain active and incomplete. Frozen specification:
docs/spec-v2.1.md, SHA256
6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace.
The architecture verdict is only go-for-phase1-development; no release claim.

Main through PR94: dda429d4a21981c01b5211b40429359e7a7c8afa.
PR93 proved installed recurring Root controller/timer resume with protected
policy, hidden key source and kernel network denial in the Debian CI VM.
PR94 proved the fixed provider-only Unix TLS route through a separate keyless
network UID, disabled policy/wrong-UID/key-source denial and a public certificate
handshake without HTTP, prompt, Authorization, API key or paid model invocation.
Defaults for controller, provider, pricing and egress remain disabled.

Current native-provider-key-setup work adds a fixed-path Linux Root TTY command,
Stop-latched/drained checks, non-echoed confirmation and private atomic no-replace
credential publication. No activation/rearm/restart/network call. CI must prove
actual controlling-terminal behavior using only a synthetic key, private single
link, pipe/repeat denial and unchanged policies/latch. Local tests are not proof
of those installed guest behaviors. See architecture/0079-native-provider-key-setup.md.

Merge commits only after every check on the exact final PR head succeeds, actual
relevant artifact acceptance and a fresh ready/clean/current-main gate. Never
bypass a failed probe or protection. Use CI VMs; no local VM/model/ISO downloads.
Root/service/account changes belong only in guarded disposable Debian guests.
Physical input and physical 8 GB performance are deferred, not demonstrated.
No real provider key supplied; no paid/API/model execution accepted.

Remaining: approved live provider flow and independently verified model/pricing,
full policy profiles, approval/task UI, coding delegates/PTY/MCP, GUI workflows,
hardware/physical8GB, runtime package, signed installer/ISO/updates and release.
Do not narrow completion to CI components. Preserve unknown-effect/no-retry rules.

Local checks: .venv unittest discovery with PYTHONPATH=src, Ruff, diff whitespace,
shell syntax and Python compilation. Linux-only tests must actually execute in CI.
Check disk before builds/downloads; warn below20GiB or at90%, halt large downloads
below10GiB, never delete user data. Last observation30GiB free85% on2026-10-18.
No agent /compact tool is available; use concise handoffs for automatic compaction.
The task workspace outputs/ contains the full acceptance ledger, accepted artifact
reports and authoritative operational continuation; older source notes are archived
there under continuation-history/repo-through-pr54.md.

Next checkpoint: PR95 merged d1dff576374bb2456f576b5cc523f08494abb923 after
CI39083234775 all checks success and artifact12120320000/53hashes acceptance.
Native Root TTY key setup is now demonstrated with synthetic input only; real key,
activation and live paid API flow remain pending. Crash may leave a private source
staging link; systemd copies sources, so provider link checks do not detect it.
Current prompt-intake-status work adds a read-only GTK view and fixed native status
client. It shows only queue/provisioning state, not execution completion. Slow
refreshes are off the UI thread and cannot replace a newer acknowledged request.
The GTK/AT-SPI fixture is synthetic; separate installed broker tests must prove the
production status client/native transport. Local298tests/28Linux skips pass;
final-head CI/artifact acceptance remains required. See architecture/0080.

PR96 merged2e76f5be167feea2878e3fbaa7142c9bf25600a6 after exact-final-head
CI39084715416 all success, artifact12120402273/53hashes, synthetic GTK status and
visually inspected final PNG. Current human-task-status work extends protected
native operation07 to a human/boot/prompt/task-bound read-only journal snapshot:
latest16 actions with total count and all64 bounded approval records. No args,
reason, nonce/digest/grant IDs or credentials. Existing PAM view/confirm unchanged.
GTK uses fixed labels, revision/task binding and a bounded scroll region; status
reads cannot submit, approve or execute. Approvals schema now initializes with
State, so the first empty status read needs no DDL. Local306tests pass/28Linux skips.
Installed native scope/redaction/pending/done/verified and Stop-unknown/revoked
witnesses plus separate synthetic GTK text/responsiveness/screenshot need final CI.
Full original version, real provider execution, policy profiles and release remain
incomplete. See architecture/0081-human-task-journal.md and task workspace outputs.

PR97 merged e4848e1f820f554d948cedf728f5408c4b076e93 after exact-head
CI39085949215 all success, artifact12120753199/53hashes and native journal +
separate synthetic GTK/visual evidence. Current pam-permission-profiles work adds
policy.set_profile exact native PAM approval, task-bound workspace leases and
single-use exact automatic grants; no automatic profile/budget/model disclosure.
Supervised read/health; Auto adds writes/selected development entrypoints; Full
admits additional immutable/workspace tool entrypoints inside the SAME sandbox.
PAM view explicitly shows workspace-only/no-network scope. Entry policy does not
constrain child exec; kernel workspace/IPC/network isolation remains the boundary.
Limits32 grants,900s (Full300s),300s runtime cap. New authorization/dispatch checks
lease expiry/epoch/native generation/provenance. Replacement revokes prior leases'
grants; changing mode while executing denies; running actions keep original runtime
bounds, Stop stays independent. Broker recovery invalidates profiles. No host-data
or network widening, no mode UI command/full profile product claim. Local312tests
pass/28Linux skips; native PAM/count/expiry/Full protected-path/Stop VM witnesses
pending. See architecture/0082-pam-workspace-profiles.md and workspace outputs.
