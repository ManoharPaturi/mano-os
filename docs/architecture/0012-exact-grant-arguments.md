# ADR0012: grants bind exact operation arguments

Status: candidate until current-head CI. Trusted PAM integration remains next.

A capability/resource pair alone is insufficient for request-bound approval: an
agent could reuse files.read on a different path or terminal.run with changed argv.
Every grant now requires approved_args, strictly validated through ActionRequest's
operation schema. The protected grant stores canonical argument JSON. Proposal
reservation and dispatch both require identical arguments. Object-key ordering is
irrelevant; path, argv, cwd, timeout and write content changes are denied. Count,
expiry, task/caller/resource/boot identity, revocation and budgets remain enforced.
A smaller timeout is also a different approved operation in this exact-grant mode.

The trusted issuance API still requires approved_human_uid and approved_args. It
is not a public endpoint or evidence of PAM authentication by itself. The next
separate approval channel must render broker-owned exact arguments, authenticate
the human via PAM, bind nonce/task/operation/expiry and atomically consume approval.
Broader automatic/multi-operation grant profiles will need explicit policy scope
validation; this change does not silently introduce wildcard templates.

Existing journals without the new argument column are upgraded transactionally:
all legacy grants revoked, executing actions unknown, queued intents failed, one
migration event recorded. History and identifiers are retained, with no deletes or
replay. Old rows can still be inspected/idempotently returned as prior state, but
cannot authorize fresh operations or dispatch. Reopening does not repeat migration.
This is a safety-relevant schema migration tested on SQLite, not a power-loss proof.

Unit tests cover changed argv/cwd/timeout, file path/content, valid empty writes,
malformed/out-of-budget approval templates, and legacy executing/queued recovery.
Debian library probe exercises actual legacy-column migration and no new authority.
Real IPC adds a changed-target attack; real service requires changed-target denial
before a fresh valid request, proving the denial did not exhaust the remaining use.
Full previous VM suites, credential attacks, restart and stop assertions remain.

Resource paths remain syntax-checked rather than FD-pinned. Exact argument binding
is necessary but cannot prevent filesystem races or supply a sandbox. Next: trusted
request-bound PAM channel, pinned resources, executor/native stop/verifier and original
Phase1 minimal agent/golden OS-boundary gate. Full v2.1 scope remains active.
