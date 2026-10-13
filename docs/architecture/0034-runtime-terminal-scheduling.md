# Broker Runtime terminal scheduling

The non-root broker service now supplies the fixed private launcher client to
Runtime. An authorized fresh terminal proposal receives its durable intent reply
before execution. Its broker-issued action ID enters a process-local queue once.
Idempotent replay returns existing journal metadata and does not enqueue again.
The existing Registry quota bounds held pending descriptors; two active jobs
match the launcher's concurrent quota. No public Start or grant mutation API is added.

After protected control and request handling, the service ticks Runtime: poll
active jobs and launch at most one queued action with the trusted Executor.
Executor rechecks live authority after preparation and commits executing before
Start. Dispatch failures are settled durably, not automatically rescheduled.
Shutdown attempts cancellation, marks uncertain work appropriately, closes leases
and the launcher pidfd. Startup retains the existing epoch renewal/revocation and
unknown recovery; process-local queues and jobs are never restored from model paths.

The existing watchdog is unchanged. Private RPCs remain bounded and synchronous;
a stuck call can trigger the broker watchdog and conservative restart recovery.
This does not establish latency or independent native Stop during a frozen broker.
An asynchronous transport and native Stop integration remain acceptance work.

Portable tests check reply-before-dispatch, one enqueue on replay, concurrency
backpressure and no automatic retry. The disposable installed-launcher probe now
uses actual Runtime proposal scheduling, journal, Registry and executor. It passes
explicit operator caller metadata to Runtime rather than testing kernel request
socket identity, and operator grants rather than PAM authorization. Both limitations
are explicit in the report. Actual broker request/PAM integration remains required.
