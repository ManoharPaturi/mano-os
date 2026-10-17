# Bounded provider transactions without blocking broker ticks

The existing fixed provider client waits for up to forty seconds. Calling it from
the broker event loop would delay approvals, terminal scheduling and journal Stop
synchronization. ProviderWorker instead owns at most two nonblocking Unix packet
sockets and polls readiness with a zero timeout, on the journal's owning thread.
There are no worker threads, copied SQLite connections or child-held journal writers.

Launch validates separate service identities and the Root listener, reads only the
Root pricing credential, prepares/reserves and claims exactly once, then sends one
packet. A full listener or send buffer fails immediately without retry. A failed
send after claim retains the full reservation as unknown. Poll independently reads
native Stop, checks the original grant and forty-second deadline, and receives only
when readable. Missing Stop state, Stop/rearm, expiry, failed receipt and shutdown
close the original connection and preserve uncertain effects without a second call.
The fixed provider's independent thirty-five-second kill bound remains unchanged.
Closing a broker socket is not a substitute for the native provider cgroup kill.

This commit supplies the internal scheduler adapter and regression tests. It does
not register model.plan in the public Registry, change the recurring core scheduler,
enable provider generation or permit Internet access. Installed event-loop wiring
and positive end-to-end execution are separate acceptance gates still to implement.
