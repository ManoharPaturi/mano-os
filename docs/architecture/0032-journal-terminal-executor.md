# Durable journal terminal execution

The trusted Executor accepts a broker-issued action identifier and retrieves its
original strict request from the journal. It uses the Registry-held workspace and
cwd lease, not paths or descriptors supplied by a public execution request.

Preparation sends the original action and two held descriptors to the private
launcher. It does not execute task argv. The adapter checks grant revocation,
expiry, epoch, boot, exact approved arguments, terminal capability and resource
budget before preparation and again after that blocking round trip. Registry.start
commits the executing journal transition before the Start message is sent.
A lost acknowledgement becomes unknown; no uncertain start is retried.

Polling checks live authority before querying the owned job. Expiry, revocation,
Stop or transport failure triggers best-effort cancellation and unknown state.
An explicit finished integer exit code becomes done for zero, failed otherwise.
Success stays unverified; artifact custody remains a separate protocol.
Stop cancellation here depends on the broker being scheduled; independent native
Stop for a frozen broker remains required and is not established by this adapter.

The current launcher has fixed 128 MiB/24 PID/20 percent CPU ceilings. Grants below
those ceilings are rejected without preparation; configurable lower kernel limits
remain required. The adapter never silently runs a narrower grant with larger limits.

Local tests use a real SQLite journal and instrumented transport to check durable
Start ordering, repeat denial without disturbing a running action, revocation during
prepare, lost Start acknowledgement, Stop cancellation and lower-budget rejection.
The actual root-service VM probe adds real Registry/native descriptor pins and this
adapter in the persistent broker process, real completion/output and Stop cancellation.
Its grant originates from an operator fixture; no PAM approval or public Runtime
execution integration is claimed. Production daemon/Runtime wiring and frozen-broker
Stop acceptance remain required.

The first VM run rejected a journal created under the setgid/ACL task workspace.
The fixture now provisions a separate broker-owned mode0700 journal root under
/run/mano-journal-ci before starting the root service. Task-visible workspace
inheritance cannot affect journal permissions. Existing State ownership/mode
checks remain unchanged; no task workspace contains the broker journal.
