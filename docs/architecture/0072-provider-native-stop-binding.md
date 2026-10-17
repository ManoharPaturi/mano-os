# Original model authority follows native Stop generation

A prepared model job can wait while the broker's cached journal generation is stale.
Rearming Stop must not make a previously approved job usable again.

Grants now persist the native generation observed at issuance. Legacy model grants
are revoked on schema migration; an unbound generation cannot dispatch. Claiming a
provider job carries the original grant generation, never the later journal value.
The provider independently reads the Root-owned native Stop snapshot before loading
its key and again immediately before invoking the fixed HTTPS helper. A latched,
missing, corrupt, pending, or different generation fails closed. The shared reader
has no Stop write or rearm authority.

Regression tests cover Stop/rearm, stale journal updates, legacy migration, malformed
generations and read failure before provider invocation. The guarded Debian probe
reads the actual native snapshot as the provider UID in the installed service's
mount namespace. That witness establishes read access, not paid provider execution.
The service still has no Internet access and generation remains disabled by default.
Native Stop remains responsible for killing an already-running provider cgroup;
a read check does not promise atomicity across a later Stop event and an HTTP call.
