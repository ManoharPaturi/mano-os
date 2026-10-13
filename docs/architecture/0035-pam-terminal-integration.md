# Native PAM to real terminal integration

Extend the existing disposable broker/PAM service probe with the actual packaged
launcher service and an allocated locked task identity. Root administrative code
creates a broker/task workspace with existing ACL policy and provisions its held
directory FD through the protected broker socket. The task identity requests
terminal approval through the real request socket; the kernel supplies caller
credentials. The native approval helper authenticates the configured human using
PAM and consumes the exact pending operation binding. No direct grant insertion is
used for this flow.

Wrong password and changed approved arguments must leave the result absent.
The valid exact proposal returns durable intent, then the broker Runtime dispatches
its Registry-held descriptors to the private launcher. The test polls via the real
request socket until done, independently reads the fixture's known result file,
checks verified remains zero, checks replay has no new preparation/execution and
checks another task identity cannot query the action. All services stop before
removing this probe's temporary files/units/accounts.

The test uses a synthetic CI human password kept in process memory, never printed,
and real PAM authentication. Physical keyboard provenance remains null and the
physical approval UI is not exercised. Reading the known fixture result is an
operator observation, not the sealed artifact verification protocol. Native Stop
while the broker is frozen, resource-limit selection and full golden tasks remain
required. This evidence is pending until the actual VM run passes.
