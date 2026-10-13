# Private launcher client

The broker uses fixed prepare/control Unix packet sockets. Socket creator
credentials must be root, and each received packet must independently carry
exactly one root UID/GID credential. A systemd activation socket creator can
have a different PID from its serving process; connection PID equality is not
assumed. The client pins the first serving PID with pidfd_open, rejects a dead
or changed serving process, and never reconnects with implicit job recovery.

Requests are bounded to the existing packet limit. Exactly two borrowed
workspace/cwd descriptors travel on prepare; control never carries descriptors.
Unexpected reply rights are closed before denial. Truncation, duplicate JSON
keys, non-boolean ok fields and missing credentials fail closed. Network calls
have an eight-second timeout; no uncertain call is retried automatically.

The existing actual root-service VM fixture now uses this implementation from
its persistent broker UID process for prepare, start, status, bounded output
and cancellation. Its grant is still explicitly an operator fixture. This PR
establishes transport reuse, not real journal authorization or task completion.
Runtime/journal integration, independent Stop, production daemon installation
and verified artifact custody remain required.
