# Coherent checkpoint, intent and dpkg lock handoff

Status: privileged-executor transaction plumbing, no new package authority.

Root resolution/archive custody holds dpkg's frontend/backend and APT locks.
Starting dpkg while the parent still owns the backend lock would fail. Releasing
all locks would instead admit competing package managers between validation and
effects. Use Debian's documented frontend protocol: keep the frontend lock, release
only the backend, run the child with `DPKG_FRONTEND_LOCKED=1`, then reacquire the
backend after the child terminates. Direct dpkg without this frontend-owned marker
must still fail on the retained frontend lock.

`recovery.locked()` now yields a process/thread-owned `PackageLocks` scope. Nested
or concurrent lock scopes still fail before opening descriptors. Its backend
handoff context releases only that lock and reacquires it nonblocking on exit,
including exceptional exits. A failed reacquire never marks the scope ready.
Expired, wrong-process/thread and nested handoff objects cannot release locks.
The object is internal ownership bookkeeping, not a transferable authority token.

`recovery.create_locked` and `package_attempts.begin_locked` require an active owned
scope with the backend still held. They create the checkpoint and immutable intent
without reopening package lock files or releasing an outer lock. Public Root
administrative `create` retains its foreground controlling-TTY and Debian13 guards;
unsupported filesystems fail before recovery-lock access. Existing library wrappers
take their own scope. The locked variants require Debian13 Root and cannot run
outside a live owned scope or during a backend handoff. No public endpoint or new
grant is introduced.

The disposable CI driver preserves the original Root-terminal checkpoint for its
existing signed-package/recovery test. After that separate signed-package change,
it creates an additional checkpoint and attempt intent under one scope immediately
before the controlled unsigned dpkg/postinst effect. During handoff, another process
must acquire the released backend, while direct dpkg must fail on the frontend.
Checkpoint and intent calls must refuse while the backend is released. The actual
dpkg child then runs with the supported marker, reaches its controlled postinst,
and is pinned/frozen/interrupted as before. A separate fixed-file C observer uses `F_GETLK` to identify the driver
as frontend owner and actual dpkg PID as backend owner, using the opened lock files
rather than comparing procfs inode/device text with filesystem stat values. After termination, the
driver must regain the backend. The attempt stays unknown across real recovery
boot; recovery still targets the original earlier checkpoint, so the intent's
checkpoint is explicitly distinct from the selected recovery target. Neither
record is silently rewritten or treated as installed.

The specification's trusted broker remains the policy authority. The eventual
apply capability must have its own exact native PAM approval, separate from the
forecast, and a narrowly authenticated Root helper. A parallel Root policy/grant
issuer is not required by this change. Native cancellation of a real privileged
executor, process/capability/IPC/filesystem isolation, authorized acquisition,
truthful space admission, verified postconditions and operator recovery are still
required before exposing package effects to broker requests. The existing CI effect
is an unsigned controlled fixture, not a product apply endpoint or production
maintainer-script validation.

Primary references: [Debian dpkg's frontend marker](https://manpages.debian.org/trixie/dpkg/dpkg.1.en.html)
and [python-apt's backend lock handoff API](https://apt-team.pages.debian.net/python-apt/library/apt_pkg.html).
