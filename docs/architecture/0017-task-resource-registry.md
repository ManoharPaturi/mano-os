# ADR0017: live task resource registry and prepared descriptors

Status: candidate until Linux unit/real Debian CI. Trusted provisioning wire and
executor integration remain next; this is a private broker library.

Register accepts an already trusted directory FD plus human/caller/boot identity,
mints a fresh opaque ID and retains descriptor custody. It never accepts an agent
root path or caller-selected ID. Up to32 resources and32 prepared leases bound memory
and FD use. After first valid task authorization, a resource is bound to that task;
a second task needs explicit fresh provisioning even for the same directory.

Prepare validates live resource/task/caller/human/boot before consuming a grant,
then atomically reserves intent using the existing strict exact-grant checks. It
pins read targets or terminal cwd. Write preparation pins the parent, then resolves
an existing target relative to that retained parent (not the original parent name).
Absent targets record only leaf name plus parent FD; no file is created yet. Future
writers must use O_EXCL creation or the pinned existing inode. Quota denial rolls
back new reservation, while existing replay can return prior state without new FDs.

Failed pinning closes transient descriptors and records failed intent. Replays never
produce another prepared lease. Start is trusted-only, rechecks expiry/revocation/
boot through State.start and allows one dispatch-state transition; no command runs.
Release/close closes held target/cwd/parent/root FDs. A fresh registry after restart
does not know old IDs; it cannot rebuild authority from journal/model paths.

The public broker still reserves metadata intents without this registry: production
propose must be routed through registry preparation before reservation when trusted
FD provisioning is integrated. Do not feed already-reserved public intents into this
API and infer they acquired descriptor authority. There is no public registration,
executor or automatic restart reopening in this PR.

Tests cover actual Linux descriptor retention, grant/replay/one-start/stop checks,
wrong caller/boot/lost registry, cross-task resource denial, new-write preparation,
failed symlink pinning and a forced parent replacement between pin operations. Real
Debian adds resource/task/grant preparation, original target, no new descriptors on
replay, one dispatch-state transition, close and lost-registry denial, using real
monotonic time. It records no operation executed, not fake command success.

Next: narrowly authenticated provisioning, public-propose integration, sandbox/
cgroups/seccomp/Landlock and native stop/verifier, minimal prompt/model/LangGraph and
original Phase1 golden OS-boundary gate. All original v2.1 later scope remains active.
