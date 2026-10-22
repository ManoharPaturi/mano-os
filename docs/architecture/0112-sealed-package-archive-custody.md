# Exact signed archive custody before privileged package effects

Status: executor prerequisite; no installation or network acquisition authority.

A package filename is not content identity, and an open cache file can still be
modified after hashing. The future executor needs immutable bytes matching the
exact signed-catalog transaction, held while package-manager locks remain active.

`mano_runtime.package_archives.verified_archives` enters the existing fresh Root
resolution context. It scans only the fixed Root-owned `/var/cache/apt/archives`
directory while dpkg/APT locks remain held. Inputs must be trusted Root-owned,
single-link regular files without symlink traversal. Directory inventory and
scanned bytes are bounded. Only expected archive sizes are read. Each candidate
is copied to a close-on-exec memfd while hashing; source identity/size/timestamps
must remain stable. Exact SHA256 and size must match the freshly re-resolved plan.
The sealed copy's dpkg-deb Package/Version/Architecture must match that same row.
Duplicate or missing content fails closed; filenames never select authority.

Before metadata inspection or yielding, require all four kernel seals: WRITE,
GROW, SHRINK and SEAL. The Root caller receives only context-owned descriptors and
diagnostic metadata. Consumption must occur inside this context; descriptors close
on normal and exceptional exits. Later cache mutation cannot change the sealed
bytes. Native Stop is checked during copying and before yield; trusted catalog
custody is rechecked before yield. No archive is fetched, no missing file triggers
a fallback, and no package is unpacked or configured by this module.

Initial staging admission is at most 64 MiB per archive, 128 MiB total sealed
bytes, 256 MiB scanned bytes and 256 cache entries. Larger transactions are refused
for explicit resource-policy work, not silently split or retried. These are memory
staging limits, not an installation peak-space estimate. Installation peak remains
unknown: compressed archive bytes and net installed growth cannot bound arbitrary
maintainer-script writes. Full apply still needs approved resource/space admission,
reserve and ENOSPC handling. This is not a decision to make the final installer
offline-only; bounded, separately authorized acquisition remains unfinished.

The guarded disposable Root CI fixture explicitly downloads fixed requested
versions outside the product code. It must observe unchanged package status. Then
actual signed Debian archives must match hashes/metadata, Root writes/truncations
to sealed FDs must fail, and mutating the cache must leave sealed bytes unchanged.
Corrupt cache content, a fresh CI symlink and temporarily missing content must be
rejected. Source bytes are restored; only newly created CI fixture paths are
removed. All context FDs must close and exception paths must not leak descriptors.
Local Linux tests separately exercise actual memfd sealing without Root; those
tests skip on macOS. Local mocked admission tests are not native Root evidence.

The CI download is fixture setup, not product download approval. Root calculation
and dpkg-deb metadata processes remain trusted/unconfined internal subprocesses;
this adds no broker service, socket, setuid program, apply grant or PAM consent.
Before broker exposure, the executor still needs process/capability/IPC/filesystem/
resource/Stop-domain isolation, exact fresh native approval, same-scope checkpoint
and attempt journal, verified postconditions and durable Stop/crash/boot outcomes.
No native Stop cancellation of a frozen archive stage, production maintainer-script
execution, full installation or physical validation is claimed here.
