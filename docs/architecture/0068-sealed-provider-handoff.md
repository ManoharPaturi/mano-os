# Bounded sealed provider response handoff

Provider responses may exceed the public broker's 64 KiB packet limit. The
private provider-to-broker handoff sends one small metadata packet and exactly
one sealed Linux memfd, bounded by the existing 256 KiB provider response limit.
It never transports the response body as an oversized packet.

The broker receiver authenticates the kernel message UID/GID, requires exactly
one descriptor, rejects truncated/unexpected ancillary data and checks the
original task/action/boot/request digest and fresh nonce. It requires immutable
write/grow/shrink/seal locks, exact size and SHA-256. pread avoids races on the
shared descriptor offset. Every received descriptor is closed on acceptance or
rejection. The sender closes its copy even if delivery fails; no call is retried.

This transport is for the private protected provider connection only. Existing
public broker reply readers still reject all passed descriptors. No generation
operation or network profile is enabled by adding these helpers. Future installed
execution must connect this handoff to the original paid reservation and consume
it with the original expected binding and protected provider identity. A sealed
packet is custody evidence; response schema and task success need independent checks.

Linux quality tests exercise a real 250000-byte socket/memfd transfer, kernel
credentials, nonce/UID denial, mutable/multiple descriptors and descriptor leak
checks. Those tests are skipped on macOS; local compilation cannot substitute
for their final Linux CI results. No credentials or paid API calls are used.
