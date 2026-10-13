# Native Stop authority consumption

Broker and launcher units now require the native Stop service to initialize its
root-owned authority file. The read-only Python consumer validates all parent
ownership/directory modes and the no-follow regular file's root owner, mode0644,
single link, bounded size and exact armed/latched content. Missing, changing or
malformed authority fails closed; neither broker nor launcher can rearm it.

The root Controller checks armed state before preparation and again after child
preparation. If Stop trips during preparation, it cancels the blocked child and
closes owner custody. Start's fresh authority callback checks the independent
root latch. A native Stop racing Start acts on the already-created task cgroup;
no Root group created after Stop can pass both preparation/start checks.

Runtime consumes the native state before dispatch and ticks. The service also
consumes it before protected approval-control handling. On first observed trip
(or unavailable native authority), State.emergency_stop advances the journal
epoch, latches it, revokes grants and settles intent/executing conservatively.
Repeated observations do not repeatedly advance the epoch. An armed native file
does not automatically clear a previously latched journal. Startup recovery
preserves Stop; there is no model or restart-triggered rearm.

The disposable tests provision actual native service/state before Root/controller
execution. After the existing frozen-broker/launcher native kill test, they check
unknown history, old request denial, pending approval revocation, a trusted broker
UID private preparation denial, and SIGKILL broker recovery without rearm. Portable
tests check malformed/missing/root-metadata state denial and no automatic rearm.
Actual integration evidence is pending CI.

PAM-bound rearm, monotonic native Stop generations and complete native state crash
recovery remain required. This PR cannot claim the complete Stop contract or full
v2.1 completion. Physical input provenance, sealed effect verification and later
golden/OS/performance gates remain unproved here.
