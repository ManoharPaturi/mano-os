# Responsive human prompt submission

The GTK Send/Enter handler previously waited for native socket acknowledgement on
the UI thread, potentially freezing the window for the socket timeout. It now
starts one daemon worker for the bounded transport call and posts completion via
GLib idle dispatch. Widgets and the busy state change only on the UI thread.
While in flight, Send and the entry are disabled. Duplicate invocations are
ignored. Acknowledged input clears; uncertain input remains available for an
explicit retry with the existing idempotency key. No automatic retry is added.
Private exception text is not displayed. Empty or oversized input is rejected
before starting the worker.

Unit tests hold a slow transport call, verify one in-flight request and callback
thread ownership, and confirm uncertain calls are neither retried nor exposed.
The existing GTK fixture uses an explicitly injected one-second local recorder
delay and requires multiple GLib timer ticks during it. This proves event-loop
progress during a slow acknowledgement, not physical input provenance or the
full system latency target. Native production transport remains separately
covered by its installed human-session witness.
