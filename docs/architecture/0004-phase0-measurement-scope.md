# ADR 0004: distinguish Phase 0 VM measurements from Phase 6 hardware validation

Status: source-specification alignment; actual counter acceptance remains CI-gated.

The supplied v2.1 Phase 0 requires a Debian VM with an 8 GB ceiling, measured
resource/compatibility observations and a go/no-go decision. Actual physical 8 GB
laptop responsiveness and OOM survival are Phase 6 requirements. The early lab
tracker incorrectly marked physical 8 GB performance as its P0-12 pending probe.
That would block later engineering on a requirement assigned to a later phase.

Record actual pre/post guest memory, Sway RSS/high-watermark and launch-to-output
latency, observed systemd memory/process/CPU limits and probe-suite elapsed time.
Keep human-compositor memory, verified product-task success rate and monetary
costs null because these are not measured or implemented. These are lab primitive
measurements, not performance claims for a finished mano runtime.

P0-12 is accepted only when the required live observations exist, while the
architecture remains NO-GO for the still-missing GUI/authority proofs. Physical
8 GB performance and firmware/installer boot remain explicit deferred project
release gates. Project completion still requires their real validation.
