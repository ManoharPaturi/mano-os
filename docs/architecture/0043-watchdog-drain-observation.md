# Watchdog process-drain observation

Post-main51 CI38443276815 failed when the Phase0 observer saw populated0 and a
Stop latch, then immediately saw an original task PID neither exited nor zombie.
The original inner process identity was not recorded, so its precise state/PID
reuse cannot be reconstructed from that run. Do not label the failure transient
or rerun it without a change.

The observer now requires cgroup-empty, latch-present AND every recorded task PID
exited-or-zombie before leaving the same15-second deadline. The original survivor
assertions remain. Timeout diagnostics include survivor State/UID/PPid, without
command arguments, and permission/I/O errors still fail. This does not relax Stop
behavior or treat cgroup population alone as process-exit proof.

The portable process tests and all prior VM probes remain; real watchdog acceptance
is pending CI. No Stop security, resource or watchdog timeout is changed.
