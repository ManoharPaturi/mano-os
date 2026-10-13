"""Bounded by actual cgroup pids/memory/CPU limits; disposable CI only."""

import os
import time

children = []
while True:
    try:
        pid = os.fork()
        if pid == 0:
            time.sleep(600)
            raise SystemExit(0)
        children.append(pid)
        # Fill the real kernel-enforced limit without a single burst of page-table
        # copies monopolizing this two-vCPU nested CI guest. Keep attempting forks
        # after saturation, so the stop test still runs under sustained pressure.
        time.sleep(0.01)
    except OSError:
        time.sleep(0.02)
