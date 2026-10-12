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
    except OSError:
        time.sleep(0.02)
