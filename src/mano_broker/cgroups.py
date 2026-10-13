"""Fixed delegated launcher cgroup custody. Root service library, no endpoint.

Only the named service's own root child may be attached before credential drop.
No caller-selected cgroup paths, resource limits or arbitrary PID migration.
"""

import os
import stat
import sys
import time
from pathlib import Path

from .limits import Limits
from .protocol import identifier
from .state import Denied

UNIT = "/system.slice/mano-launcher.service"
ROOT = Path("/sys/fs/cgroup") / UNIT.lstrip("/")


def context(*, initialized=False):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise Denied("Trusted Linux root launcher service required")
    expected = UNIT + ("/control" if initialized else "")
    if Path("/proc/self/cgroup").read_text().strip() != "0::" + expected:
        raise Denied("Only the fixed delegated launcher service may manage tasks")
    for path in (ROOT, *ROOT.parents):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Denied("Untrusted delegated cgroup directory")
    if not any(
        line.split()[4] == "/sys/fs/cgroup" and line.split(" - ", 1)[1].split()[0] == "cgroup2"
        for line in Path("/proc/self/mountinfo").read_text().splitlines()
    ):
        raise Denied("cgroup v2 delegation required")


def write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        data = value.encode("ascii")
        if os.write(fd, data) != len(data):
            raise OSError("Short cgroup control write")
    finally:
        os.close(fd)


class TaskGroup:
    def __init__(self, manager, action_id):
        identifier(action_id)
        self.manager = manager
        self.action_id = action_id
        self.path = ROOT / ("task-" + action_id)
        self.closed = False

    def attach_root_child(self, pid):
        context(initialized=True)
        if self.closed or type(pid) is not int or pid <= 0:
            raise Denied("Live own child required")
        fields = dict(
            line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines()
        )
        if (
            int(fields["PPid"].strip()) != os.getpid()
            or fields["Uid"].split() != ["0", "0", "0", "0"]
            or Path(f"/proc/{pid}/cgroup").read_text().strip() != "0::" + UNIT + "/control"
        ):
            raise Denied("Only this manager's blocked root child may be moved")
        # The parent must not reap this owned child before attach; an unreaped
        # child PID cannot be reused. Child executes no task code before GO.
        write(self.path / "cgroup.procs", str(pid))

    def populated(self):
        values = dict(
            line.split() for line in (self.path / "cgroup.events").read_text().splitlines()
        )
        return values["populated"] == "1"

    def kill_and_close(self):
        context(initialized=True)
        if self.closed:
            return
        write(self.path / "cgroup.kill", "1")
        deadline = time.monotonic() + 5
        while self.populated():
            if time.monotonic() >= deadline:
                raise TimeoutError("Owned task cgroup remains populated")
            time.sleep(0.01)
        self.path.rmdir()
        self.closed = True
        self.manager.jobs.pop(self.action_id)


class Manager:
    def __init__(self):
        context()
        if set((ROOT / "cgroup.procs").read_text().split()) != {str(os.getpid())}:
            raise Denied("Launcher must start alone in its delegated cgroup")
        if not {"cpu", "memory", "pids"} <= set((ROOT / "cgroup.controllers").read_text().split()):
            raise Denied("Required delegation controllers unavailable")
        self.jobs = {}
        self.seen = set()
        self.closed = False
        control = ROOT / "control"
        control.mkdir(mode=0o700)
        write(control / "cgroup.procs", str(os.getpid()))
        write(ROOT / "cgroup.subtree_control", "+cpu +memory +pids")
        write(control / "memory.max", str(64 * 1024 * 1024))
        write(control / "pids.max", "8")
        write(control / "cpu.max", "20000 100000")

    def create(self, action_id, limits=None):
        context(initialized=True)
        if limits is None:
            limits = Limits()
        if not isinstance(limits, Limits):
            raise Denied("Typed kernel limits required")
        limits = Limits.parse(limits.body())
        identifier(action_id)
        if self.closed or len(self.jobs) >= 2 or len(self.seen) >= 64 or action_id in self.seen:
            raise Denied("Task group quota or one-shot action exhausted")
        self.seen.add(action_id)  # Failed creation also cannot replay this ID.
        task = TaskGroup(self, action_id)
        task.path.mkdir(mode=0o700)
        try:
            write(task.path / "memory.max", str(limits.memory_bytes))
            write(task.path / "memory.oom.group", "1")
            write(task.path / "pids.max", str(limits.pids))
            write(task.path / "cpu.max", str(limits.cpu_percent * 1000) + " 100000")
            memory = int((task.path / "memory.max").read_text())
            pids = int((task.path / "pids.max").read_text())
            quota, period = map(int, (task.path / "cpu.max").read_text().split())
            if (not 0 <= memory <= limits.memory_bytes or pids != limits.pids
                    or period != 100000 or not 0 < quota <= limits.cpu_percent * 1000):
                raise Denied("Kernel limits exceed approved resource ceilings")
        except BaseException:
            task.path.rmdir()  # Only the fresh empty cgroup, never a user path.
            raise
        self.jobs[action_id] = task
        return task

    def close(self):
        context(initialized=True)
        if self.closed:
            return
        for task in list(self.jobs.values()):
            task.kill_and_close()
        write(ROOT / "cgroup.subtree_control", "-cpu -memory -pids")
        write(ROOT / "cgroup.procs", str(os.getpid()))
        (ROOT / "control").rmdir()
        self.closed = True
