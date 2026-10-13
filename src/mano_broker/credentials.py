"""Fixed own-child credential transition after cgroup placement; no executor."""

import ctypes
import grp
import os
import signal
import sys
from pathlib import Path

from .cgroups import UNIT
from .launch_admission import task_account
from .protocol import identifier
from .state import Denied


def drop(*, action_id, caller_uid, parent_pid):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise Denied("Root launcher child required")
    identifier(action_id)
    if type(parent_pid) is not int or parent_pid <= 0 or os.getppid() != parent_pid:
        raise Denied("Original supervisor parent required")
    if (
        Path("/proc/self/cgroup").read_text().strip() != "0::" + UNIT + "/task-" + action_id
        or Path(f"/proc/{parent_pid}/cgroup").read_text().strip() != "0::" + UNIT + "/control"
    ):
        raise Denied("Place own child in task cgroup before credential drop")
    account = task_account(caller_uid)
    group = grp.getgrnam("mano-request")
    libc = ctypes.CDLL(None, use_errno=True)
    os.setgroups([group.gr_gid])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)

    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    libc.capset.argtypes = (ctypes.POINTER(Header), ctypes.POINTER(Data))
    libc.capset.restype = ctypes.c_int
    header = Header(0x20080522, 0)
    data = (Data * 2)()
    if libc.capset(ctypes.byref(header), data) != 0:
        raise OSError(ctypes.get_errno(), "Failed to clear child capabilities")
    # UID changes clear PDEATHSIG, so set it after dropping and close the race by
    # rechecking PPid. No task argv may execute until this function succeeds.
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(1, signal.SIGKILL, 0, 0, 0):
        raise OSError(ctypes.get_errno(), "Failed to constrain launcher child")
    fields = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    if (
        os.getppid() != parent_pid
        or fields["Uid"].split() != [str(account.pw_uid)] * 4
        or fields["Gid"].split() != [str(account.pw_gid)] * 4
        or set(os.getgroups()) != {group.gr_gid}
        or fields["NoNewPrivs"].strip() != "1"
        or any(
            int(fields[name].strip(), 16) != 0 for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")
        )
    ):
        raise Denied("Credential transition verification failed")
