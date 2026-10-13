"""Fixed private socket activation validation for the root launcher."""

import os
import socket

from .state import Denied

PATHS = {
    "prepare": "/run/mano-launcher/prepare.sock",
    "control": "/run/mano-launcher/control.sock",
}


def activated_listeners():
    if (
        os.geteuid() != 0
        or os.environ.get("LISTEN_PID") != str(os.getpid())
        or os.environ.get("LISTEN_FDS") != "2"
    ):
        raise Denied("Fixed root launcher activation required")
    names = os.environ.get("LISTEN_FDNAMES", "").split(":")
    if len(names) != 2 or set(names) != set(PATHS):
        raise Denied("Unknown launcher descriptor names")
    listeners = {}
    try:
        for fd, name in enumerate(names, 3):
            listener = socket.socket(fileno=fd)
            listeners[name] = listener
            if (
                listener.family != socket.AF_UNIX
                or listener.type != socket.SOCK_SEQPACKET
                or listener.getsockname() != PATHS[name]
                or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
                or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED)
            ):
                raise Denied("Untrusted launcher listener")
            os.set_inheritable(fd, False)
        for key in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
            os.environ.pop(key, None)
        return listeners
    except BaseException:
        for listener in listeners.values():
            listener.close()
        raise
