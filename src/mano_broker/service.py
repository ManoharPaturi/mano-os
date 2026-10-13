"""Fixed-path, non-root, systemd socket-activated request service."""

import os
import socket
import sys
import time
from pathlib import Path

from .ipc import serve_connection
from .state import State

REQUEST_SOCKET = "/run/mano-broker/request.sock"
STATE_DIRECTORY = Path("/var/lib/mano-broker/runtime")


class Admission:
    """Global connection budget; rejected connections acquire no grant authority."""

    def __init__(self, now):
        self.updated = now
        self.tokens = 20.0

    def admit(self, now):
        self.tokens = min(20.0, self.tokens + max(0, now - self.updated) * 10)
        self.updated = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True


def activated_listener():
    if os.geteuid() == 0:
        raise ValueError("Broker service must not run as root")
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        raise ValueError("Expected one systemd listener")
    listener = socket.socket(fileno=3)
    if (
        listener.family != socket.AF_UNIX
        or listener.type != socket.SOCK_SEQPACKET
        or listener.getsockname() != REQUEST_SOCKET
        or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED)
    ):
        listener.close()
        raise ValueError("Unexpected systemd listener")
    for key in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        os.environ.pop(key, None)
    listener.set_inheritable(False)
    listener.settimeout(0.5)
    return listener


def notify(message):
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        raise ValueError("Expected systemd notify channel")
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
        channel.sendto(message.encode(), address)


def run(listener, state, boot_id):
    state.recover()  # Never infer success or repeat an executing action after restart.
    budget = Admission(time.monotonic())
    notify("READY=1")
    while True:
        notify("WATCHDOG=1")
        try:
            connection, _ = listener.accept()
        except TimeoutError:
            continue
        with connection:
            if budget.admit(time.monotonic()):
                serve_connection(state, connection, boot_id=boot_id)
            # Otherwise close without parsing, journaling or acquiring rights.


def main():
    if len(sys.argv) != 1:
        raise ValueError("Service has no caller-selectable paths or commands")
    with activated_listener() as listener:
        state = State(STATE_DIRECTORY)
        try:
            run(listener, state, Path("/proc/sys/kernel/random/boot_id").read_text().strip())
        finally:
            state.close()


if __name__ == "__main__":
    main()
