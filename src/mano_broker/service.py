"""Fixed-path, non-root, systemd socket-activated request service."""

import os
import selectors
import socket
import sys
import time
from pathlib import Path

from .control import serve_control
from .ipc import serve_connection
from .state import State

SOCKET_PATHS = {
    "request": "/run/mano-broker/request.sock",
    "control": "/run/mano-broker/control.sock",
}
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


def activated_listeners():
    if os.geteuid() == 0:
        raise ValueError("Broker service must not run as root")
    names = os.environ.get("LISTEN_FDNAMES", "").split(":")
    if (
        os.environ.get("LISTEN_PID") != str(os.getpid())
        or os.environ.get("LISTEN_FDS") != "2"
        or len(names) != 2
        or set(names) != set(SOCKET_PATHS)
    ):
        raise ValueError("Expected named request and control systemd listeners")
    listeners = {}
    try:
        for fd, name in enumerate(names, start=3):
            listener = socket.socket(fileno=fd)
            listeners[name] = listener
            if (
                listener.family != socket.AF_UNIX
                or listener.type != socket.SOCK_SEQPACKET
                or listener.getsockname() != SOCKET_PATHS[name]
                or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
                or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED)
            ):
                raise ValueError("Unexpected systemd listener")
            listener.set_inheritable(False)
            listener.setblocking(False)
        for key in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
            os.environ.pop(key, None)
        return listeners
    except BaseException:
        for listener in listeners.values():
            listener.close()
        raise


def notify(message):
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        raise ValueError("Expected systemd notify channel")
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
        channel.sendto(message.encode(), address)


def run(listeners, state, boot_id):
    state.recover()
    # Independent admission budgets; give protected control priority when both ready.
    budgets = {name: Admission(time.monotonic()) for name in listeners}
    with selectors.DefaultSelector() as selector:
        for name, listener in listeners.items():
            selector.register(listener, selectors.EVENT_READ, name)
        notify("READY=1")
        while True:
            notify("WATCHDOG=1")
            events = sorted(selector.select(0.5), key=lambda item: item[0].data != "control")
            for key, _ in events:
                try:
                    connection, _ = key.fileobj.accept()
                except BlockingIOError:
                    continue
                with connection:
                    if budgets[key.data].admit(time.monotonic()):
                        handler = serve_control if key.data == "control" else serve_connection
                        handler(state, connection, boot_id=boot_id)


def main():
    if len(sys.argv) != 1:
        raise ValueError("Service has no caller-selectable paths or commands")
    listeners = activated_listeners()
    try:
        state = State(STATE_DIRECTORY)
        try:
            run(listeners, state, Path("/proc/sys/kernel/random/boot_id").read_text().strip())
        finally:
            state.close()
    finally:
        for listener in listeners.values():
            listener.close()


if __name__ == "__main__":
    main()
