"""Fixed root socket-activated launcher; no configurable paths or CLI commands."""

import selectors
import sys
import time

from .cgroups import Manager
from .launch_controller import Controller, serve_control, serve_prepare
from .launch_transport import activated_listeners
from .service import Admission


def iteration(selector, budgets, controller):
    # Control wins when both sockets are ready, including owned cancellation.
    events = sorted(selector.select(0.05), key=lambda item: item[0].data != "control")
    for key, _ in events:
        try:
            connection, _ = key.fileobj.accept()
        except BlockingIOError:
            continue
        with connection:
            if budgets[key.data].admit(time.monotonic()):
                if key.data == "control":
                    serve_control(controller, connection)
                else:
                    serve_prepare(controller, connection)
    controller.sweep()


def run(listeners):
    manager = Manager()
    controller = Controller(manager)
    try:
        with selectors.DefaultSelector() as selector:
            for name, listener in listeners.items():
                listener.setblocking(False)
                selector.register(listener, selectors.EVENT_READ, name)
            budgets = {name: Admission(time.monotonic()) for name in listeners}
            while True:
                iteration(selector, budgets, controller)
    finally:
        try:
            controller.close()
        finally:
            manager.close()


def main():
    if len(sys.argv) != 1:
        raise ValueError("Launcher has no caller-selected commands or paths")
    listeners = activated_listeners()
    try:
        run(listeners)
    finally:
        for listener in listeners.values():
            listener.close()


if __name__ == "__main__":
    main()
