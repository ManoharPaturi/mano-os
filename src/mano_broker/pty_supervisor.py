"""Root-owned cgroup lifecycle; the dropped task worker alone owns its PTY.

Preparation performs sandbox validation without allocating a PTY or starting an
application. Each input command has one delivery and one bounded acknowledgement;
uncertain delivery kills the job instead of retrying it.
"""

import base64
import json
import os
import select
import socket
import time

from .credentials import drop
from .protocol import canonical, identifier, unique_object
from .pty_session import TaskPTY, geometry
from .sandbox import command
from .state import Denied

PACKET = 8192


def send(connection, value):
    packet = canonical(value).encode()
    if len(packet) > PACKET or connection.send(packet) != len(packet):
        raise Denied("Incomplete private PTY packet")


def receive(connection):
    packet, _, flags, _ = connection.recvmsg(PACKET)
    if not packet or flags & socket.MSG_TRUNC:
        raise Denied("Lost or oversized private PTY packet")
    return json.loads(packet, object_pairs_hook=unique_object)


def worker(connection, workspace, cwd, args):
    command(workspace, cwd, args["argv"], task_pty=True)
    send(connection, dict(kind="ready"))
    if receive(connection) != dict(kind="start"):
        raise Denied("One-shot PTY start required")
    # EOF on the private socket revokes authority. cgroup kill and PDEATHSIG
    # additionally work when either broker or worker cannot service this loop.
    with TaskPTY(
        workspace,
        cwd,
        args["argv"],
        timeout=args["timeout_seconds"],
        rows=args["rows"],
        columns=args["columns"],
        revoked=lambda: False,
    ) as pty:
        offset = 0
        seen = set()
        reason = "unknown"
        try:
            while True:
                # Read first, including the last buffered bytes after process exit.
                data = pty.read()
                if data:
                    send(
                        connection,
                        dict(
                            kind="output",
                            offset=offset,
                            data=base64.b64encode(data).decode("ascii"),
                        ),
                    )
                    offset += len(data)
                code = pty.poll()
                if code is not None:
                    if data:
                        continue
                    reason = "exited"
                    break
                if not select.select([connection], [], [], 0.01)[0]:
                    continue
                value = receive(connection)
                if not isinstance(value, dict) or set(value) != {"kind", "id", "args"}:
                    raise Denied("Invalid worker operation")
                identifier(value["id"])
                operation, body = value["kind"], value["args"]
                if len(seen) >= 64 or value["id"] in seen or not isinstance(body, dict):
                    raise Denied("PTY operation quota exceeded")
                seen.add(value["id"])
                count = 0
                if operation == "write" and set(body) == {"data"}:
                    data = base64.b64decode(body["data"], validate=True)
                    if pty.input_bytes + len(data) > args["input_limit_bytes"]:
                        raise Denied("Approved PTY input budget exceeded")
                    count = pty.write(data)
                elif operation == "resize" and set(body) == {"rows", "columns"}:
                    pty.resize(**body)
                elif operation == "close" and not body:
                    pty.close("closed")
                else:
                    raise Denied("Unknown worker operation")
                send(connection, dict(kind="ack", id=value["id"], written=count))
                if operation == "close":
                    reason = "closed"
                    break
        except (OSError, ValueError, PermissionError, OverflowError):
            reason = (
                pty.reason if pty.reason in {"timed-out", "revoked", "output-limit"} else "unknown"
            )
        pty.close(reason)
        send(connection, dict(kind="finished", reason=reason, return_code=pty.return_code))


class PTYChild:
    def __init__(self, manager, admission):
        self.group = manager.create(admission.action_id, admission.limits)
        self.started = self.closed = False
        self.state, self.result = "preparing", None
        self.output = bytearray()
        self.outcome = self.ack = None
        self.pid = None
        self.connection = None
        self.timeout = json.loads(admission.request.args_json)["timeout_seconds"]
        placement_r = placement_w = -1
        parent = os.getpid()
        child = None
        try:
            self.connection, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            placement_r, placement_w = os.pipe()
            self.pid = os.fork()
            if self.pid == 0:
                try:
                    keep = {
                        0,
                        1,
                        2,
                        child.fileno(),
                        placement_r,
                        admission.workspace_fd,
                        admission.cwd_fd,
                    }
                    for entry in os.listdir("/proc/self/fd"):
                        fd = int(entry)
                        if fd not in keep:
                            try:
                                os.close(fd)
                            except OSError:
                                pass
                    if os.read(placement_r, 1) != b"p":
                        os._exit(125)
                    os.close(placement_r)
                    drop(
                        action_id=admission.action_id,
                        caller_uid=admission.caller_uid,
                        parent_pid=parent,
                    )
                    child.settimeout(2)
                    worker(
                        child,
                        admission.workspace_fd,
                        admission.cwd_fd,
                        json.loads(admission.request.args_json),
                    )
                    os._exit(0)
                except BaseException:
                    os._exit(125)
            child.close()
            child = None
            os.close(placement_r)
            placement_r = -1
            self.group.attach_root_child(self.pid)
            os.write(placement_w, b"p")
            os.close(placement_w)
            placement_w = -1
            self.connection.settimeout(5)
            if receive(self.connection) != dict(kind="ready"):
                raise Denied("Task PTY worker not ready")
            self.connection.setblocking(False)
            self.state = "prepared"
            self.prepared_deadline = time.monotonic() + 5
        except BaseException:
            self.cancel()
            raise
        finally:
            for fd in (placement_r, placement_w):
                if fd >= 0:
                    os.close(fd)
            if child is not None:
                child.close()

    def start(self, authorize):
        if (
            self.closed
            or self.state != "prepared"
            or not callable(authorize)
            or time.monotonic() >= self.prepared_deadline
        ):
            raise Denied("Live one-shot prepared PTY required")
        try:
            if authorize() is not True or time.monotonic() >= self.prepared_deadline:
                raise Denied("Fresh PTY start authority required")
            self.started = True
            send(self.connection, dict(kind="start"))
            self.state = "running"
            self.runtime_deadline = time.monotonic() + self.timeout + 5
        except BaseException:
            self.cancel()
            raise

    def _drain(self):
        # Bounded work per service sweep; never block the Root event loop.
        for _ in range(20):
            if not select.select([self.connection], [], [], 0)[0]:
                break
            value = receive(self.connection)
            kind = value.get("kind")
            if kind == "output" and set(value) == {"kind", "offset", "data"}:
                data = base64.b64decode(value["data"], validate=True)
                if (
                    type(value["offset"]) is not int
                    or value["offset"] != len(self.output)
                    or not 1 <= len(data) <= 4096
                    or len(self.output) + len(data) > 65536
                ):
                    raise Denied("Invalid PTY output bounds")
                self.output.extend(data)
            elif kind == "ack" and set(value) == {"kind", "id", "written"}:
                identifier(value["id"])
                if self.ack is not None or type(value["written"]) is not int:
                    raise Denied("Unexpected PTY acknowledgement")
                self.ack = value
            elif kind == "finished" and set(value) == {"kind", "reason", "return_code"}:
                if (
                    self.outcome is not None
                    or type(value["return_code"]) is not int
                    or value["reason"]
                    not in {"exited", "closed", "unknown", "timed-out", "revoked", "output-limit"}
                ):
                    raise Denied("Invalid PTY outcome")
                self.outcome = value
                break  # EOF is expected only after this complete packet.
            else:
                raise Denied("Invalid private worker reply")

    def poll(self):
        if self.closed:
            return None
        if time.monotonic() >= (self.runtime_deadline if self.started else self.prepared_deadline):
            self.cancel()
            return None
        try:
            if self.outcome is None:
                self._drain()
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if not pid:
                return None
            self.pid = None
            if self.outcome is None:
                self._drain()
            if not self.started or os.waitstatus_to_exitcode(status) != 0 or self.outcome is None:
                raise Denied("No complete PTY outcome")
            self._close()
            self.state = "finished"
        except (OSError, ValueError, TypeError, KeyError):
            self.cancel()
        return None

    def operate(self, operation, operation_id, args):
        if self.closed or self.state != "running" or self.ack is not None:
            raise Denied("Live PTY required")
        identifier(operation_id)
        if operation == "resize":
            geometry(**args)
        try:
            send(self.connection, dict(kind=operation, id=operation_id, args=args))
            deadline = time.monotonic() + 1
            while self.ack is None and time.monotonic() < deadline:
                self.poll()
                if self.ack is None:
                    if self.closed:
                        break
                    select.select([self.connection], [], [], 0.01)
            ack, self.ack = self.ack, None
            if ack is None or ack["id"] != operation_id:
                raise Denied("Uncertain PTY input; no retry")
            return ack["written"]
        except BaseException:
            self.cancel()
            raise

    def cancel(self):
        if not self.closed:
            self._close()
            self.state = "unknown" if self.started else "not-started"

    def _close(self):
        try:
            self.group.kill_and_close()
            if self.pid is not None:
                os.waitpid(self.pid, 0)
                self.pid = None
        finally:
            if self.connection is not None:
                self.connection.close()
            self.closed = True
