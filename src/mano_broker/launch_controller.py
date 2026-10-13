"""Bounded private job custody and broker-only control library; no listener.

Control start trusts the authenticated broker assertion. Broker journal/grant
coupling is a separate integration gate, not established by this library.
"""

import base64
import json
import os
import pwd
import secrets
import select
from dataclasses import dataclass

from .ipc import Peer, receive
from .launch_admission import receive as receive_admission
from .protocol import canonical, identifier, unique_object
from .runner import OUTPUT_LIMIT
from .state import Denied
from .stop_state import require_armed
from .supervisor import Child


@dataclass
class Record:
    action_id: str
    owner: object
    owner_fd: int
    child: object


class Controller:
    def __init__(self, manager, *, stop_check=require_armed):
        self.manager = manager
        self.instance_id = secrets.token_hex(16)
        self.records = {}
        self.stop_check = stop_check

    def actor(self, peer):
        if not isinstance(peer, Peer) or type(peer.pid) is not int or peer.pid <= 0:
            raise Denied("Kernel broker peer required")
        broker = pwd.getpwnam("mano-broker")
        if (
            os.geteuid() != 0
            or peer.uid == 0
            or (peer.uid, peer.gid) != (broker.pw_uid, broker.pw_gid)
        ):
            raise Denied("Authenticated private broker required")

    def prepare(self, admission):
        self.actor(admission.owner)
        self.stop_check()
        if len(self.records) >= 64:
            raise Denied("Retained job quota exhausted")
        owner_fd = os.pidfd_open(admission.owner.pid)
        child = None
        try:
            if select.select([owner_fd], [], [], 0)[0]:
                raise Denied("Preparing broker already exited")
            child = Child(self.manager, admission)
            self.stop_check()  # Stop may have tripped while the child was being prepared.
        except BaseException:
            if child is not None:
                child.cancel()
            os.close(owner_fd)
            raise
        job_id = secrets.token_hex(16)
        self.records[job_id] = Record(admission.action_id, admission.owner, owner_fd, child)
        return dict(
            schema_version="1.0",
            ok=True,
            instance_id=self.instance_id,
            job_id=job_id,
            action_id=admission.action_id,
            state="prepared",
        )

    def record(self, body, peer):
        for name in ("instance_id", "job_id", "action_id"):
            identifier(body[name])
        row = self.records.get(body["job_id"])
        if (
            body["instance_id"] != self.instance_id
            or row is None
            or row.action_id != body["action_id"]
            or row.owner != peer
            or select.select([row.owner_fd], [], [], 0)[0]
        ):
            raise Denied("No live owned job in this service instance")
        return row

    def dispatch(self, packet, *, peer):
        self.actor(peer)
        value = json.loads(packet.decode("utf8"), object_pairs_hook=unique_object)
        if (
            not isinstance(value, dict)
            or set(value) != {"schema_version", "operation", "body"}
            or value["schema_version"] != "1.0"
            or not isinstance(value["body"], dict)
        ):
            raise Denied("Unknown private control envelope")
        body = value["body"]
        operation = value["operation"]
        if operation == "hello" and not body:
            return dict(schema_version="1.0", ok=True, instance_id=self.instance_id)
        expected = {"instance_id", "job_id", "action_id"}
        if operation == "read_output":
            expected |= {"stream", "offset", "length"}
        if operation not in {"start", "status", "cancel", "read_output"} or set(body) != expected:
            raise Denied("Unknown control operation or fields")
        row = self.record(body, peer)
        child = row.child
        if operation == "start":
            def authority():
                self.stop_check()
                return True  # Authenticated broker assertion plus independent root latch.
            child.start(authority)
        elif operation == "cancel":
            child.cancel()
        else:
            child.poll()
        result = child.result
        response = dict(
            schema_version="1.0",
            ok=True,
            instance_id=self.instance_id,
            job_id=body["job_id"],
            action_id=row.action_id,
            state=child.state,
            effect_verified=False,
        )
        if operation == "read_output":
            if (
                body["stream"] not in {"stdout", "stderr"}
                or type(body["offset"]) is not int
                or not 0 <= body["offset"] <= OUTPUT_LIMIT
                or type(body["length"]) is not int
                or not 1 <= body["length"] <= 4096
                or result is None
            ):
                raise Denied("Completed bounded output range required")
            data = getattr(result, body["stream"])
            piece = data[body["offset"] : body["offset"] + body["length"]]
            response.update(
                data=base64.b64encode(piece).decode("ascii"),
                eof=body["offset"] + len(piece) >= len(data),
            )
        elif result is not None:
            response.update(
                reason=result.reason,
                return_code=result.return_code,
                stdout_bytes=len(result.stdout),
                stderr_bytes=len(result.stderr),
            )
        return response

    def sweep(self):
        for row in self.records.values():
            if select.select([row.owner_fd], [], [], 0)[0]:
                row.child.cancel()
            else:
                row.child.poll()

    def close(self):
        for row in self.records.values():
            row.child.cancel()
            os.close(row.owner_fd)
        self.records.clear()


def serve_prepare(controller, connection):
    admission = None
    try:
        admission = receive_admission(connection)
        response = controller.prepare(admission)
    except (ValueError, TypeError, KeyError, RecursionError, OSError):
        response = dict(schema_version="1.0", ok=False, error="denied")
    finally:
        if admission is not None:
            admission.close()
    try:
        connection.sendall(canonical(response).encode())
    except OSError:
        pass  # Ownership/TTL remain live; an abandoned reply must not kill the service.


def serve_control(controller, connection):
    connection.settimeout(2)
    try:
        peer, packet = receive(connection)  # Closes/rejects any unexpected passed rights.
        response = controller.dispatch(packet, peer=peer)
    except (ValueError, TypeError, KeyError, RecursionError, OSError):
        response = dict(schema_version="1.0", ok=False, error="denied")
    try:
        connection.sendall(canonical(response).encode())
    except OSError:
        pass
