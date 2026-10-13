"""One-shot blocked child lifecycle, trusted root service API; no listener.

Start requires a trusted authority callback. Production broker grant/epoch
transport is not implemented here; fixture callbacks are operator authorization.
"""

import base64
import json
import os
import select
import time

from .credentials import drop
from .protocol import ActionRequest, Capability, canonical, unique_object
from .runner import OUTPUT_LIMIT, ProcessResult, run
from .sandbox import command
from .state import Denied

MAX_REPORT = 192 * 1024


class Child:
    def __init__(self, manager, admission):
        request = ActionRequest.parse(canonical(admission.request.body()).encode())
        if request.capability != Capability.RUN:
            raise Denied("Supervised terminal request required")
        self.timeout = json.loads(request.args_json)["timeout_seconds"]
        self.group = manager.create(admission.action_id)
        self.started = False
        self.closed = False
        self.state = "preparing"
        self.result = None
        self.buffer = bytearray()
        self.workspace = self.cwd = self.control_r = self.control_w = self.report_r = -1
        placement_r = placement_w = report_w = -1
        parent = os.getpid()
        self.pid = None
        try:
            self.workspace = os.dup(admission.workspace_fd)
            self.cwd = os.dup(admission.cwd_fd)
            placement_r, placement_w = os.pipe()
            self.control_r, self.control_w = os.pipe()
            self.report_r, report_w = os.pipe()
            self.pid = os.fork()
        except BaseException:
            self.group.kill_and_close()
            for fd in (
                self.workspace,
                self.cwd,
                self.control_r,
                self.control_w,
                self.report_r,
                placement_r,
                placement_w,
                report_w,
            ):
                if fd >= 0:
                    os.close(fd)
            self.closed = True
            raise
        if self.pid == 0:
            try:
                keep = {0, 1, 2, self.workspace, self.cwd, placement_r, self.control_r, report_w}
                for entry in os.listdir("/proc/self/fd"):
                    fd = int(entry)
                    if fd not in keep:
                        try:
                            os.close(fd)
                        except OSError:
                            pass  # The directory enumeration's own temporary FD.
                if os.read(placement_r, 1) != b"p":
                    os._exit(125)
                os.close(placement_r)
                drop(
                    action_id=admission.action_id,
                    caller_uid=admission.caller_uid,
                    parent_pid=parent,
                )
                args = json.loads(admission.request.args_json)
                command(
                    self.workspace, self.cwd, args["argv"]
                )  # Fail before READY on invalid setup.
                os.write(report_w, b"R")
                if os.read(self.control_r, 1) != b"s":
                    os._exit(125)
                os.set_blocking(self.control_r, False)

                def revoked():
                    if not select.select([self.control_r], [], [], 0)[0]:
                        return False
                    os.read(self.control_r, 1)  # Cancel or parent EOF both revoke.
                    return True

                result = run(
                    self.workspace,
                    self.cwd,
                    args["argv"],
                    timeout=args["timeout_seconds"],
                    revoked=revoked,
                )
                packet = canonical(
                    dict(
                        reason=result.reason,
                        return_code=result.return_code,
                        stdout=base64.b64encode(result.stdout).decode("ascii"),
                        stderr=base64.b64encode(result.stderr).decode("ascii"),
                    )
                ).encode()
                if len(packet) > MAX_REPORT:
                    os._exit(125)
                while packet:
                    count = os.write(report_w, packet)
                    if count <= 0:
                        os._exit(125)
                    packet = packet[count:]
                os._exit(0)
            except BaseException:
                os._exit(125)  # No raw argv/password/environment in privileged logs.
        os.close(placement_r)
        os.close(self.control_r)
        os.close(report_w)
        try:
            self.group.attach_root_child(self.pid)
            os.write(placement_w, b"p")
            os.close(placement_w)
            placement_w = -1
            if (
                not select.select([self.report_r], [], [], 5)[0]
                or os.read(self.report_r, 1) != b"R"
            ):
                raise Denied("Placed child did not become ready")
            os.set_blocking(self.report_r, False)
            self.state = "prepared"
            self.prepared_deadline = time.monotonic() + 5
        except BaseException:
            self.cancel()
            raise
        finally:
            if placement_w >= 0:
                os.close(placement_w)

    def start(self, authorize):
        if self.closed or self.state != "prepared" or not callable(authorize):
            raise Denied("One-shot prepared child required")
        if time.monotonic() >= self.prepared_deadline:
            self.cancel()
            raise Denied("Prepared start deadline expired")
        try:
            authorized = authorize()
        except BaseException:
            self.cancel()
            raise
        if authorized is not True or time.monotonic() >= self.prepared_deadline:
            self.cancel()
            raise Denied("Fresh start authority required")
        self.started = True  # Conservative uncertainty if delivery fails after authorization.
        try:
            os.write(self.control_w, b"s")
        except OSError:
            self.cancel()
            raise
        self.state = "running"
        self.runtime_deadline = time.monotonic() + self.timeout + 5

    def poll(self):
        if self.closed:
            return self.result
        if not self.started and time.monotonic() >= self.prepared_deadline:
            self.cancel()
            return None
        if self.started and time.monotonic() >= self.runtime_deadline:
            self.cancel()
            return None  # Supervisor/compiler hangs also become unknown, not success.
        try:
            self._read_report()
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if not pid:
                return None
            self.pid = None
            self._read_report()  # The final write may have raced the first drain.
            if not self.started or os.waitstatus_to_exitcode(status) != 0:
                raise Denied("No complete started child report")
            value = json.loads(self.buffer, object_pairs_hook=unique_object)
            if (
                set(value) != {"reason", "return_code", "stdout", "stderr"}
                or value["reason"] not in {"completed", "timed-out", "output-limit", "revoked"}
                or (value["return_code"] is not None and type(value["return_code"]) is not int)
            ):
                raise Denied("Invalid child report")
            stdout = base64.b64decode(value["stdout"], validate=True)
            stderr = base64.b64decode(value["stderr"], validate=True)
            if len(stdout) > OUTPUT_LIMIT or len(stderr) > OUTPUT_LIMIT:
                raise Denied("Child stream budget exceeded")
            self.result = ProcessResult(value["reason"], value["return_code"], stdout, stderr)
            self._close()
            self.state = "finished"  # Observed process result, never independently verified effect.
            return self.result
        except (ValueError, TypeError, KeyError, OSError):
            self.cancel()
            return None

    def _read_report(self):
        while True:
            try:
                chunk = os.read(self.report_r, 4096)
            except BlockingIOError:
                return
            if not chunk:
                return
            if len(self.buffer) + len(chunk) > MAX_REPORT:
                raise Denied("Child report budget exceeded")
            self.buffer.extend(chunk)

    def cancel(self):
        if self.closed:
            return
        self._close()
        self.state = "unknown" if self.started else "not-started"

    def _close(self):
        self.group.kill_and_close()
        if self.pid is not None:
            os.waitpid(self.pid, 0)  # cgroup populated=0 already; own unreaped child only.
            self.pid = None
        for fd in (self.control_w, self.report_r, self.workspace, self.cwd):
            os.close(fd)
        self.closed = True
