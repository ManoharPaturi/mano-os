"""Approved interactive sessions with durable, at-most-once input attempts.

The public caller selects only an owned action and bounded data/geometry. Private
launcher handles and worker descriptors never cross the broker boundary.
"""

import base64
import hashlib
import json
import secrets

from .executor import Executor
from .protocol import Capability, canonical, identifier, text
from .pty_session import geometry
from .state import Denied


class PTYJobs(Executor):
    capability = Capability.PTY
    capabilities = {Capability.PTY}

    def launch(self, action_id):
        # Capacity is reserved before prepare/start and retained for history.
        try:
            with self.state.transaction():
                if self.state.db.execute("SELECT count(*) FROM pty_sessions").fetchone()[0] >= 32:
                    raise Denied("PTY session history quota exhausted")
                self.state.db.execute("INSERT INTO pty_sessions(action_id) VALUES(?)", (action_id,))
        except BaseException:
            # Settle outside the failed reservation transaction, so rollback
            # cannot restore an intent that will never be scheduled again.
            self.settle_unknown(action_id)
            self.registry.release(action_id)
            raise
        return super().launch(action_id)

    def settle_unknown(self, action_id):
        super().settle_unknown(action_id)
        self.state.db.execute(
            "UPDATE pty_operations SET state='unknown' WHERE action_id=? AND state='intent'",
            (action_id,),
        )

    def private(self, action_id, operation, **args):
        handle = self.jobs[action_id]
        response = self.client.exchange(
            "control", dict(schema_version="1.0", operation=operation, body=handle | args)
        )
        if (
            response.get("schema_version") != "1.0"
            or response.get("ok") is not True
            or response.get("effect_verified") is not False
            or any(response.get(k) != v for k, v in handle.items())
        ):
            raise Denied("Unbound PTY response")
        return response

    def abandon(self, action_id):
        handle = self.jobs.pop(action_id, None)
        if handle is not None:
            try:
                self.control("cancel", handle)
            except (OSError, ValueError, TypeError, KeyError):
                pass
        self.settle_unknown(action_id)

    def poll(self, action_id):
        try:
            self.authority(action_id, "executing")
            row = self.state.db.execute(
                "SELECT * FROM pty_sessions WHERE action_id=?", (action_id,)
            ).fetchone()
            response = self.private(action_id, "pty_read", offset=len(row["data"]), length=4096)
            data = base64.b64decode(response["data"], validate=True)
            if (
                response["offset"] != len(row["data"])
                or len(data) > 4096
                or type(response["total_bytes"]) is not int
                or not len(row["data"]) + len(data) <= response["total_bytes"] <= 65536
            ):
                raise Denied("Invalid PTY output custody")
            self.observe_stop()
            self.authority(action_id, "executing")
            with self.state.transaction():
                self.state.db.execute(
                    "UPDATE pty_sessions SET data=? WHERE action_id=?",
                    (row["data"] + data, action_id),
                )
                if (
                    response["state"] == "finished"
                    and len(row["data"]) + len(data) == response["total_bytes"]
                ):
                    outcome = response.get("outcome")
                    if (
                        not isinstance(outcome, dict)
                        or set(outcome) != {"kind", "reason", "return_code"}
                        or outcome["kind"] != "finished"
                        or type(outcome["return_code"]) is not int
                        or outcome["reason"]
                        not in {
                            "exited",
                            "closed",
                            "unknown",
                            "timed-out",
                            "revoked",
                            "output-limit",
                        }
                    ):
                        raise Denied("Missing explicit PTY outcome")
                    self.state.db.execute(
                        "UPDATE pty_sessions SET outcome_json=? WHERE action_id=?",
                        (canonical(outcome), action_id),
                    )
                    state = (
                        "done"
                        if outcome["reason"] == "exited" and outcome["return_code"] == 0
                        else "unknown"
                        if outcome["reason"] == "unknown"
                        else "failed"
                    )
                    self.state.transition(
                        action_id,
                        state,
                        exit_code=None if state == "unknown" else outcome["return_code"],
                    )
                    self.jobs.pop(action_id)
                elif response["state"] not in {"running", "finished"}:
                    raise Denied("Uncertain PTY lifecycle")
            return response
        except BaseException:
            self.abandon(action_id)
            raise

    def owned(self, task_id, action_id, caller_uid):
        identifier(task_id)
        identifier(action_id)
        row = self.state.db.execute(
            "SELECT a.*,s.data,s.input_bytes,s.outcome_json FROM actions a "
            "JOIN tasks t ON t.id=a.task_id JOIN pty_sessions s ON s.action_id=a.id "
            "WHERE a.id=? AND a.task_id=? AND t.caller_uid=? AND t.boot_id=?",
            (action_id, task_id, caller_uid, self.boot_id),
        ).fetchone()
        if row is None:
            raise Denied("No owned current-boot PTY session")
        return row

    def dispatch(self, operation, body, *, caller_uid):
        if not isinstance(body, dict):
            raise Denied("Expected PTY operation")
        fields = {"task_id", "action_id"}
        if operation == "pty_read":
            fields |= {"offset", "length"}
        elif operation in {"pty_write", "pty_resize", "pty_close"}:
            fields |= {"key"}
            fields |= (
                {"data"}
                if operation == "pty_write"
                else ({"rows", "columns"} if operation == "pty_resize" else set())
            )
        elif operation != "pty_status":
            raise Denied("Unknown PTY operation")
        if set(body) != fields:
            raise Denied("Unexpected PTY fields")
        row = self.owned(body["task_id"], body["action_id"], caller_uid)
        action_id = row["id"]
        if operation in {"pty_status", "pty_read"}:
            result = dict(
                state=row["state"],
                output_bytes=len(row["data"]),
                input_bytes=row["input_bytes"],
                effect_verified=False,
                outcome=json.loads(row["outcome_json"]) if row["outcome_json"] else None,
            )
            if operation == "pty_read":
                offset, length = body["offset"], body["length"]
                if (
                    type(offset) is not int
                    or not 0 <= offset <= len(row["data"])
                    or type(length) is not int
                    or not 1 <= length <= 4096
                ):
                    raise Denied("Bounded PTY output range required")
                data = row["data"][offset : offset + length]
                result.update(
                    offset=offset,
                    data=base64.b64encode(data).decode("ascii"),
                    prefix_sha256=hashlib.sha256(row["data"][: offset + len(data)]).hexdigest(),
                    eof=row["state"] in {"done", "failed", "unknown"}
                    and offset + len(data) == len(row["data"]),
                )
            return dict(schema_version="1.0", ok=True, session=result)
        key = text(body["key"], 128)
        args = {k: v for k, v in body.items() if k not in {"task_id", "action_id", "key"}}
        charge = 0
        if operation == "pty_write":
            if not isinstance(args["data"], str) or len(args["data"]) > 5464:
                raise Denied("Invalid PTY input")
            data = base64.b64decode(args["data"], validate=True)
            if not 1 <= len(data) <= 4096:
                raise Denied("Bounded PTY write required")
            charge = len(data)
        elif operation == "pty_resize":
            geometry(**args)
        digest = hashlib.sha256(
            canonical(dict(operation=operation, args=args)).encode()
        ).hexdigest()
        with self.state.transaction():
            old = self.state.db.execute(
                "SELECT * FROM pty_operations WHERE action_id=? AND key=?", (action_id, key)
            ).fetchone()
            if old is not None:
                if old["digest"] != digest:
                    raise Denied("PTY input key reused with changed payload")
                # Replays return a stored acknowledgement, including after expiry;
                # they never reauthorize input or contact the worker.
                return dict(
                    schema_version="1.0",
                    ok=True,
                    operation=json.loads(old["reply_json"])
                    if old["reply_json"]
                    else dict(state="unknown", written=None),
                )
            _, request = self.authority(action_id, "executing")
            if action_id not in self.jobs:
                raise Denied("No live PTY custody")
            count = self.state.db.execute(
                "SELECT count(*) FROM pty_operations WHERE action_id=?", (action_id,)
            ).fetchone()[0]
            # Leave a close operation available after input/resize exhaustion.
            if count >= (64 if operation == "pty_close" else 63):
                raise Denied("PTY input operation quota exhausted")
            if row["input_bytes"] + charge > json.loads(request.args_json)["input_limit_bytes"]:
                raise Denied("Approved PTY input budget exhausted")
            operation_id = secrets.token_hex(16)
            self.state.db.execute(
                "INSERT INTO pty_operations VALUES(?,?,?,?,'intent',NULL)",
                (action_id, key, digest, operation_id),
            )
            self.state.db.execute(
                "UPDATE pty_sessions SET input_bytes=input_bytes+? WHERE action_id=?",
                (charge, action_id),
            )
        try:
            self.observe_stop()
            self.authority(action_id, "executing")
            response = self.private(
                action_id,
                "pty_input",
                input_operation=operation[4:],
                operation_id=operation_id,
                args=args,
            )
            written = response.get("written")
            if (
                response.get("operation_id") != operation_id
                or type(written) is not int
                or not 0 <= written <= charge
            ):
                raise Denied("Uncertain PTY acknowledgement")
            self.observe_stop()
            self.authority(action_id, "executing")
            reply = dict(state="acknowledged", written=written, effect_verified=False)
            with self.state.transaction():
                self.state.db.execute(
                    "UPDATE pty_operations SET state='acknowledged',reply_json=? "
                    "WHERE action_id=? AND key=?",
                    (canonical(reply), action_id, key),
                )
            return dict(schema_version="1.0", ok=True, operation=reply)
        except BaseException:
            self.abandon(action_id)
            raise
