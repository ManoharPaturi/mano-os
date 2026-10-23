"""Broker request facade, descriptor custody and trusted terminal scheduling."""

import json
import sys
import time
import traceback
from collections import deque

from .artifacts import Store
from .checkpoints import execute as execute_checkpoint
from .executor import Executor
from .file_reads import execute as execute_file_read
from .file_writes import execute as execute_file_write
from .ipc import dispatch, public_action, receive
from .package_apply import ApplyWorker
from .protocol import ActionRequest, Capability, canonical, identifier, unique_object
from .provider_jobs import ProviderJobs
from .provider_worker import ProviderWorker
from .pty_jobs import PTYJobs
from .registry import Registry
from .restoration import Restorer
from .state import Denied
from .stop_state import Snapshot, snapshot


class Runtime:
    def __init__(self, state, *, boot_id, launcher=None, stop_reader=None, model_worker=None):
        self.state = state
        self.boot_id = boot_id
        self.model_worker = model_worker or (
            ProviderWorker(ProviderJobs(state), boot_id=boot_id) if launcher else None
        )
        self.registry = Registry(model_policy=(
            self.model_worker.check_policy if self.model_worker else None))
        self.model_pending = deque()
        self.artifacts = Store()
        self.pending = deque()
        self.file_pending = deque()
        self.checkpoint_pending = deque()
        self.restore_pending = deque()
        self.package_pending = deque()
        self.package_worker = ApplyWorker(self)
        self.restorer = Restorer(self)
        self.write_pending = deque()
        self.pty_pending = deque()
        self.launcher = launcher
        self.stop_reader = stop_reader or (snapshot if launcher else None)
        self.executor = (
            Executor(state, self.registry, launcher, boot_id=boot_id,
                     observe_stop=self.sync_stop) if launcher else None
        )
        self.ptys = (PTYJobs(state, self.registry, launcher, boot_id=boot_id,
                             observe_stop=self.sync_stop) if launcher else None)
        # Process-local FD authority cannot survive daemon restart. Keep history,
        # reconcile executing state and revoke old intent/grant/pending epoch.
        with state.transaction():
            state.recover()
            state.db.execute("UPDATE pty_operations SET state='unknown' WHERE state='intent'")
            state.db.execute("UPDATE restore_steps SET state='unknown' WHERE state='intent'")
            state.db.execute("UPDATE grants SET revoked=1")
            state.db.execute("UPDATE actions SET state='failed' WHERE state='intent'")
            state.db.execute("UPDATE meta SET value=value+1 WHERE key='epoch'")
            state.event(None, "runtime-authority-renewal", {"epoch": state.meta("epoch")})
            state.db.execute("INSERT OR IGNORE INTO meta VALUES('native_generation',-1)")
        self.sync_stop()

    def sync_stop(self):
        if self.stop_reader is None:
            return
        try:
            observed = self.stop_reader()
            if isinstance(observed, Snapshot):
                previous = self.state.meta("native_generation")
                if observed.generation < previous:
                    stopped = True  # Native rollback cannot restore authority.
                else:
                    if observed.generation > previous:
                        with self.state.transaction():
                            if previous >= 0 or observed.generation > 0:
                                self.state.emergency_stop()  # Revoke even if Stop was unseen.
                                if not observed.latched:
                                    self.state.db.execute(
                                        "UPDATE meta SET value=0 WHERE key='latched'"
                                    )
                                    self.state.event(None, "native-authenticated-rearm", {
                                        "generation": observed.generation
                                    })
                            self.state.db.execute(
                                "UPDATE meta SET value=? WHERE key='native_generation'",
                                (observed.generation,)
                            )
                    stopped = observed.latched
            else:
                stopped = observed  # Explicit trusted test adapter; no public caller supplies it.
            if type(stopped) is not bool:
                stopped = True
        except (OSError, ValueError):
            stopped = True  # Missing/corrupt authority cannot enable execution.
        if stopped and not self.state.meta("latched"):
            self.state.emergency_stop()

    def live_task(self, body, peer):
        if not isinstance(body, dict):
            raise Denied("Expected task operation")
        task_id = identifier(body.get("task_id"))
        resource_id = identifier(body.get("resource_id"))
        task = self.state.db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        resource = self.registry.resources.get(resource_id)
        if (
            task is None
            or resource is None
            or task["resource_id"] != resource_id
            or task["caller_uid"] != peer.uid
            or task["boot_id"] != self.boot_id
            or resource.task_id != task_id
            or (resource.human_uid, resource.caller_uid, resource.boot_id)
            != (task["human_uid"], peer.uid, self.boot_id)
        ):
            raise Denied("No live provisioned task")

    def dispatch(self, packet, *, peer, now):
        self.sync_stop()
        value = json.loads(packet.decode("utf8"), object_pairs_hook=unique_object)
        if (
            not isinstance(value, dict)
            or set(value) != {"schema_version", "operation", "body"}
            or value["schema_version"] != "1.0"
        ):
            raise Denied("Invalid runtime envelope")
        if value['operation'] == 'package_catalog':
            if (not isinstance(value['body'],dict)
                    or set(value['body']) != {'task_id','resource_id'}):
                raise Denied('Exact current task package catalog query required')
            self.live_task(value['body'],peer)
            from .package_catalog import summary

            return dict(schema_version='1.0',ok=True,catalog=summary())
        if value['operation'] == 'package_apply_result':
            from .package_apply import result_for

            return dict(schema_version='1.0', ok=True,
                result=result_for(self.state, value['body'], caller_uid=peer.uid,
                                  boot_id=self.boot_id))
        if value['operation'] == 'package_install_review':
            from .package_reviews import review

            return dict(schema_version='1.0', ok=True,
                        review=review(self, value['body'], peer=peer))
        if value["operation"] in {"pty_status", "pty_read", "pty_write", "pty_resize", "pty_close"}:
            if self.ptys is None:
                raise Denied("PTY launcher unavailable")
            return self.ptys.dispatch(value["operation"], value["body"], caller_uid=peer.uid)
        if value["operation"] in {"propose", "request_approval"}:
            self.live_task(value["body"], peer)
        if value["operation"] == "propose":
            if self.state.meta("latched"):
                raise Denied("Proposals unavailable while emergency Stop is latched")
            request = ActionRequest.parse(canonical(value["body"]).encode())
            row, prepared = self.registry.prepare(
                self.state, request, caller_uid=peer.uid, now=now, boot_id=self.boot_id
            )
            if (prepared is not None and request.capability in
                    {Capability.RUN, Capability.MCP, Capability.PACKAGE}
                    and self.executor):
                self.pending.append(row["id"])
            if prepared is not None and request.capability == Capability.PACKAGE_APPLY:
                self.package_pending.append(row['id'])
            if prepared is not None and request.capability == Capability.PTY and self.ptys:
                self.pty_pending.append(row["id"])
            if prepared is not None and request.capability == Capability.RESTORE:
                self.restore_pending.append(row["id"])
            if prepared is not None and request.capability == Capability.CHECKPOINT:
                self.checkpoint_pending.append(row["id"])
            if prepared is not None and request.capability == Capability.WRITE:
                self.write_pending.append(row["id"])
            if prepared is not None and request.capability == Capability.READ:
                self.file_pending.append(row['id'])
            if prepared is not None and request.capability == Capability.PLAN and self.model_worker:
                self.model_pending.append(row["id"])
            return {
                "schema_version": "1.0",
                "ok": True,
                "fresh": prepared is not None,
                "action": public_action(row),
            }
        return dispatch(self.state, packet, peer=peer, now=now, boot_id=self.boot_id)

    def settle_model(self, action_id):
        row = self.state.db.execute('SELECT state FROM actions WHERE id=?',
                                    (action_id,)).fetchone()
        if row is not None and row['state'] in {'intent', 'executing'}:
            self.state.transition(action_id, 'failed' if row['state'] == 'intent' else 'unknown')
        self.registry.release(action_id)

    def tick_models(self):
        if self.model_worker is None:
            return
        for action_id in list(self.model_worker.pending):
            try:
                self.model_worker.poll(action_id)
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.settle_model(action_id)
                self.state.event(action_id, 'model-poll-denied', {
                    'error_type': type(error).__name__})
            if action_id not in self.model_worker.pending:
                self.registry.release(action_id)
        if self.model_pending and len(self.model_worker.pending) < 2:
            action_id = self.model_pending.popleft()
            try:
                if self.state.meta('latched'):
                    raise Denied('Native Stop prevents model dispatch')
                self.model_worker.launch(action_id)
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.settle_model(action_id)
                self.state.event(action_id, 'model-dispatch-denied', {
                    'error_type': type(error).__name__})
            finally:
                self.registry.release(action_id)

    def tick(self):
        self.sync_stop()
        for action_id in list(self.package_worker.pending):
            try:
                self.package_worker.poll(action_id)
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.state.event(action_id, 'package-result-uncertain',
                                 {'error_type': type(error).__name__})
        if self.package_pending and not self.package_worker.pending:
            action_id = self.package_pending.popleft()
            try:
                self.package_worker.launch(action_id)
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.settle_model(action_id)
                self.registry.release(action_id)
                self.state.event(action_id, 'package-dispatch-denied',
                                 {'error_type': type(error).__name__})
        for action_id in list(self.restorer.jobs):
            try:
                self.restorer.poll(action_id)
            except (OSError,ValueError,KeyError,TypeError) as error:
                self.state.event(action_id,"restore-denied",{"error_type":type(error).__name__})
        if self.restore_pending and not self.restorer.jobs:
            action_id = self.restore_pending.popleft()
            try:
                self.restorer.launch(action_id)
            except (OSError,ValueError,KeyError,TypeError) as error:
                self.settle_model(action_id)
                self.registry.release(action_id)
                self.state.event(action_id,"restore-denied",{"error_type":type(error).__name__})
        if self.checkpoint_pending:
            action_id = self.checkpoint_pending.popleft()
            try:
                execute_checkpoint(self, action_id)
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.state.event(action_id, "checkpoint-denied",
                                 {"error_type": type(error).__name__,
                                  "errno": error.errno if isinstance(error, OSError) else None,
                                  "denial": str(error) if isinstance(error, Denied) else None,
                                  "stages": [f"{frame.name}:{frame.lineno}" for frame in
                                             traceback.extract_tb(error.__traceback__)[-4:]]})
        if self.file_pending:
            action_id = self.file_pending.popleft()
            try:
                execute_file_read(self, action_id)
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.state.event(action_id, 'file-read-denied', {
                    'error_type': type(error).__name__})
        if self.write_pending:
            action_id = self.write_pending.popleft()
            try:
                execute_file_write(self, action_id)
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.state.event(action_id, "file-write-denied",
                                 {"error_type": type(error).__name__})
        self.tick_models()
        if self.ptys:
            for action_id in list(self.ptys.jobs):
                try:
                    self.ptys.poll(action_id)
                except (OSError, ValueError, KeyError, TypeError) as error:
                    self.state.event(action_id, "pty-poll-denied",
                                     {"error_type": type(error).__name__})
            if self.pty_pending and len(self.ptys.jobs) + len(self.executor.jobs) < 2:
                action_id = self.pty_pending.popleft()
                try:
                    self.ptys.launch(action_id)
                except (OSError, ValueError, KeyError, TypeError) as error:
                    self.state.event(action_id, "pty-dispatch-denied",
                                     {"error_type": type(error).__name__})
        if self.executor is None:
            return
        for action_id in list(self.executor.jobs):
            try:
                self.executor.poll(action_id)
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.state.event(action_id, "terminal-poll-denied", {
                    "error_type": type(error).__name__, "errno": getattr(error, "errno", None)
                })  # No arguments, paths, grants or secrets in diagnostics.
        if self.pending and len(self.executor.jobs) + len(self.ptys.jobs) < 2:
            action_id = self.pending.popleft()
            try:
                self.executor.launch(action_id)
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.state.event(action_id, "terminal-dispatch-denied", {
                    "error_type": type(error).__name__, "errno": getattr(error, "errno", None)
                })  # Failed/unknown intent is durable; never reschedule it.

    def close(self):
        try:
            if self.model_worker:
                self.model_worker.close()
        finally:
            try:
                for action_id in self.model_pending:
                    self.settle_model(action_id)
            finally:
                self.model_pending.clear()
                self.close_terminal()

    def close_terminal(self):
        try:
            self.package_worker.close()
            for action_id in self.package_pending:
                self.settle_model(action_id)
            self.package_pending.clear()
            if self.ptys:
                for action_id in list(self.ptys.jobs):
                    self.ptys.abandon(action_id)
                for action_id in self.pty_pending:
                    self.ptys.settle_unknown(action_id)
            self.pty_pending.clear()
            for action_id in self.file_pending:
                self.settle_model(action_id)
            self.file_pending.clear()
            for action_id in self.checkpoint_pending:
                self.settle_model(action_id)
            self.checkpoint_pending.clear()
            for action_id in list(self.restorer.jobs):
                self.restorer.fail(action_id)
            for action_id in self.restore_pending:
                self.settle_model(action_id)
            self.restore_pending.clear()
            for action_id in self.write_pending:
                self.settle_model(action_id)
            self.write_pending.clear()
            if self.executor:
                for action_id, handle in list(self.executor.jobs.items()):
                    try:
                        self.executor.control("cancel", handle)
                    except (OSError, ValueError, KeyError, TypeError):
                        pass
                    self.executor.settle_unknown(action_id)
                for action_id in self.pending:
                    self.executor.settle_unknown(action_id)
                self.executor.jobs.clear()
            self.pending.clear()
        finally:
            self.registry.close()
            self.artifacts.close()
            if self.launcher:
                self.launcher.close()


def serve_runtime(runtime, connection):
    connection.settimeout(2)
    try:
        peer, packet = receive(connection)
        result = runtime.dispatch(packet, peer=peer, now=time.monotonic())
    except (ValueError, TypeError, KeyError, RecursionError, OSError) as error:
        print(
            canonical(
                {
                    "event": "runtime-request-denied",
                    "error_type": type(error).__name__,
                    "errno": getattr(error, "errno", None),
                }
            ),
            file=sys.stderr,
            flush=True,
        )
        result = {"schema_version": "1.0", "ok": False, "error": "denied"}
    try:
        connection.sendall(canonical(result).encode())
    except OSError:
        pass
