"""Durable broker policy/journal core. This module does not execute commands.

Only trusted broker code calls mutation methods. A later authenticated IPC service
must derive caller UID from kernel credentials and expose a restricted method set.
"""

import hashlib
import json
import math
import os
import secrets
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path

from mano_protocol.errors import Denied as Denied

from .protocol import ActionRequest, Capability, Mode, canonical, identifier


class State:
    def __init__(self, directory: Path):
        directory = directory.absolute()
        if any(p.is_symlink() for p in (directory, *directory.parents)):
            raise ValueError("State path contains symlink")
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("Broker state must be owned by broker and mode0700")
        self.directory = directory
        file = directory / "state.sqlite3"
        fd = os.open(file, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ValueError("Unsafe broker database")
        finally:
            os.close(fd)
        self.db = sqlite3.connect(file, isolation_level=None, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA synchronous=EXTRA")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value INTEGER NOT NULL);
            INSERT OR IGNORE INTO meta VALUES('epoch',0);
            INSERT OR IGNORE INTO meta VALUES('latched',0);
            CREATE TABLE IF NOT EXISTS tasks(
                id TEXT PRIMARY KEY,human_uid INTEGER NOT NULL,caller_uid INTEGER NOT NULL,
                mode TEXT NOT NULL,resource_id TEXT NOT NULL,classification TEXT NOT NULL,
                boot_id TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS grants(
                id TEXT PRIMARY KEY,task_id TEXT NOT NULL REFERENCES tasks(id),
                capability TEXT NOT NULL,resource_id TEXT NOT NULL,human_uid INTEGER NOT NULL,
                epoch INTEGER NOT NULL,expires REAL NOT NULL,max_count INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,budget_json TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,approved_args_json TEXT,
                native_generation INTEGER NOT NULL DEFAULT -1);
            CREATE TABLE IF NOT EXISTS task_profiles(
                task_id TEXT PRIMARY KEY REFERENCES tasks(id),
                grant_id TEXT NOT NULL REFERENCES grants(id),
                approval_id TEXT NOT NULL REFERENCES approvals(id),
                mode TEXT NOT NULL,expires REAL NOT NULL,remaining INTEGER NOT NULL,
                max_timeout INTEGER NOT NULL,boot_id TEXT NOT NULL,
                epoch INTEGER NOT NULL,generation INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS profile_grants(
                grant_id TEXT PRIMARY KEY REFERENCES grants(id),
                source_grant_id TEXT NOT NULL REFERENCES grants(id));
            CREATE TABLE IF NOT EXISTS actions(
                id TEXT PRIMARY KEY,task_id TEXT NOT NULL REFERENCES tasks(id),
                grant_id TEXT NOT NULL REFERENCES grants(id),request_digest TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,request_json TEXT NOT NULL,state TEXT NOT NULL,
                exit_code INTEGER,verified INTEGER NOT NULL DEFAULT 0,
                evidence_json TEXT NOT NULL DEFAULT '[]',
                UNIQUE(task_id,idempotency_key));
            CREATE TABLE IF NOT EXISTS events(
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,action_id TEXT REFERENCES actions(id),
                event TEXT NOT NULL,details_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS approvals(
                id TEXT PRIMARY KEY,task_id TEXT NOT NULL REFERENCES tasks(id),
                request_key TEXT NOT NULL,proposal_json TEXT NOT NULL,
                request_digest TEXT NOT NULL,view_json TEXT NOT NULL,
                state TEXT NOT NULL,grant_id TEXT REFERENCES grants(id),
                UNIQUE(task_id,request_key));
            CREATE TABLE IF NOT EXISTS artifacts(
                id TEXT PRIMARY KEY,action_id TEXT NOT NULL REFERENCES actions(id),
                metadata_json TEXT NOT NULL,data BLOB NOT NULL,
                CHECK(length(data)<=8388608));
            CREATE TABLE IF NOT EXISTS checkpoints(
                action_id TEXT PRIMARY KEY REFERENCES actions(id), metadata_json TEXT NOT NULL,
                data BLOB NOT NULL, CHECK(length(data)<=4194304));
            CREATE TABLE IF NOT EXISTS checkpoint_layouts(
                action_id TEXT PRIMARY KEY REFERENCES checkpoints(action_id),
                layout_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS restore_attempts(
                action_id TEXT PRIMARY KEY REFERENCES actions(id),plan_json TEXT NOT NULL,
                metadata_json TEXT);
            CREATE TABLE IF NOT EXISTS restore_steps(
                action_id TEXT NOT NULL REFERENCES restore_attempts(action_id),sequence INTEGER,
                operation_json TEXT NOT NULL,state TEXT NOT NULL,
                PRIMARY KEY(action_id,sequence));
            CREATE TABLE IF NOT EXISTS terminal_outputs(
                action_id TEXT PRIMARY KEY REFERENCES actions(id),metadata_json TEXT NOT NULL,
                stdout BLOB NOT NULL,stderr BLOB NOT NULL,
                CHECK(length(stdout)<=65536),CHECK(length(stderr)<=65536));
            CREATE TABLE IF NOT EXISTS developer_workflows(
                id TEXT PRIMARY KEY,task_id TEXT NOT NULL REFERENCES tasks(id),key TEXT NOT NULL,
                digest TEXT NOT NULL,config_json TEXT NOT NULL,epoch INTEGER NOT NULL,
                boot_id TEXT NOT NULL,generation INTEGER NOT NULL,UNIQUE(task_id,key));
            CREATE TABLE IF NOT EXISTS file_writes(
                action_id TEXT PRIMARY KEY REFERENCES actions(id), metadata_json TEXT);
            CREATE TABLE IF NOT EXISTS pty_sessions(
                action_id TEXT PRIMARY KEY REFERENCES actions(id),
                data BLOB NOT NULL DEFAULT X'', input_bytes INTEGER NOT NULL DEFAULT 0,
                outcome_json TEXT, CHECK(length(data)<=65536));
            CREATE TABLE IF NOT EXISTS pty_operations(
                action_id TEXT NOT NULL REFERENCES actions(id), key TEXT NOT NULL,
                digest TEXT NOT NULL, operation_id TEXT NOT NULL, state TEXT NOT NULL,
                reply_json TEXT, PRIMARY KEY(action_id,key));
            CREATE TABLE IF NOT EXISTS artifact_contracts(
                approval_id TEXT PRIMARY KEY REFERENCES approvals(id),path TEXT NOT NULL,
                sha256 TEXT NOT NULL,size INTEGER NOT NULL,boot_id TEXT NOT NULL,
                epoch INTEGER NOT NULL,CHECK(size>=0 AND size<=8388608));
            CREATE TABLE IF NOT EXISTS human_prompts(
                id TEXT PRIMARY KEY,human_uid INTEGER NOT NULL,request_key TEXT NOT NULL,
                prompt TEXT NOT NULL,boot_id TEXT NOT NULL,state TEXT NOT NULL,
                task_id TEXT REFERENCES tasks(id),UNIQUE(human_uid,request_key));
            CREATE TABLE IF NOT EXISTS prompt_launch_contexts(
                prompt_id TEXT PRIMARY KEY REFERENCES human_prompts(id),
                metadata_json TEXT NOT NULL);

            CREATE TABLE IF NOT EXISTS model_budgets(
                task_id TEXT PRIMARY KEY REFERENCES tasks(id),
                money_limit INTEGER NOT NULL, token_limit INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS model_reservations(
                action_id TEXT PRIMARY KEY REFERENCES actions(id),
                task_id TEXT NOT NULL REFERENCES model_budgets(task_id),
                money INTEGER NOT NULL,tokens INTEGER NOT NULL,
                settled INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS core_cycles(
                prompt_id TEXT PRIMARY KEY REFERENCES human_prompts(id),
                state TEXT NOT NULL CHECK(state IN ('running','waiting','terminal','unknown')),
                nonce TEXT NOT NULL,model_json TEXT NOT NULL,generation INTEGER NOT NULL,
                epoch INTEGER NOT NULL,status TEXT NOT NULL,updated REAL NOT NULL,
                human_uid INTEGER NOT NULL,CHECK(length(model_json)<=1024));
            CREATE TABLE IF NOT EXISTS provider_jobs(
                action_id TEXT PRIMARY KEY REFERENCES model_attempts(action_id),
                request_digest TEXT NOT NULL,binding_json TEXT NOT NULL,state TEXT NOT NULL,
                CHECK(state IN ('prepared','dispatching','finished','unknown')),
                CHECK(length(binding_json)<=2048));
            CREATE TABLE IF NOT EXISTS model_prices(
                action_id TEXT PRIMARY KEY REFERENCES model_attempts(action_id),
                policy_json TEXT NOT NULL,CHECK(length(policy_json)<=4096));
            CREATE TABLE IF NOT EXISTS model_attempts(
                action_id TEXT PRIMARY KEY REFERENCES actions(id),
                request_digest TEXT NOT NULL,result_json TEXT,result_sha256 TEXT,
                CHECK(length(result_json)<=131072));
        """)

        # Upgrade pre-binding journals without silently retaining broad authority.
        with self.transaction():
            columns = {row[1] for row in self.db.execute("PRAGMA table_info(grants)")}
            if "native_generation" not in columns:
                self.db.execute("ALTER TABLE grants ADD COLUMN native_generation "
                                "INTEGER NOT NULL DEFAULT -1")
                self.db.execute("UPDATE grants SET revoked=1 WHERE capability='model.plan'")
                self.event(None, "native-generation-grant-migration", {})
            if "approved_args_json" not in columns:
                self.db.execute("ALTER TABLE grants ADD COLUMN approved_args_json TEXT")
                self.db.execute("UPDATE grants SET revoked=1")
                self.db.execute("UPDATE actions SET state='unknown' WHERE state='executing'")
                self.db.execute("UPDATE actions SET state='failed' WHERE state='intent'")
                self.event(None, "exact-grant-migration", {"legacy_authority_revoked": True})

    def close(self):
        self.db.close()

    @contextmanager
    def transaction(self):
        # Trusted composed mutations (approval + grant) share one outer commit.
        nested = self.db.in_transaction
        name = "trusted_" + secrets.token_hex(8)
        self.db.execute(f"SAVEPOINT {name}" if nested else "BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute(f"RELEASE {name}" if nested else "COMMIT")
        except BaseException:
            if nested:
                self.db.execute(f"ROLLBACK TO {name}")
                self.db.execute(f"RELEASE {name}")
            else:
                self.db.execute("ROLLBACK")
            raise

    def event(self, action_id, event, details):
        self.db.execute(
            "INSERT INTO events(action_id,event,details_json) VALUES(?,?,?)",
            (action_id, event, canonical(details)),
        )

    def meta(self, key):
        return self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()[0]

    def create_task(self, *, human_uid, caller_uid, mode, resource_id, classification, boot_id):
        if (
            type(human_uid) is not int
            or human_uid < 0
            or type(caller_uid) is not int
            or caller_uid <= 0
            or caller_uid in {human_uid, os.geteuid()}
        ):
            raise ValueError("Expected trusted human UID and unprivileged task UID")
        mode = Mode(mode)
        identifier(resource_id)
        if (
            classification not in {"public", "internal", "sensitive"}
            or not isinstance(boot_id, str)
            or not boot_id
        ):
            raise ValueError("Invalid task classification/boot identity")
        task_id = secrets.token_hex(16)
        with self.transaction():
            self.db.execute(
                "INSERT INTO tasks VALUES(?,?,?,?,?,?,?)",
                (task_id, human_uid, caller_uid, mode.value, resource_id, classification, boot_id),
            )
            self.event(None, "task-created", {"task_id": task_id})
        return task_id

    def issue_grant(
        self,
        task_id,
        *,
        approved_human_uid,
        approved_args,
        capability,
        resource_id,
        expires,
        max_count,
        memory_bytes,
        pids,
        cpu_percent,
        max_timeout_seconds,
    ):
        # Trusted approval adapter supplies approved_human_uid after request-bound
        # authentication. This is intentionally not an untrusted wire endpoint.
        task = self.db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        capability = Capability(capability)
        if (
            type(approved_human_uid) is not int
            or task is None
            or approved_human_uid != task["human_uid"]
            or resource_id != task["resource_id"]
        ):
            raise Denied("Grant identity/resource mismatch")
        if type(expires) not in {int, float} or not math.isfinite(expires) or expires <= 0:
            raise ValueError("Invalid expiry")
        budgets = {
            "memory_bytes": memory_bytes,
            "pids": pids,
            "cpu_percent": cpu_percent,
            "max_timeout_seconds": max_timeout_seconds,
        }
        if (
            type(max_count) is not int
            or not 1 <= max_count <= 1000
            or any(type(value) is not int or value <= 0 for value in budgets.values())
            or memory_bytes > 4 * 1024**3
            or pids > 256
            or cpu_percent > 100
            or max_timeout_seconds > 300
        ):
            raise ValueError("Invalid bounded resource/count grant")
        # Reuse the strict operation parser; trusted approval cannot smuggle extra
        # fields, environment variables, malformed paths or unbounded commands.
        approved = ActionRequest.parse(
            canonical(
                {
                    "schema_version": "1.0",
                    "task_id": task_id,
                    "grant_id": "0" * 32,
                    "capability": capability.value,
                    "resource_id": resource_id,
                    "args": approved_args,
                    "idempotency_key": "approval-template",
                    "reason": "trusted exact operation",
                }
            ).encode()
        )
        if (capability in {Capability.RUN, Capability.PTY, Capability.MCP, Capability.PACKAGE}
                and approved_args.get("timeout_seconds",60) > max_timeout_seconds):
            raise ValueError("Approved timeout exceeds grant budget")
        grant_id = secrets.token_hex(16)
        with self.transaction():
            if self.meta("latched"):
                raise Denied("Emergency stop latched")
            native = self.db.execute("SELECT value FROM meta WHERE key='native_generation'")
            row = native.fetchone()
            generation = int(row[0]) if row else -1
            if not -1 <= generation <= (1 << 63) - 1:
                raise Denied("Invalid native Stop grant generation")
            self.db.execute(
                "INSERT INTO grants(id,task_id,capability,resource_id,human_uid,epoch,expires,"
                "max_count,budget_json,approved_args_json,native_generation) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    grant_id,
                    task_id,
                    capability.value,
                    resource_id,
                    approved_human_uid,
                    self.meta("epoch"),
                    expires,
                    max_count,
                    canonical(budgets),
                    approved.args_json,
                    generation,
                ),
            )
            self.event(None, "grant-issued", {"grant_id": grant_id, "task_id": task_id})
        return grant_id

    def authorize(self, request: ActionRequest, *, caller_uid, now, boot_id):
        # Reparse even an in-process object; transport cannot bypass the wire contract.
        request = ActionRequest.parse(canonical(request.body()).encode())
        if type(now) not in {int, float} or not math.isfinite(now) or now < 0:
            raise Denied("Invalid trusted monotonic time")
        with self.transaction():
            task = self.db.execute("SELECT * FROM tasks WHERE id=?", (request.task_id,)).fetchone()
            if task is None or type(caller_uid) is not int or caller_uid != task["caller_uid"]:
                raise Denied("Caller/task mismatch")
            if boot_id != task["boot_id"]:
                raise Denied("Task belongs to another boot")
            prior = self.db.execute(
                "SELECT * FROM actions WHERE task_id=? AND idempotency_key=?",
                (request.task_id, request.idempotency_key),
            ).fetchone()
            if prior:
                if prior["request_digest"] != request.digest:
                    raise Denied("Idempotency binding mismatch")
                return dict(prior), False
            if self.db.execute("SELECT count(*) FROM actions WHERE task_id=? "
                    "AND json_extract(request_json,'$.capability')='workspace.restore' "
                    "AND state IN ('intent','executing')",(request.task_id,)).fetchone()[0]:
                raise Denied("Destination source restore must settle before another action")
            grant = self.db.execute(
                "SELECT * FROM grants WHERE id=?", (request.grant_id,)
            ).fetchone()
            if (
                grant is None
                or grant["task_id"] != request.task_id
                or grant["capability"] != request.capability.value
                or grant["resource_id"] != request.resource_id
                or grant["approved_args_json"] != request.args_json
            ):
                raise Denied("Capability/resource grant mismatch")
            if self.meta("latched") or grant["revoked"] or grant["epoch"] != self.meta("epoch"):
                raise Denied("Grant revoked")
            if now >= grant["expires"] or grant["used"] >= grant["max_count"]:
                raise Denied("Grant expired or exhausted")
            from .profiles import Profiles

            Profiles(self).require_grant(grant['id'], now=now, boot_id=boot_id)
            budget = json.loads(grant["budget_json"])
            args = json.loads(request.args_json)
            if (
                request.capability in {Capability.RUN, Capability.PTY, Capability.MCP,
                                       Capability.PACKAGE}
                and args.get("timeout_seconds",60) > budget["max_timeout_seconds"]
            ):
                raise Denied("Requested timeout exceeds grant")
            from .feedback import validate
            from .restoration import validate as validate_restore

            validate(self, request, caller_uid=caller_uid, boot_id=boot_id)
            validate_restore(self, request, caller_uid=caller_uid, boot_id=boot_id)
            from .package_catalog import validate as validate_packages

            validate_packages(request)
            if request.capability == Capability.PACKAGE_APPLY:
                from .package_apply import validate as validate_apply

                validate_apply(self, request, caller_uid=caller_uid, boot_id=boot_id)
                origin = self.db.execute("SELECT view_json FROM approvals "
                    "WHERE grant_id=? AND state='approved'", (request.grant_id,)).fetchone()
                if origin is None:
                    raise Denied('Package apply requires a distinct fresh native approval')
                view = json.loads(origin['view_json'])
                if (view['capability'] != request.capability.value
                        or canonical(view['args']) != request.args_json
                        or view['task_id'] != request.task_id
                        or view['resource_id'] != request.resource_id):
                    raise Denied('Native package approval scope differs')
            # All profiles retain the same boundaries. Network, external effects,
            # devices, credentials and host-system mutation have no capability here.
            action_id = secrets.token_hex(16)
            self.db.execute("UPDATE grants SET used=used+1 WHERE id=?", (grant["id"],))
            self.db.execute(
                "INSERT INTO actions(id,task_id,grant_id,request_digest,"
                "idempotency_key,request_json,"
                "state) VALUES(?,?,?,?,?,?,'intent')",
                (
                    action_id,
                    request.task_id,
                    request.grant_id,
                    request.digest,
                    request.idempotency_key,
                    canonical(request.body()),
                ),
            )
            self.event(action_id, "intent", {"request_digest": request.digest})
            row = self.db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
            return dict(row), True

    def start(self, action_id, *, now, boot_id):
        if type(now) not in {int, float} or not math.isfinite(now) or now < 0:
            raise Denied("Invalid trusted monotonic time")
        with self.transaction():
            row = self.db.execute(
                "SELECT a.state,a.grant_id,a.request_json,g.approved_args_json,"
                "g.expires,g.epoch,g.revoked,"
                "t.boot_id "
                "FROM actions a "
                "JOIN grants g ON a.grant_id=g.id JOIN tasks t ON a.task_id=t.id WHERE a.id=?",
                (action_id,),
            ).fetchone()
            if (
                row is None
                or row["state"] != "intent"
                or row["approved_args_json"] != canonical(json.loads(row["request_json"])["args"])
                or row["revoked"]
                or self.meta("latched")
                or row["epoch"] != self.meta("epoch")
                or now >= row["expires"]
                or boot_id != row["boot_id"]
            ):
                raise Denied("Dispatch grant expired/revoked or action not dispatchable")
            from .profiles import Profiles

            Profiles(self).require_grant(row['grant_id'], now=now, boot_id=boot_id)
            self.db.execute("UPDATE actions SET state='executing' WHERE id=?", (action_id,))
            self.event(action_id, "executing", {})

    def transition(self, action_id, state, *, exit_code=None):
        allowed = {"intent": {"failed"}, "executing": {"done", "failed", "unknown"}}
        with self.transaction():
            row = self.db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
            if row is None or state not in allowed.get(row["state"], set()):
                raise Denied("Invalid action transition")
            if state in {"done", "failed"}:
                if (state == "done" and (type(exit_code) is not int or exit_code != 0)) or (
                    state == "failed" and row["state"] == "executing" and type(exit_code) is not int
                ):
                    raise ValueError("Expected explicit exit outcome")
            elif exit_code is not None:
                raise ValueError("Unexpected exit code")
            self.db.execute(
                "UPDATE actions SET state=?,exit_code=? WHERE id=?", (state, exit_code, action_id)
            )
            self.event(action_id, state, {"exit_code": exit_code})

    def record_verification(self, action_id, *, checked_artifacts):
        # Trusted verifier only, never an action proposal field. Evidence is
        # structured identity/hash metadata; artifact custody is an executor gate.
        if not checked_artifacts or any(
            set(item) != {"artifact_id", "sha256"}
            or not isinstance(item["sha256"], str)
            or len(item["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in item["sha256"])
            for item in checked_artifacts
        ):
            raise ValueError("Verification requires checked artifact evidence")
        for item in checked_artifacts:
            identifier(item["artifact_id"])
        with self.transaction():
            row = self.db.execute(
                "SELECT state,verified FROM actions WHERE id=?", (action_id,)
            ).fetchone()
            if row is None or row["state"] != "done" or row["verified"]:
                raise Denied("Action cannot be verified")
            seen = set()
            for item in checked_artifacts:
                artifact = self.db.execute(
                    "SELECT metadata_json,data FROM artifacts WHERE id=? AND action_id=?",
                    (item["artifact_id"], action_id),
                ).fetchone()
                if artifact is None or item["artifact_id"] in seen:
                    raise Denied("Verification requires original unique artifact custody")
                seen.add(item["artifact_id"])
                metadata = json.loads(artifact[0])
                if (len(artifact[1]) != metadata["size"]
                        or metadata["sha256"] != item["sha256"]
                        or hashlib.sha256(artifact[1]).hexdigest() != item["sha256"]):
                    raise Denied("Verification artifact integrity mismatch")
            self.db.execute(
                "UPDATE actions SET verified=1,evidence_json=? WHERE id=?",
                (canonical(checked_artifacts), action_id),
            )
            self.event(action_id, "verified", {"artifacts": checked_artifacts})

    def emergency_stop(self):
        with self.transaction():
            self.db.execute("UPDATE meta SET value=value+1 WHERE key='epoch'")
            self.db.execute("UPDATE meta SET value=1 WHERE key='latched'")
            self.db.execute("UPDATE grants SET revoked=1")
            self.db.execute("UPDATE actions SET state='unknown' WHERE state='executing'")
            self.db.execute("UPDATE actions SET state='failed' WHERE state='intent'")
            self.db.execute("UPDATE human_prompts SET state='unknown_task_creation' "
                            "WHERE state='creating_task'")
            self.db.execute("UPDATE core_cycles SET state='unknown',status='controller_uncertain' "
                            "WHERE state IN ('running','waiting')")
            self.event(None, "emergency-stop", {"epoch": self.meta("epoch")})

    def recover(self):
        with self.transaction():
            changed = self.db.execute(
                "UPDATE actions SET state='unknown' WHERE state='executing'"
            ).rowcount
            prompts = self.db.execute("UPDATE human_prompts SET state='unknown_task_creation' "
                                      "WHERE state='creating_task'").rowcount
            cycles = self.db.execute("UPDATE core_cycles SET state='unknown',"
                                     "status='controller_uncertain' "
                                     "WHERE state IN ('running','waiting')").rowcount
            self.db.execute('UPDATE grants SET revoked=1 WHERE id IN '
                            '(SELECT grant_id FROM task_profiles)')
            self.db.execute('UPDATE task_profiles SET remaining=0')
            self.event(None, "recovery", {"unknown_actions": changed, "unknown_prompts": prompts,
                                           "unknown_core_cycles": cycles})
        return changed
