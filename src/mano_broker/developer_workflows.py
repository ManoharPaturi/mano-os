"""Broker-owned recorded workflow definitions, reconciled against real effects.

Root registers prospective plans, never grants. Known recorded test failures may
advance; unknown effects, changed plans/output, Stop or authority loss halt.
"""

import hashlib
import json
import secrets

from mano_protocol.file_writes import metadata as write_metadata
from mano_protocol.plans import proposal
from mano_protocol.workflows import definition, operation_key

from .approvals import effective_state
from .file_writes import result as write_result
from .protocol import canonical, identifier, text
from .state import Denied
from .terminal_output import read as terminal_output


def register(runtime, *, managed, request_key, workflow, boot_id):
    definition(workflow)
    text(request_key, 128)
    if (
        not isinstance(managed, dict)
        or set(managed)
        != {"context", "workspace", "caller_uid", "caller_name", "mode", "prompt_id"}
        or managed["mode"] != "supervised"
    ):
        raise Denied("Trusted managed developer context required")
    context = managed["context"]
    if not isinstance(context, dict) or set(context) != {
        "task_id",
        "resource_id",
        "operation_key",
        "prompt",
    }:
        raise Denied("Fixed developer context required")
    text(context["prompt"], 8192)
    text(context["operation_key"], 128)
    identifier(managed["prompt_id"])
    state = runtime.state
    task = state.db.execute(
        "SELECT * FROM tasks WHERE id=?", (identifier(context["task_id"]),)
    ).fetchone()
    resource = runtime.registry.resources.get(identifier(context["resource_id"]))
    if (
        task is None
        or resource is None
        or state.meta("latched")
        or task["boot_id"] != boot_id
        or resource.boot_id != boot_id
        or task["resource_id"] != context["resource_id"]
        or resource.task_id != task["id"]
        or task["caller_uid"] != managed["caller_uid"]
        or task["mode"] != "supervised"
        or resource.caller_uid != task["caller_uid"]
        or resource.human_uid != task["human_uid"]
    ):
        raise Denied("No live task/resource for recorded developer workflow")
    config = canonical(dict(managed=managed, workflow=workflow))
    if len(config.encode()) > 40000:
        raise Denied("Recorded developer context exceeds budget")
    digest = hashlib.sha256(config.encode()).hexdigest()
    with state.transaction():
        prior = state.db.execute(
            "SELECT * FROM developer_workflows WHERE task_id=? AND key=?", (task["id"], request_key)
        ).fetchone()
        if prior:
            if prior["digest"] != digest:
                raise Denied("Recorded workflow key conflicts with original definition")
            return prior["id"]
        if state.db.execute("SELECT count(*) FROM developer_workflows").fetchone()[0] >= 16:
            raise Denied("Recorded workflow lifetime quota exhausted")
        workflow_id = secrets.token_hex(16)
        state.db.execute(
            "INSERT INTO developer_workflows VALUES(?,?,?,?,?,?,?,?)",
            (
                workflow_id,
                task["id"],
                request_key,
                digest,
                config,
                state.meta("epoch"),
                boot_id,
                state.meta("native_generation"),
            ),
        )
        state.event(
            None,
            "recorded-developer-workflow",
            dict(workflow_id=workflow_id, task_id=task["id"], definition_sha256=digest),
        )
        return workflow_id


def status(runtime, workflow_id, *, boot_id, now):
    identifier(workflow_id)
    state = runtime.state
    row = state.db.execute(
        "SELECT * FROM developer_workflows WHERE id=?", (workflow_id,)
    ).fetchone()
    if row is None:
        raise Denied("Unknown recorded developer workflow")
    config = json.loads(row["config_json"])
    definition(config["workflow"])
    context = config["managed"]["context"]
    result = dict(
        id=workflow_id,
        config=config,
        observations=[],
        index=0,
        status="ready",
        verification_scope="recorded plans; observed exits and exact-file-v1 snapshot",
        provider_disclosure=False,
    )
    resource = runtime.registry.resources.get(context["resource_id"])
    if (
        row["boot_id"] != boot_id
        or row["epoch"] != state.meta("epoch")
        or row["generation"] != state.meta("native_generation")
        or state.meta("latched")
        or resource is None
        or resource.task_id != row["task_id"]
    ):
        result["status"] = "revoked"
        return result
    task = state.db.execute("SELECT * FROM tasks WHERE id=?", (row["task_id"],)).fetchone()
    if task is None or task["mode"] != "supervised":
        result["status"] = "revoked"
        return result
    for index, step in enumerate(config["workflow"]["steps"]):
        result["index"] = index
        result.pop("action_id", None)
        selected = context | dict(operation_key=operation_key(workflow_id, index))
        expected = proposal(step["plan"], selected)
        action = state.db.execute(
            "SELECT * FROM actions WHERE task_id=? AND idempotency_key=?",
            (row["task_id"], selected["operation_key"]),
        ).fetchone()
        if action is None:
            approval = state.db.execute(
                "SELECT * FROM approvals WHERE task_id=? AND request_key=?",
                (task["id"], selected["operation_key"]),
            ).fetchone()
            if approval is not None:
                original = json.loads(approval["proposal_json"])
                original.pop("grant_id", None)
                if original != expected:
                    raise Denied("Recorded step differs from saved approval")
                result["approval_id"] = approval["id"]
                approval_state = effective_state(state, approval, now)
                if approval_state == "pending":
                    result["status"] = "awaiting_grant"
                elif approval_state != "approved":
                    result["status"] = "failed"
                else:
                    grant = state.db.execute(
                        "SELECT * FROM grants WHERE id=?", (approval["grant_id"],)
                    ).fetchone()
                    if (
                        grant is None
                        or grant["revoked"]
                        or now >= grant["expires"]
                        or grant["epoch"] != state.meta("epoch")
                    ):
                        result["status"] = "failed"
            return result
        actual = json.loads(action["request_json"])
        actual.pop("grant_id", None)
        if actual != expected:
            raise Denied("Recorded step differs from broker action")
        result["action_id"] = action["id"]
        if action["state"] in {"intent", "executing", "unknown"}:
            result["status"] = {
                "intent": "queued",
                "executing": "running",
                "unknown": "unknown_effect",
            }[action["state"]]
            return result
        if step["plan"].get("capability") == "files.write":
            receipt = write_result(
                state,
                task_id=task["id"],
                action_id=action["id"],
                caller_uid=task["caller_uid"],
                boot_id=boot_id,
            )
            if receipt is None:
                result["status"] = "failed"
                return result
            receipt = write_metadata(
                receipt,
                task_id=task["id"],
                action_id=action["id"],
                path=step["plan"]["args"]["path"],
            )
            content = step["plan"]["args"]["text"].encode("utf8")
            if (
                receipt["size"] != len(content)
                or receipt["sha256"] != hashlib.sha256(content).hexdigest()
            ):
                raise Denied("Write receipt differs from recorded content")
            result["observations"].append(dict(action_id=action["id"], publication=receipt))
        else:
            captured = terminal_output(
                state,
                task_id=task["id"],
                action_id=action["id"],
                caller_uid=task["caller_uid"],
                boot_id=boot_id,
            )
            if captured is None:
                result["status"] = "failed"
                return result
            meta = captured[0]
            expect = step["expect"]
            if (
                meta["reason"] != "completed"
                or meta["return_code"] != expect["exit_code"]
                or any(
                    meta["streams"][s]["sha256"] != expect[s + "_sha256"]
                    for s in ("stdout", "stderr")
                )
            ):
                result["status"] = "unexpected_outcome"
                return result
            result["observations"].append(dict(action_id=action["id"], output=meta))
    final = config["workflow"]["artifact"]
    contract = state.db.execute(
        "SELECT c.* FROM artifact_contracts c JOIN approvals ap "
        "ON c.approval_id=ap.id WHERE ap.grant_id=?",
        (action["grant_id"],),
    ).fetchone()
    if contract is None or any(contract[k] != final[k] for k in ("path", "sha256", "size")):
        raise Denied("Final test lacks the original exact-file contract")
    artifacts = state.db.execute(
        "SELECT id,metadata_json,data FROM artifacts WHERE action_id=? ORDER BY rowid",
        (action["id"],),
    ).fetchall()
    artifact_id = None
    for artifact in artifacts:
        metadata = json.loads(artifact["metadata_json"])
        if (
            metadata.get("relative_path") == final["path"]
            and metadata.get("sha256") == final["sha256"]
            and metadata.get("size") == final["size"]
        ):
            if (
                len(artifact["data"]) != final["size"]
                or hashlib.sha256(artifact["data"]).hexdigest() != final["sha256"]
            ):
                raise Denied("Recorded workflow artifact integrity mismatch")
            artifact_id = artifact["id"]
            if not action["verified"]:
                break
            evidence = json.loads(action["evidence_json"])
            if dict(artifact_id=artifact_id, sha256=final["sha256"]) in evidence:
                break
            artifact_id = None
    if action["verified"] and artifact_id is None:
        raise Denied("Recorded workflow lacks original verified artifact custody")
    result.update(
        status="verified" if action["verified"] else "needs_verification",
        artifact_id=artifact_id,
        current_file_reverified=False,
    )
    return result
