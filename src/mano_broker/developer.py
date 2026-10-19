"""Root operator for recorded test/fix workflows; each effect still needs a grant.

The broker owns the definition and derives progress from its journal. Core graph
checkpoints and this process cannot certify completion or select a different step.
"""

import json
import os
import subprocess
import sys

from mano_protocol.actions import canonical, identifier, unique_object
from mano_protocol.workflows import operation_key

from .lifecycle import run_mock_step
from .task_factory import control_request


def query(workflow_id):
    return control_request("developer_workflow_status", dict(workflow_id=identifier(workflow_id)))[
        "workflow"
    ]


def step(workflow_id):
    observed = query(workflow_id)
    state = observed["status"]
    config = observed["config"]
    last = len(config["workflow"]["steps"]) - 1
    if state in {"ready", "queued", "running"}:
        index = observed["index"]
        managed = config["managed"] | dict(
            context=config["managed"]["context"]
            | dict(operation_key=operation_key(workflow_id, index))
        )
        run_mock_step(managed, config["workflow"]["steps"][index]["plan"])
        observed = query(workflow_id)  # Discard core-reported progress as authority.
    if observed["status"] == "awaiting_grant" and observed["index"] == last:
        # Approval identity comes from the protected broker's original proposal
        # lookup, never an untrusted checkpoint's claimed approval_id.
        control_request(
            "declare_artifact_contract",
            dict(approval_id=observed["approval_id"], **config["workflow"]["artifact"]),
        )
    elif observed["status"] == "needs_verification":
        action_id = observed["action_id"]
        artifact_id = observed["artifact_id"]
        if artifact_id is None:
            captured = control_request(
                "capture_artifact",
                dict(action_id=action_id, path=config["workflow"]["artifact"]["path"]),
            )["artifact"]
            artifact_id = captured["artifact_id"]
        control_request(
            "check_artifact_contract", dict(action_id=action_id, artifact_id=artifact_id)
        )
        observed = query(workflow_id)
    return observed


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="Recorded developer workflow operator")
    parser.add_argument(
        "--recorded",
        action="store_true",
        required=True,
        help="Explicit recorded mock plans; no provider disclosure",
    )
    args = parser.parse_args(argv)
    del args
    try:
        if sys.platform != "linux" or os.geteuid() != 0:
            raise PermissionError("Trusted Linux root workflow operator required")
        packet = sys.stdin.buffer.read(65537)
        if not 1 <= len(packet) <= 65536:
            raise ValueError("Bounded workflow input required")
        value = json.loads(packet, object_pairs_hook=unique_object)
        if not isinstance(value, dict):
            raise ValueError("Expected recorded workflow request")
        if set(value) == {"managed", "request_key", "workflow"}:
            result = control_request("register_developer_workflow", value)["workflow"]
        elif set(value) == {"workflow_id"}:
            result = step(value["workflow_id"])
        else:
            raise ValueError("Unexpected recorded workflow fields")
        print(canonical(dict(schema_version="1.0", ok=True, workflow=result)))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        print(canonical(dict(schema_version="1.0", ok=False, error="uncertain")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
