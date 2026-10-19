"""Recorded developer plans and exact observed-exit/artifact predicates; no grants."""

import re

from .actions import canonical, relative_path
from .plans import parse_plan


def digest(value):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value):
        raise ValueError("Expected SHA256 digest")
    return value


def definition(value):
    if not isinstance(value, dict) or set(value) != {"steps", "artifact"}:
        raise ValueError("Unexpected recorded workflow fields")
    if not isinstance(value["steps"], list) or not 2 <= len(value["steps"]) <= 8:
        raise ValueError("Expected 2..8 bounded developer steps")
    for step in value["steps"]:
        if not isinstance(step, dict) or set(step) != {"plan", "expect"}:
            raise ValueError("Unexpected developer step fields")
        plan = parse_plan(step["plan"])
        if plan["capability"] == "files.write":
            if step["expect"] != {}:
                raise ValueError("Write publication cannot self-verify an expected result")
        elif plan["capability"] == "terminal.run":
            expect = step["expect"]
            if (
                not isinstance(expect, dict)
                or set(expect) != {"exit_code", "stdout_sha256", "stderr_sha256"}
                or type(expect["exit_code"]) is not int
                or not 0 <= expect["exit_code"] <= 125
            ):
                raise ValueError("Expected explicit ordinary command exit and stream digests")
            digest(expect["stdout_sha256"])
            digest(expect["stderr_sha256"])
        else:
            raise ValueError("Recorded developer steps support writes and terminal tests")
    last = value["steps"][-1]
    if parse_plan(last["plan"])["capability"] != "terminal.run" or last["expect"]["exit_code"] != 0:
        raise ValueError("Workflow must finish with an explicitly successful test")
    artifact = value["artifact"]
    if (
        not isinstance(artifact, dict)
        or set(artifact) != {"path", "sha256", "size"}
        or type(artifact["size"]) is not int
        or not 0 <= artifact["size"] <= 32768
    ):
        raise ValueError("Expected bounded independent exact-file predicate")
    relative_path(artifact["path"])
    digest(artifact["sha256"])
    if len(canonical(value).encode()) > 32768:
        raise ValueError("Recorded workflow exceeds fixed budget")
    return value


def operation_key(workflow_id, index):
    from .actions import identifier

    identifier(workflow_id)
    if type(index) is not int or not 0 <= index < 8:
        raise ValueError("Invalid recorded step index")
    return f"developer-{workflow_id}-{index}"
