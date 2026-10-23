"""Strict untrusted action proposals. No caller identity or authority fields."""

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath

MAX_PACKET = 65536


class Capability(StrEnum):
    INSPECT = "system.inspect_health"
    READ = "files.read"
    WRITE = "files.write"
    RESTORE = "workspace.restore"
    CHECKPOINT = "workspace.checkpoint"
    MCP = "mcp.discover"
    PACKAGE = "packages.plan_install"
    PACKAGE_APPLY = "packages.apply_install"
    RUN = "terminal.run"
    PTY = "terminal.open_pty"
    PLAN = "model.plan"
    BUDGET = "model.set_budget"
    PROFILE = "policy.set_profile"


class Mode(StrEnum):
    SUPERVISED = "supervised"
    AUTO = "auto"
    FULL = "full-access"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32}", value):
        raise ValueError("Expected broker-issued identifier")
    return value


def model_identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9._/-]{1,128}', value):
        raise ValueError('Invalid explicit model identifier')
    return value


def text(value, maximum=4096, *, allow_empty=False):
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or len(value.encode()) > maximum
        or "\x00" in value
    ):
        raise ValueError("Invalid bounded text")
    return value


def relative_path(value):
    text(value)
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ValueError("Expected canonical workspace-relative path")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


@dataclass(frozen=True)
class ActionRequest:
    task_id: str
    grant_id: str
    capability: Capability
    resource_id: str
    args_json: str
    idempotency_key: str
    reason: str

    @classmethod
    def parse(cls, packet: bytes, *, historical_checkpoint=False):
        if not isinstance(packet, bytes) or not 1 <= len(packet) <= MAX_PACKET:
            raise ValueError("Invalid packet size")
        value = json.loads(
            packet.decode("utf8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")),
        )
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "schema_version",
                "task_id",
                "grant_id",
                "capability",
                "resource_id",
                "args",
                "idempotency_key",
                "reason",
            }
            or value["schema_version"] != "1.0"
        ):
            raise ValueError("Unknown or missing request fields/version")
        capability = Capability(value["capability"])
        args = value["args"]
        if not isinstance(args, dict):
            raise ValueError("Arguments must be an object")
        if capability == Capability.INSPECT:
            if args:
                raise ValueError("Inspect takes no caller-controlled target")
        elif capability in {Capability.READ, Capability.WRITE}:
            expected = {"path"} if capability == Capability.READ else {"path", "text"}
            if set(args) != expected:
                raise ValueError("Unexpected file arguments")
            relative_path(args["path"])
            if ".mano-write-staging" in PurePosixPath(args["path"]).parts:
                raise ValueError("Reserved broker write-custody directory")
            if capability == Capability.WRITE:
                text(args["text"], 32768, allow_empty=True)
        elif capability == Capability.RESTORE:
            from .restoration import arguments

            arguments(args)
        elif capability == Capability.PACKAGE:
            from .packages import arguments

            arguments(args)
        elif capability == Capability.PACKAGE_APPLY:
            from .packages import apply_arguments

            apply_arguments(args)
        elif capability == Capability.CHECKPOINT:
            from .checkpoints import EXCLUDED, LEGACY_EXCLUDED

            scopes = [dict(root=".", excluded_names=list(EXCLUDED))]
            if historical_checkpoint:
                scopes.append(dict(root=".", excluded_names=list(LEGACY_EXCLUDED)))
            if args not in scopes:
                raise ValueError("Explicit complete source-root checkpoint scope required")
        elif capability == Capability.PROFILE:
            from .profiles import configuration

            configuration(args)
        elif capability == Capability.BUDGET:
            if set(args) != {'money_micro_usd', 'tokens'}:
                raise ValueError('Unexpected model budget fields')
            for key, maximum in (('money_micro_usd', 10**12), ('tokens', 10**9)):
                if type(args[key]) is not int or not 1 <= args[key] <= maximum:
                    raise ValueError('Invalid bounded model budget')
        elif capability == Capability.PLAN:
            if set(args) not in ({'provider', 'model', 'prompt', 'max_output_tokens'},
                                 {'provider', 'model', 'prompt', 'max_output_tokens', 'feedback'}):
                raise ValueError('Unexpected model disclosure arguments')
            if args['provider'] != 'openai':
                raise ValueError('Unsupported fixed provider')
            model_identifier(args['model'])
            text(args['prompt'], 8192)
            if 'feedback' in args:
                from .feedback import parse

                parse(args['feedback'])
            if (type(args['max_output_tokens']) is not int
                    or not 16 <= args['max_output_tokens'] <= 8192):
                raise ValueError('Invalid output token ceiling')
        else:
            fields = {"argv", "cwd", "timeout_seconds"}
            if capability == Capability.MCP:
                from .mcp import VERSION

                fields.add("protocol_version")
                if args.get("protocol_version") != VERSION:
                    raise ValueError("Explicit supported MCP protocol version required")
            if capability == Capability.PTY:
                fields |= {"rows", "columns", "input_limit_bytes"}
                for key, maximum in (("rows", 200), ("columns", 400),
                                     ("input_limit_bytes", 65536)):
                    if type(args.get(key)) is not int or not 1 <= args[key] <= maximum:
                        raise ValueError("Invalid bounded PTY arguments")
            if set(args) != fields:
                raise ValueError("Unexpected terminal arguments")
            argv = args["argv"]
            if not isinstance(argv, list) or not 1 <= len(argv) <= 128:
                raise ValueError("Invalid argv")
            for index, item in enumerate(argv):
                text(item, allow_empty=index > 0)
            relative_path(args["cwd"])
            if type(args["timeout_seconds"]) is not int or not 1 <= args["timeout_seconds"] <= 300:
                raise ValueError("Invalid timeout")
        return cls(
            identifier(value["task_id"]),
            identifier(value["grant_id"]),
            capability,
            identifier(value["resource_id"]),
            canonical(args),
            text(value["idempotency_key"], 128),
            text(value["reason"], 1024),
        )

    def body(self):
        return {
            "schema_version": "1.0",
            "task_id": self.task_id,
            "grant_id": self.grant_id,
            "capability": self.capability.value,
            "resource_id": self.resource_id,
            "args": json.loads(self.args_json),
            "idempotency_key": self.idempotency_key,
            "reason": self.reason,
        }

    @property
    def digest(self):
        return hashlib.sha256(canonical(self.body()).encode()).hexdigest()
