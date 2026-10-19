"""Bounded untrusted failure observations; never execution or disclosure authority."""

import base64
import hashlib

LIMIT = 4096


def parse(value):
    from .actions import identifier

    if (
        not isinstance(value, dict)
        or set(value) != {"action_id", "boot_id", "return_code", "stdout", "stderr", "untrusted"}
        or value["untrusted"] is not True
        or not isinstance(value["boot_id"], str)
        or not 1 <= len(value["boot_id"]) <= 128
        or type(value["return_code"]) is not int
        or not 1 <= value["return_code"] <= 255
    ):
        raise ValueError("Exact bounded failed execution feedback required")
    identifier(value["action_id"])
    result = {}
    for stream in ("stdout", "stderr"):
        record = value[stream]
        if (
            not isinstance(record, dict)
            or set(record) != {"data_base64", "text", "size", "sha256"}
            or type(record["size"]) is not int
            or not 0 <= record["size"] <= LIMIT
            or not isinstance(record["data_base64"], str)
            or len(record["data_base64"]) > 4 * ((LIMIT + 2) // 3)
        ):
            raise ValueError("Invalid feedback stream bounds")
        data = base64.b64decode(record["data_base64"], validate=True)
        if (
            base64.b64encode(data).decode() != record["data_base64"]
            or len(data) != record["size"]
            or hashlib.sha256(data).hexdigest() != record["sha256"]
        ):
            raise ValueError("Feedback stream integrity mismatch")
        if data.decode("utf8") != record["text"]:
            raise ValueError("Feedback text differs from captured bytes")
        result[stream] = data
    if not 1 <= sum(len(data) for data in result.values()) <= LIMIT:
        raise ValueError("Feedback must contain complete nonempty streams within 4096 bytes")
    return result


def capture(metadata, stdout, stderr):
    if (
        metadata["reason"] != "completed"
        or metadata["output_limit_reached"]
        or metadata["effect_verified"] is not False
    ):
        raise ValueError("Unknown or incomplete execution cannot supply repair feedback")
    value = dict(
        action_id=metadata["action_id"],
        boot_id=metadata["boot_id"],
        return_code=metadata["return_code"],
        untrusted=True,
    )
    for stream, data in (("stdout", stdout), ("stderr", stderr)):
        if not isinstance(data, bytes):
            raise ValueError("Binary execution feedback required")
        value[stream] = dict(
            data_base64=base64.b64encode(data).decode(),
            text=data.decode("utf8"),
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )
        if metadata["streams"][stream] != dict(size=len(data), sha256=value[stream]["sha256"]):
            raise ValueError("Feedback differs from captured output")
    parse(value)
    return value
