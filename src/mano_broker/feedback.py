"""Reconcile model feedback with original private terminal custody before disclosure."""

import json

from mano_protocol.feedback import capture, parse

from .state import Denied
from .terminal_output import read


def validate(state, request, *, caller_uid, boot_id):
    args = json.loads(request.args_json)
    if request.capability != "model.plan" or "feedback" not in args:
        return
    value = args["feedback"]
    parse(value)
    if value["boot_id"] != boot_id:
        raise Denied("Feedback belongs to another boot")
    original = read(
        state,
        task_id=request.task_id,
        action_id=value["action_id"],
        caller_uid=caller_uid,
        boot_id=boot_id,
    )
    if original is None:
        raise Denied("Feedback has no original terminal custody")
    metadata, row = original
    expected = capture(metadata, row["stdout"], row["stderr"])
    if value != expected:
        raise Denied("Feedback differs from original captured failure")
