"""Human request data only; these records cannot authorize execution."""

import json
import os
import uuid
from pathlib import Path


def store_request(text):
    value = text.strip()
    if not value or len(value) > 8192 or "\x00" in value:
        raise ValueError("Enter a request of 1–8192 characters")
    directory = Path.home() / ".local/state/mano"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    message = {
        "schema_version": "1.0",
        "kind": "prompt_request",
        "request_id": str(uuid.uuid4()),
        "text": value,
        "uid": os.getuid(),
    }
    descriptor = os.open(
        directory / "requests.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "w") as stream:
        stream.write(json.dumps(message) + "\n")
    return message
