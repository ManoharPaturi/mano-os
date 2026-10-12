#!/usr/bin/env python3
"""Root CI-only authority spike with fixed PAM identity and fixed marker effect."""

import json
import os
import pwd
import socket
import struct
import subprocess
import time
from pathlib import Path

from mano_lab.approval import TARGET, Request, digest

DIRECTORY = Path("/run/mano-approval-fixture")
SOCKET = DIRECTORY / "human.sock"
JOURNAL = Path("/var/lib/mano-broker/approval-journal.jsonl")


def main():
    if os.getuid() != 0 or Path("/etc/mano-lab-disposable").read_text().strip() != "mano-phase0-ci":
        raise RuntimeError("Disposable guest root required")
    if subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() not in {
        "kvm",
        "qemu",
    }:
        raise RuntimeError("QEMU guest required")
    human = pwd.getpwnam("mano-human")
    DIRECTORY.mkdir(mode=0o711, exist_ok=True)
    if (
        DIRECTORY.is_symlink()
        or DIRECTORY.stat().st_uid != 0
        or SOCKET.exists()
        or JOURNAL.exists()
        or Path(TARGET).exists()
    ):
        raise RuntimeError("Refusing existing approval fixture state")
    requests = [Request.create(time.monotonic()), Request.create(time.monotonic(), expired=True)]
    indexed = {r.view["request_id"]: r for r in requests}
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    listener.bind(str(SOCKET))
    os.chown(SOCKET, human.pw_uid, human.pw_gid)
    os.chmod(SOCKET, 0o600)
    listener.listen(8)

    def authenticate(password):
        result = subprocess.run(
            ["/usr/local/lib/mano-lab/pam-approve-probe"],
            input=password + "\n",
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        return result.returncode == 0

    while True:
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(5)
            _pid, uid, _gid = struct.unpack(
                "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            try:
                packet = conn.recv(8193)
                if len(packet) > 8192:
                    raise ValueError("Oversized packet")
                body = json.loads(packet)
                if not isinstance(body, dict):
                    raise ValueError("Object required")
                if uid != human.pw_uid:
                    reply = {"decision": "peer-denied"}
                elif body == {"action": "view"}:
                    reply = {"requests": [r.view for r in requests]}
                else:
                    request = indexed.get(body.get("request_id"))
                    outcome = (
                        "binding-denied"
                        if request is None
                        else request.decision(uid, human.pw_uid, body, time.monotonic, authenticate)
                    )
                    event = {
                        "peer_uid": uid,
                        "request_id": body.get("request_id"),
                        "decision": outcome,
                        "operation_digest": digest(request.view) if request else None,
                    }
                    fd = os.open(
                        JOURNAL, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600
                    )
                    with os.fdopen(fd, "w") as stream:
                        stream.write(json.dumps(event) + "\n")
                    if outcome == "approved":
                        fd = os.open(
                            TARGET, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                        )
                        with os.fdopen(fd, "w") as stream:
                            stream.write(json.dumps(event) + "\n")
                    reply = event
                conn.sendall(json.dumps(reply).encode())
            except (ValueError, TypeError, TimeoutError, json.JSONDecodeError):
                conn.sendall(b'{"decision":"malformed-denied"}')


if __name__ == "__main__":
    main()
