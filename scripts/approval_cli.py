#!/usr/bin/env python3
"""Trusted authenticated TTY fixture UI; reads only broker-supplied operations."""

import getpass
import json
import os
import socket
import struct

from mano_lab.approval import digest


def rpc(body):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(15)
        client.connect("/run/mano-approval-fixture/human.sock")
        _pid, uid, _gid = struct.unpack(
            "3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        assert uid == 0, "Approval server is not the protected root principal"
        client.sendall(json.dumps(body).encode())
        return json.loads(client.recv(8192))


def main():
    if not os.isatty(0) or os.ttyname(0) != "/dev/ttyS0":
        raise RuntimeError("Real CI human serial TTY required")
    views = rpc({"action": "view"})["requests"]
    good, expired, _rearm = views
    print("Broker approval: " + json.dumps(good, sort_keys=True), flush=True)

    def body(view, password="unused"):
        return {
            "action": "approve",
            "request_id": view["request_id"],
            "nonce": view["nonce"],
            "operation_digest": digest(view),
            "password": password,
        }

    outcomes = {}
    changed = body(good)
    changed["operation_digest"] = "0" * 64
    outcomes["changed_operation"] = rpc(changed)["decision"]
    nonce = body(good)
    nonce["nonce"] = "0" * 64
    outcomes["wrong_nonce"] = rpc(nonce)["decision"]
    extra = body(good)
    extra["target"] = "/etc/mano/sentinel"
    outcomes["injected_target"] = rpc(extra)["decision"]
    outcomes["expired"] = rpc(body(expired))["decision"]
    wrong = getpass.getpass("Wrong approval password: ")
    outcomes["wrong_password"] = rpc(body(good, wrong))["decision"]
    password = getpass.getpass("Approval password: ")
    approved = body(good, password)
    outcomes["valid"] = rpc(approved)["decision"]
    outcomes["replay"] = rpc(approved)["decision"]
    expected = {
        "changed_operation": "binding-denied",
        "wrong_nonce": "binding-denied",
        "injected_target": "schema-denied",
        "expired": "expired-denied",
        "wrong_password": "auth-denied",
        "valid": "approved",
        "replay": "replay-denied",
    }
    assert outcomes == expected, outcomes
    print(
        json.dumps(
            {
                "approval_outcomes": outcomes,
                "request_id": good["request_id"],
                "operation_digest": digest(good),
                "uid": os.getuid(),
                "tty": os.ttyname(0),
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
