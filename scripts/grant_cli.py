#!/usr/bin/env python3
"""TTY-only positive/revoked grant checks and explicitly authenticated rearm."""

import getpass
import json
import os
import sys

from approval_cli import rpc

from mano_lab.approval import digest


def main():
    assert os.isatty(0) and os.ttyname(0) == "/dev/ttyS0"
    assert len(sys.argv) == 2 and sys.argv[1] in {"before", "revoked", "rearm", "final"}
    mode = sys.argv[1]
    good, _expired, rearm = rpc({"action": "view"})["requests"]
    view = rearm if mode in {"rearm", "final"} else good
    if mode == "rearm":
        print("Broker rearm: " + json.dumps(view, sort_keys=True), flush=True)
        password = getpass.getpass("Rearm approval password: ")
        approval = rpc(
            {
                "action": "approve",
                "request_id": view["request_id"],
                "nonce": view["nonce"],
                "operation_digest": digest(view),
                "password": password,
            }
        )
        assert approval["decision"] == "approved"
    request = {
        "action": "use_grant",
        "request_id": view["request_id"],
        "nonce": view["nonce"],
        "operation_digest": digest(view),
    }
    result = rpc(request)
    assert result["decision"] == (
        "grant-valid" if mode in {"before", "rearm"} else "revoked-denied"
    ), result
    print(
        json.dumps(
            {"grant_mode": mode, "result": result, "uid": os.getuid(), "tty": os.ttyname(0)}
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
