#!/usr/bin/env python3
"""Human-only CI serial terminal trigger for independent native stopd."""

import json
import os
import socket
import struct


def main():
    assert os.isatty(0) and os.ttyname(0) == "/dev/ttyS0"
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(5)
        client.connect("/run/mano-stop-fixture/human.sock")
        _pid, uid, _gid = struct.unpack(
            "3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        assert uid == 0
        client.sendall(b"STOP")
        reply = client.recv(32).decode()
    assert reply == "STOPPED", reply
    print(
        json.dumps({"trusted_stop_reply": reply, "uid": os.getuid(), "tty": os.ttyname(0)}),
        flush=True,
    )


if __name__ == "__main__":
    main()
