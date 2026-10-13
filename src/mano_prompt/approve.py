"""Human TTY approval client. Passwords go only to the protected native adapter."""

import array
import getpass
import json
import os
import socket
import struct
import sys

from mano_broker.protocol import identifier

SOCKET = "/run/mano-approval/human.sock"


def view_packet(approval_id):
    return b"\x01\x01" + identifier(approval_id).encode("ascii")


def rearm_view_packet():
    return b"\x01\x03"


def rearm_confirmation_packet(view, password):
    generation = view.get("generation")
    nonce = view.get("nonce")
    if (view.get("operation") != "system.rearm" or type(generation) is not int
            or not 0 <= generation <= (1 << 63) - 1 or not isinstance(nonce, str)
            or len(nonce) != 64 or any(c not in "0123456789abcdef" for c in nonce)):
        raise ValueError("Invalid native rearm challenge")
    encoded = password.encode("utf8")
    if not 1 <= len(encoded) <= 256 or b"\0" in encoded:
        raise ValueError("Invalid bounded authentication password")
    return bytearray(b"\x01\x04" + generation.to_bytes(8, "big") + nonce.encode("ascii")
                     + len(encoded).to_bytes(2, "big") + encoded)


def confirmation_packet(view, password):
    approval_id = identifier(view["approval_id"])
    fields = []
    for name in ("nonce", "operation_digest"):
        field = view[name]
        if (
            not isinstance(field, str)
            or len(field) != 64
            or any(c not in "0123456789abcdef" for c in field)
        ):
            raise ValueError("Invalid protected challenge")
        fields.append(field.encode("ascii"))
    encoded = password.encode("utf8")
    if not 1 <= len(encoded) <= 256 or b"\0" in encoded:
        raise ValueError("Expected password of1-256 UTF8 bytes without NUL")
    return bytearray(
        b"\x01\x02"
        + approval_id.encode("ascii")
        + b"".join(fields)
        + len(encoded).to_bytes(2, "big")
        + encoded
    )


def rpc(packet):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(15)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        client.connect(SOCKET)
        _, creator_uid, _ = struct.unpack(
            "3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        if creator_uid != 0:
            raise ValueError("Unexpected approval socket creator")
        client.sendall(packet)
        response, ancillary, flags, _ = client.recvmsg(
            131072, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(253 * 4), socket.MSG_CMSG_CLOEXEC
        )
        credentials = []
        unexpected = False
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds = array.array("i")
                fds.frombytes(data[: len(data) - len(data) % fds.itemsize])
                for fd in fds:
                    os.close(fd)
                unexpected = True
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) == 12:
                credentials.append(struct.unpack("3i", data))
            else:
                unexpected = True
        if (
            unexpected
            or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or len(credentials) != 1
            or credentials[0][0] <= 0
            or credentials[0][1] != 0
        ):
            raise ValueError("Unexpected approval reply sender")
        result = json.loads(response.decode("utf8"))
        if (
            not isinstance(result, dict)
            or result.get("schema_version") != "1.0"
            or result.get("ok") is not True
        ):
            raise PermissionError("Approval denied")
        return result


def main():
    if len(sys.argv) != 2 or not os.isatty(0) or not os.isatty(1):
        raise ValueError("Use mano-approve APPROVAL_ID or --rearm from your human TTY")
    rearming = sys.argv[1] == "--rearm"
    view = rpc(rearm_view_packet() if rearming else view_packet(sys.argv[1]))["view"]
    if view["human_uid"] != os.getuid() or (
        not rearming and view["approval_id"] != sys.argv[1]
    ):
        raise ValueError("Approval is not bound to this human and request")
    print("Allow new tasks again; old permissions stay revoked:" if rearming else
          "Broker-owned operation (reason_untrusted is only model explanation):")
    print(json.dumps(view, indent=2, sort_keys=True, ensure_ascii=True))
    if input("Approve this exact operation? [y/N] ").strip().lower() != "y":
        return
    password = getpass.getpass("OS authentication password: ")
    packet = (rearm_confirmation_packet(view, password) if rearming
              else confirmation_packet(view, password))
    del password
    try:
        result = rpc(packet)
    finally:
        packet[:] = b"\0" * len(packet)
    print("Emergency Stop rearmed." if rearming else "Approval recorded: " + result["grant_id"])


if __name__ == "__main__":
    main()
