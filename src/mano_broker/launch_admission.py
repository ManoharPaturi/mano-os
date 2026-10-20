"""Private broker-to-root launch admission library; does not launch any process.

No listener is installed. Future trusted launch service must add one-shot action
custody, cgroup/drop/stop lifecycle and live broker authority before effects.
"""

import array
import fcntl
import grp
import json
import os
import pwd
import socket
import stat
import subprocess
import threading
from dataclasses import dataclass

from .ipc import CREDENTIALS, Peer
from .limits import Limits
from .protocol import MAX_PACKET, ActionRequest, Capability, canonical, identifier, unique_object
from .resources import Workspace
from .state import Denied


@dataclass
class LaunchAdmission:
    action_id: str
    caller_uid: int
    request: ActionRequest
    workspace_fd: int
    cwd_fd: int
    owner: Peer | None = None
    limits: Limits = Limits()

    def close(self):
        for name in ("workspace_fd", "cwd_fd"):
            fd = getattr(self, name)
            if fd >= 0:
                os.close(fd)
                setattr(self, name, -1)


def task_account(caller_uid):
    if os.geteuid() != 0:
        raise Denied("Root task identity validation required")
    broker = pwd.getpwnam("mano-broker")
    if type(caller_uid) is not int or caller_uid < 1000:
        raise Denied("Unprivileged allocated task UID required")
    account = pwd.getpwuid(caller_uid)
    request_group = grp.getgrnam("mano-request")
    primary = grp.getgrgid(account.pw_gid)
    if (
        not account.pw_name.startswith("mano-task-")
        or account.pw_uid == broker.pw_uid
        or account.pw_gid <= 0
        or account.pw_gid == request_group.gr_gid
        or primary.gr_name != account.pw_name
        or primary.gr_mem
        or account.pw_shell != "/usr/sbin/nologin"
        or account.pw_dir != "/nonexistent"
        or set(os.getgrouplist(account.pw_name, account.pw_gid))
        != {account.pw_gid, request_group.gr_gid}
        or any(p.pw_name != account.pw_name and p.pw_gid == account.pw_gid for p in pwd.getpwall())
    ):
        raise Denied("Task identity policy mismatch")
    status = subprocess.check_output(
        ["/usr/bin/passwd", "--status", account.pw_name],
        text=True,
        env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C"},
        timeout=5,
    ).split()
    if status[:2] != [account.pw_name, "L"]:
        raise Denied("Task login must remain locked")
    return account


def admit(packet, descriptors, *, peer):
    if os.geteuid() != 0:
        raise Denied("Root launch admission context required")
    broker = pwd.getpwnam("mano-broker")
    if peer.uid != broker.pw_uid or peer.uid == 0:
        raise Denied("Private broker-to-root identity required")
    envelope = json.loads(packet.decode("utf8"), object_pairs_hook=unique_object)
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"schema_version", "operation", "body"}
        or envelope["schema_version"] != "1.0"
        or envelope["operation"] != "launch_task"
        or not isinstance(envelope["body"], dict)
    ):
        raise Denied("Unknown launch envelope")
    body = envelope["body"]
    required = {"action_id", "caller_uid", "request"}
    if set(body) not in (required, required | {"limits"}):
        raise Denied("Unknown launch fields")
    limits = Limits.parse(body["limits"]) if "limits" in body else Limits()
    action = identifier(body["action_id"])
    account = task_account(body["caller_uid"])
    request = ActionRequest.parse(canonical(body["request"]).encode())
    if (request.capability not in
            {Capability.RUN, Capability.PTY, Capability.MCP, Capability.PACKAGE}
            or len(descriptors) != 2):
        raise Denied("Terminal request and exactly two descriptors required")
    infos = []
    for fd in descriptors:
        info = os.fstat(fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or os.get_inheritable(fd)
            or not fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_PATH
        ):
            raise Denied("Non-inheritable O_PATH directories required")
        infos.append(info)
    if (
        infos[0].st_uid != broker.pw_uid
        or infos[0].st_gid != account.pw_gid
        or stat.S_IMODE(infos[0].st_mode) != 0o2770
    ):
        raise Denied("Workspace owner/group/privacy mismatch")
    args = json.loads(request.args_json)
    if request.capability == Capability.PACKAGE:
        from .package_catalog import load

        load(args['catalog_id'])
    if threading.active_count() != 1:
        raise Denied("Metadata identity transition requires a single-threaded service")
    original_uid = os.geteuid()
    try:
        # O_PATH still checks directory search permissions. Resolve only as the
        # fixed broker owner; do not add a global DAC override to the launcher.
        os.seteuid(broker.pw_uid)
        with Workspace(descriptors[0]) as workspace:
            with workspace.pin("." if request.capability == Capability.PACKAGE
                               else args["cwd"], directory=True) as cwd:
                if (cwd.device, cwd.inode) != (infos[1].st_dev, infos[1].st_ino):
                    raise Denied("Working directory does not match workspace request")
    finally:
        os.seteuid(original_uid)
    return LaunchAdmission(action, account.pw_uid, request, *descriptors, owner=peer, limits=limits)


def receive(connection):
    if connection.family != socket.AF_UNIX or connection.type != socket.SOCK_SEQPACKET:
        raise Denied("Private local packet transport required")
    connection.settimeout(2)
    peer = Peer(
        *CREDENTIALS.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    )
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    packet, ancillary, flags, _ = connection.recvmsg(
        MAX_PACKET, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(253 * 4), socket.MSG_CMSG_CLOEXEC
    )
    descriptors = []
    senders = []
    unexpected = False
    try:
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values = array.array("i")
                values.frombytes(data[: len(data) - len(data) % values.itemsize])
                descriptors.extend(values)
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) == 12:
                senders.append(Peer(*CREDENTIALS.unpack(data)))
            else:
                unexpected = True
        if (
            unexpected
            or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or not packet
            or senders != [peer]
            or len(descriptors) != 2
        ):
            raise Denied("Malformed launch packet or inherited connection")
        admission = admit(packet, descriptors, peer=peer)
        descriptors = []  # Ownership transfers only after all validation succeeds.
        return admission
    finally:
        for fd in descriptors:
            os.close(fd)
