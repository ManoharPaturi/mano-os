"""Trusted fixed provider socket transaction. No endpoint selection or retry."""

import os
import pwd
import socket
import time

from mano_protocol.transport import CREDENTIALS, Peer

from .price_config import load_policy
from .state import Denied

PATH = '/run/mano-provider/request.sock'


def run(jobs, action_id, *, boot_id):
    broker = pwd.getpwnam('mano-broker')
    provider = pwd.getpwnam('mano-provider')
    if (broker.pw_uid == 0 or os.geteuid() != broker.pw_uid or provider.pw_uid == 0
            or provider.pw_uid == broker.pw_uid or provider.pw_gid == 0):
        raise Denied('Separate trusted broker and provider identities required')
    prepared = False
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        # Provider unit has a 35s independent hard runtime limit. This receive
        # deadline also bounds a broken listener/receipt without Python retries.
        connection.settimeout(40)
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        connection.connect(PATH)
        creator = Peer(*CREDENTIALS.unpack(connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, CREDENTIALS.size)))
        if creator.uid != 0 or creator.gid != 0 or creator.pid <= 0:
            raise Denied('Provider listener is not root activated')
        try:
            policy = load_policy(wall_time=int(time.time()))
            jobs.prepare(action_id, policy=policy, now=time.monotonic(),
                         wall_time=int(time.time()), boot_id=boot_id)
            prepared = True
            packet = jobs.claim(action_id, now=time.monotonic(), wall_time=int(time.time()),
                                boot_id=boot_id)
            if connection.send(packet) != len(packet):
                raise Denied('Incomplete provider send; effect uncertain')
            return jobs.receive(connection, action_id, expected_uid=provider.pw_uid,
                                expected_gid=provider.pw_gid, boot_id=boot_id)
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            if prepared:
                action, _, job, _ = jobs.original(action_id, boot_id)
                if action['state'] == 'executing' and job['state'] in {'prepared', 'dispatching'}:
                    jobs.uncertain(action_id, boot_id=boot_id)
            raise
