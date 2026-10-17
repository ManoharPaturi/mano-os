"""One-owner, bounded provider transactions; never wait for network in broker ticks."""

import os
import pwd
import select
import socket
import time
from dataclasses import dataclass

from mano_protocol.stop_state import snapshot
from mano_protocol.transport import CREDENTIALS, Peer

from .price_config import load_policy
from .provider_client import PATH
from .state import Denied


@dataclass
class Pending:
    connection: socket.socket
    provider_uid: int
    provider_gid: int
    deadline: float


class ProviderWorker:
    """Internal scheduler adapter. Public model dispatch is still disabled."""

    def __init__(self, jobs, *, boot_id):
        self.jobs = jobs
        self.boot_id = boot_id
        self.pending = {}
        self.closed = False

    def launch(self, action_id):
        if self.closed or action_id in self.pending or len(self.pending) >= 2:
            raise Denied('Provider worker closed, duplicate or at capacity')
        broker = pwd.getpwnam('mano-broker')
        provider = pwd.getpwnam('mano-provider')
        if (broker.pw_uid == 0 or os.geteuid() != broker.pw_uid or provider.pw_uid == 0
                or provider.pw_uid == broker.pw_uid or provider.pw_gid <= 0):
            raise Denied('Separate broker and provider identities required')
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        prepared = False
        try:
            connection.setblocking(False)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            # A full/unavailable local listener fails immediately; never retry a send.
            connection.connect(PATH)
            creator = Peer(*CREDENTIALS.unpack(connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, CREDENTIALS.size)))
            if creator.pid <= 0 or creator.uid != 0 or creator.gid != 0:
                raise Denied('Provider listener is not Root activated')
            policy = load_policy(wall_time=int(time.time()))
            self.jobs.prepare(action_id, policy=policy, now=time.monotonic(),
                              wall_time=int(time.time()), boot_id=self.boot_id)
            prepared = True
            packet = self.jobs.claim(action_id, now=time.monotonic(),
                                     wall_time=int(time.time()), boot_id=self.boot_id)
            if connection.send(packet) != len(packet):
                raise Denied('Incomplete provider send; effect uncertain')
            self.pending[action_id] = Pending(connection, provider.pw_uid, provider.pw_gid,
                                               time.monotonic() + 40)
        except BaseException:
            connection.close()
            if prepared:
                self._uncertain(action_id)
            raise

    def _uncertain(self, action_id):
        action, _, job, _ = self.jobs.original(action_id, self.boot_id)
        if action['state'] == 'executing' and job['state'] in {'prepared', 'dispatching'}:
            self.jobs.uncertain(action_id, boot_id=self.boot_id)

    def cancel(self, action_id):
        pending = self.pending.pop(action_id, None)
        if pending is not None:
            try:
                pending.connection.close()
            finally:
                self._uncertain(action_id)

    def poll(self, action_id):
        pending = self.pending.get(action_id)
        if pending is None:
            raise Denied('No original provider transaction')
        try:
            _, request, _, _ = self.jobs.original(action_id, self.boot_id)
            grant = self.jobs.state.db.execute('SELECT * FROM grants WHERE id=?',
                                               (request.grant_id,)).fetchone()
            native = snapshot()
            now = time.monotonic()
            if (now >= pending.deadline or native.latched or grant['revoked']
                    or native.generation != grant['native_generation'] or now >= grant['expires']):
                raise Denied('Provider transaction expired or stopped')
            readable, _, _ = select.select([pending.connection], [], [], 0)
            if not readable:
                return None
            result = self.jobs.receive(pending.connection, action_id,
                expected_uid=pending.provider_uid, expected_gid=pending.provider_gid,
                boot_id=self.boot_id)
        except BaseException:
            self.cancel(action_id)
            raise
        self.pending.pop(action_id)
        pending.connection.close()
        return result

    def close(self):
        self.closed = True
        for action_id in list(self.pending):
            self.cancel(action_id)
