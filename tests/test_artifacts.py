import errno
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

from mano_broker.artifacts import MAX_BYTES, Store, durable_chunk
from mano_broker.protocol import ActionRequest, Capability, Mode, canonical
from mano_broker.registry import Registry
from mano_broker.state import Denied, State


@unittest.skipUnless(sys.platform == 'linux', 'Linux memfd seals/native pins required')
class SealedArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.work = self.base / 'work'
        self.work.mkdir()
        (self.work / 'result').write_bytes(b'original')
        self.state = State(self.base / 'state')
        self.registry = Registry()
        fd = os.open(self.work, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            self.resource = self.registry.register(
                fd, human_uid=1002, caller_uid=1004, boot_id='boot'
            )
        finally:
            os.close(fd)
        self.task = self.state.create_task(human_uid=1002, caller_uid=1004, mode=Mode.AUTO,
            resource_id=self.resource, classification='internal', boot_id='boot')
        self.registry.resources[self.resource].task_id = self.task
        args = dict(argv=['/usr/bin/true'], cwd='.', timeout_seconds=10)
        grant = self.state.issue_grant(self.task, approved_human_uid=1002, approved_args=args,
            capability=Capability.RUN, resource_id=self.resource, expires=100, max_count=1,
            memory_bytes=64 * 1024**2, pids=8, cpu_percent=10, max_timeout_seconds=10)
        request = ActionRequest.parse(canonical(dict(schema_version='1.0', task_id=self.task,
            resource_id=self.resource, grant_id=grant, capability='terminal.run', args=args,
            idempotency_key='one', reason='capture')).encode())
        row, _ = self.state.authorize(request, caller_uid=1004, now=10, boot_id='boot')
        self.action = row['id']
        self.store = Store()

    def tearDown(self):
        self.store.close()
        self.registry.close()
        self.state.close()
        self.temp.cleanup()

    def done(self):
        self.state.start(self.action, now=10, boot_id='boot')
        self.state.transition(self.action, 'done', exit_code=0)

    def capture(self, path='result', boot='boot'):
        return self.store.capture(self.state, self.registry, self.action, path, boot_id=boot)

    def test_sealed_bytes_survive_source_mutation_and_reject_writes(self):
        self.done()
        metadata = self.capture()
        fd = self.store.items[metadata['artifact_id']].fd
        (self.work / 'result').write_bytes(b'replaced')
        self.assertEqual(os.pread(fd, 32, 0), b'original')
        self.assertEqual(metadata['sha256'], hashlib.sha256(b'original').hexdigest())
        self.assertFalse(metadata['effect_verified'])
        self.assertFalse(os.get_inheritable(fd))
        for mutate in (lambda: os.pwrite(fd, b'x', 0), lambda: os.ftruncate(fd, 0)):
            with self.assertRaises(OSError) as caught:
                mutate()
            self.assertEqual(caught.exception.errno, errno.EPERM)
        self.assertEqual(self.state.db.execute('SELECT verified FROM actions').fetchone()[0], 0)

    def test_no_intent_wrong_boot_escape_or_hardlink_capture(self):
        with self.assertRaises(Denied):
            self.capture()
        self.done()
        for path, boot in (('../escape', 'boot'), ('result', 'other')):
            with self.assertRaises(ValueError):
                self.capture(path, boot)
        os.link(self.work / 'result', self.work / 'alias')
        with self.assertRaises(Denied):
            self.capture()
        self.assertFalse(self.store.items)

    def test_oversize_denial_closes_temporary_descriptors(self):
        self.done()
        with open(self.work / 'result', 'wb') as source:
            source.truncate(MAX_BYTES + 1)
        before = len(os.listdir('/proc/self/fd'))
        with self.assertRaises(Denied):
            self.capture()
        self.assertEqual(before, len(os.listdir('/proc/self/fd')))
        self.assertFalse(self.store.items)

    def test_durable_bytes_survive_restart_and_reject_wrong_caller_and_corruption(self):
        self.done()
        metadata = self.capture()
        self.store.persist(self.state, metadata['artifact_id'])
        self.store.persist(self.state, metadata['artifact_id'])
        self.store.close()
        self.state.close()
        self.state = State(self.base / 'state')
        kwargs = dict(task_id=self.task, caller_uid=1004, boot_id='boot', offset=0, length=4096)
        result = durable_chunk(self.state, metadata['artifact_id'], **kwargs)
        self.assertEqual(result['data'], b'original')
        self.assertTrue(result['eof'])
        self.assertFalse(result['metadata']['effect_verified'])
        for update in (dict(caller_uid=1002), dict(boot_id='other'), dict(offset=True),
                       dict(length=4097), dict(offset=999)):
            with self.assertRaises(Denied):
                durable_chunk(self.state, metadata['artifact_id'], **(kwargs | update))
        self.state.db.execute('UPDATE artifacts SET data=?', (b'corrupt!',))
        with self.assertRaises(Denied):
            durable_chunk(self.state, metadata['artifact_id'], **kwargs)
