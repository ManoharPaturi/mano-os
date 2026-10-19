import base64
import hashlib
import unittest
from unittest.mock import Mock

from mano_core.broker import read_file_result
from mano_protocol.file_results import MAX_READ
from mano_protocol.plans import parse_plan


class FileResultClientTests(unittest.TestCase):
    def setUp(self):
        self.query = dict(task_id='a' * 32, action_id='b' * 32, path='notes.txt')
        self.data = b'untrusted bytes\x00' * 1000
        self.meta = dict(artifact_id='c' * 32, action_id='b' * 32, task_id='a' * 32,
            boot_id='boot', relative_path='notes.txt', effect_verified=False,
            sha256=hashlib.sha256(self.data).hexdigest(), size=len(self.data),
            source_device=1, source_inode=2)

    def response(self, packet):
        body = packet['body']
        self.assertEqual(packet['operation'], 'file_result')
        self.assertEqual(body['task_id'], self.query['task_id'])
        self.assertEqual(body['action_id'], self.query['action_id'])
        self.assertEqual(body['length'], 4096)
        end = body['offset'] + 4096
        return dict(schema_version='1.0', ok=True, artifact=self.meta.copy(),
            data=base64.b64encode(self.data[body['offset']:end]).decode(),
            eof=end >= len(self.data))

    def test_exact_multichunk_binary_empty_and_boundary_results(self):
        for data in (self.data, b'', b'x' * MAX_READ):
            self.data = data
            self.meta.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
            client = Mock(side_effect=self.response)
            result = read_file_result(client, **self.query)
            self.assertEqual(result, dict(metadata=self.meta, data=data))
            self.assertLessEqual(client.call_count, 8)
            self.assertEqual([c.args[0]['body']['offset'] for c in client.call_args_list],
                             list(range(0, max(1, len(data)), 4096)))

    def test_binding_bounds_and_forged_verification_are_denied(self):
        for change in (dict(task_id='d' * 32), dict(action_id='d' * 32),
                dict(artifact_id='invalid'), dict(relative_path='other'),
                dict(effect_verified=True),
                dict(size=True), dict(size=MAX_READ + 1), dict(source_inode=True),
                dict(sha256='z' * 64), dict(boot_id=''), dict(extra='authority')):
            def client(packet, change=change):
                response = self.response(packet)
                response['artifact'].update(change)
                return response
            with self.subTest(change=change), self.assertRaises(ValueError):
                read_file_result(client, **self.query)

    def test_changed_metadata_digest_eof_and_empty_nonprogress_never_retry(self):
        for change in (dict(data=''), dict(data='not base64'), dict(eof=True),
                       dict(data=base64.b64encode(b'x').decode()),
                       dict(data=base64.b64encode(b'X' * 4097).decode())):
            with self.subTest(change=change), self.assertRaises(ValueError):
                read_file_result(lambda p, change=change: self.response(p) | change, **self.query)
        count = 0
        def changed(packet):
            nonlocal count
            count += 1
            response = self.response(packet)
            if count == 2:
                response['artifact']['artifact_id'] = 'd' * 32
            return response
        with self.assertRaises(ValueError):
            read_file_result(changed, **self.query)
        self.assertEqual(count, 2)
        self.meta['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            read_file_result(self.response, **self.query)
        client = Mock(side_effect=TimeoutError())
        with self.assertRaises(TimeoutError):
            read_file_result(client, **self.query)
        client.assert_called_once()

    def test_typed_plans_cannot_expand_authority_or_capability(self):
        read = dict(capability='files.read', args=dict(path='notes.txt'), reason='Read notes')
        self.assertEqual(parse_plan(read), read)
        write = dict(capability='files.write', args=dict(path='notes.txt', text='bounded'),
                     reason='Write notes')
        self.assertEqual(parse_plan(write), write)
        for change in (dict(capability='files.write'), dict(capability='model.plan'),
                dict(capability='policy.set_profile'), dict(grant_id='a' * 32),
                dict(verified=True), dict(args=dict(path='../outside'))):
            with self.subTest(change=change), self.assertRaises(ValueError):
                parse_plan(read | change)
