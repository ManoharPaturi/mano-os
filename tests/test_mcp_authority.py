import copy
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from mano_broker.feedback import validate
from mano_broker.ipc import Peer, dispatch
from mano_broker.state import Denied, State
from mano_broker.terminal_output import persist, read
from mano_core.mcp import MCPDiscovery, proposal
from mano_protocol.actions import ActionRequest, canonical
from mano_protocol.feedback import capture
from mano_protocol.mcp import VERSION, Discovery


class MCPAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / 'journal')
        self.task = self.state.create_task(human_uid=1002, caller_uid=1004, mode='supervised',
            resource_id='a'*32, classification='internal', boot_id='boot')
        self.proposal = proposal(task_id=self.task, resource_id='a'*32,
            argv=['/usr/bin/server'], key='discover-once', reason='Inspect server')
        self.args = self.proposal['args']

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def request(self, grant):
        return ActionRequest.parse(canonical(self.proposal | dict(grant_id=grant)).encode())

    def begin(self):
        grant = self.state.issue_grant(self.task, approved_human_uid=1002,
            approved_args=self.args, capability='mcp.discover', resource_id='a'*32,
            expires=100, max_count=1, memory_bytes=256*1024**2, pids=32,
            cpu_percent=20, max_timeout_seconds=20)
        request = self.request(grant)
        row, fresh = self.state.authorize(request, caller_uid=1004, now=10, boot_id='boot')
        self.assertTrue(fresh)
        self.state.start(row['id'], now=10, boot_id='boot')
        return request, row['id']

    def test_exact_version_argv_and_deadline_are_approved(self):
        self.assertEqual(self.args['protocol_version'], VERSION)
        for changes in (dict(protocol_version='2025-11-25'), dict(network=True),
                        dict(timeout_seconds=True)):
            changed = copy.deepcopy(self.proposal)
            changed['args'].update(changes)
            with self.assertRaises(ValueError):
                ActionRequest.parse(canonical(changed | dict(grant_id='0'*32)).encode())
        request, action = self.begin()
        changed = request.body()
        changed['args'] = self.args | dict(argv=['/usr/bin/other'])
        with self.assertRaises(Denied):
            self.state.authorize(ActionRequest.parse(canonical(changed).encode()),
                                 caller_uid=1004, now=10, boot_id='boot')
        self.state.transition(action, 'unknown')
        row, fresh = self.state.authorize(request, caller_uid=1004, now=10, boot_id='boot')
        self.assertFalse(fresh)
        self.assertEqual(row['state'], 'unknown')

    def test_adapter_failure_is_custodied_but_cannot_be_model_failure_feedback(self):
        _, action = self.begin()
        persist(self.state, action, dict(return_code=1, reason='completed'),
                dict(stdout=b'{}', stderr=b'protocol failure'), boot_id='boot')
        meta, row = read(self.state, task_id=self.task, action_id=action,
                         caller_uid=1004, boot_id='boot')
        feedback = capture(meta, row['stdout'], row['stderr'])
        body = self.proposal | dict(capability='model.plan', grant_id='0'*32,
            args=dict(provider='openai', model='snapshot', prompt='Inspect failure',
                      max_output_tokens=100, feedback=feedback))
        with self.assertRaisesRegex(Denied, 'Only original terminal.run'):
            validate(self.state, ActionRequest.parse(canonical(body).encode()),
                     caller_uid=1004, boot_id='boot')
        with self.assertRaises(Denied):
            read(self.state, task_id=self.task, action_id=action, caller_uid=1005, boot_id='boot')

    def test_sdk_success_binds_proposal_and_marks_all_metadata_untrusted(self):
        request, action = self.begin()
        conversation = Discovery()
        conversation.next_packet = None
        conversation.sent()
        conversation.accept(canonical(dict(jsonrpc='2.0', id='mano-discover',
            result=dict(supportedVersions=[VERSION], capabilities={}))).encode())
        result = conversation.manifest(server_return_code=0)
        persist(self.state, action, dict(return_code=0, reason='completed'),
                dict(stdout=canonical(result).encode(), stderr=b'separate logs'), boot_id='boot')

        def client(envelope):
            return dispatch(self.state, canonical(envelope).encode(),
                            peer=Peer(123,1004,1004), now=10, boot_id='boot')

        worker = MCPDiscovery(client, request=request, action_id=action)
        observed = worker.result()
        self.assertEqual(observed['status'], 'discovered')
        self.assertTrue(observed['untrusted'])
        self.assertFalse(observed['effect_verified'])
        self.assertFalse(observed['invocation_authorized'])
        self.assertEqual(observed['stderr'], b'separate logs')
        wrong = Mock(return_value=dict(schema_version='1.0', ok=True, action=dict(
            id=action, task_id=self.task, state='done', verified=0,
            proposal_digest=hashlib.sha256(b'wrong proposal').hexdigest())))
        with self.assertRaises(ValueError):
            MCPDiscovery(wrong, request=request, action_id=action).result()
        self.assertEqual(wrong.call_count, 1)

    def test_sdk_never_restarts_unknown_or_denied_start(self):
        client = Mock(return_value=dict(schema_version='1.0', ok=False))
        with self.assertRaises(ValueError):
            MCPDiscovery.start(client, proposal=self.proposal, grant_id='0'*32)
        self.assertEqual(client.call_count, 1)
        request, action = self.begin()
        self.state.transition(action, 'unknown')
        client = Mock(return_value=dict(schema_version='1.0', ok=True, action=dict(
            id=action, task_id=self.task, state='unknown', verified=0,
            proposal_digest=hashlib.sha256(canonical(self.proposal).encode()).hexdigest())))
        with self.assertRaises(ValueError):
            MCPDiscovery(client, request=request, action_id=action).result()
        self.assertEqual(client.call_count, 1)
