import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from mano_core.provider import ResponsesPlanner, request_body, response_plan
from mano_protocol.actions import canonical


class ProviderContractTests(unittest.TestCase):
    def setUp(self):
        self.plan = dict(args=dict(argv=['/usr/bin/true'], cwd='.', timeout_seconds=1),
                         reason='workspace check')
        self.response = dict(object='response', model='explicit-snapshot', status='completed',
            usage=dict(input_tokens=20, output_tokens=30, total_tokens=50),
            output=[dict(type='reasoning', summary=[]), dict(type='function_call',
                name='propose_terminal', status='completed', arguments=canonical(self.plan))])
        self.config = dict(model='explicit-snapshot', max_output_tokens=100)

    def parse(self, response):
        return response_plan(canonical(response).encode(), **self.config)

    def test_request_contains_only_prompt_and_fixed_nonexecuting_tool(self):
        body = request_body('human goal', **self.config)
        self.assertIs(body['store'], False)
        self.assertIs(body['parallel_tool_calls'], False)
        self.assertEqual(body['input'][1], dict(role='user', content='human goal'))
        self.assertEqual(body['tool_choice'], 'required')
        self.assertEqual({tool['name'] for tool in body['tools']},
                         {'propose_terminal', 'propose_file_read', 'propose_file_write',
                          'propose_package_plan'})
        tool = body['tools'][0]
        self.assertIs(tool['strict'], True)
        self.assertEqual(set(tool['parameters']['properties']), {'args', 'reason'})
        self.assertNotIn('grant_id', canonical(body))
        self.assertEqual(self.parse(self.response), self.plan)

    def test_read_tool_selects_capability_without_accepting_authority_or_escape(self):
        plan = dict(args=dict(path='notes.txt'), reason='Read workspace notes')
        def response(arguments):
            return self.response | dict(output=[dict(type='function_call',
                name='propose_file_read', status='completed', arguments=canonical(arguments))])
        self.assertEqual(self.parse(response(plan)), plan | dict(capability='files.read'))
        for invalid in (plan | dict(capability='terminal.run'), plan | dict(grant_id='a' * 32),
                        plan | dict(args=dict(path='/etc/passwd')),
                        plan | dict(args=dict(path='../escape')),
                        plan | dict(args=dict(path='notes.txt', argv=['true']))):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.parse(response(invalid))
        mixed = response(plan)
        mixed['output'].append(self.response['output'][1])
        with self.assertRaises(ValueError):
            self.parse(mixed)

    def test_failures_refusals_extra_tools_and_model_substitution_are_denied(self):
        mutations = [dict(status=status) for status in ('incomplete', 'failed', 'queued')]
        mutations += [dict(model='different'), dict(error={'message': 'private detail'}),
            dict(output=[]), dict(output=[dict(type='message', content=[dict(type='refusal')])]),
            dict(output=self.response['output'] * 2),
            dict(output=[self.response['output'][1] | {'name': 'approve_action'}])]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.parse(self.response | mutation)

    def test_malformed_authority_and_usage_never_become_a_plan(self):
        for plan in (self.plan | {'grant_id': 'a' * 32},
                self.plan | {'args': self.plan['args'] | {'env': {'KEY': 'secret'}}},
                self.plan | {'args': self.plan['args'] | {'cwd': '/etc'}},
                self.plan | {'args': self.plan['args'] | {'timeout_seconds': True}}):
            response = copy.deepcopy(self.response)
            response['output'][1]['arguments'] = canonical(plan)
            with self.assertRaises(ValueError):
                self.parse(response)
        for usage in (dict(input_tokens=True, output_tokens=30, total_tokens=31),
                dict(input_tokens=20, output_tokens=101, total_tokens=121),
                dict(input_tokens=20, output_tokens=30, total_tokens=60)):
            with self.assertRaises(ValueError):
                self.parse(self.response | {'usage': usage})
        for packet in (b'{"object":"response","object":"response"}', b'{"usage":NaN}',
                       b'\xff', b'x' * 262145, b'[' * 2000 + b']' * 2000):
            with self.assertRaises(ValueError):
                response_plan(packet, **self.config)

    def test_one_relay_call_no_credentials_or_retry(self):
        relay = Mock(return_value=json.dumps(self.response).encode())
        planner = ResponsesPlanner(relay, **self.config)
        self.assertEqual(planner('goal'), self.plan)
        relay.assert_called_once()
        relay.reset_mock()
        relay.side_effect = TimeoutError('uncertain')
        with self.assertRaises(TimeoutError):
            planner('goal')
        relay.assert_called_once()
        relay.reset_mock()
        with self.assertRaises(ValueError):
            planner('')
        relay.assert_not_called()

    @unittest.skipUnless(importlib.util.find_spec('langgraph'), 'Optional LangGraph required')
    def test_provider_plan_reaches_real_graph_and_journal_without_execution_authority(self):
        from mano_broker.ipc import Peer, dispatch
        from mano_broker.state import State
        from mano_core.runtime import AgentRuntime

        with tempfile.TemporaryDirectory() as directory:
            journal = State(Path(directory).resolve() / 'journal')
            try:
                task = journal.create_task(human_uid=1002, caller_uid=1005, mode='supervised',
                    resource_id='a' * 32, classification='internal', boot_id='boot')
                calls = []

                def broker(packet):
                    calls.append(packet['operation'])
                    return dispatch(journal, canonical(packet).encode(), peer=Peer(42, 1005, 1005),
                                    now=10, boot_id='boot')

                relay = Mock(return_value=canonical(self.response).encode())
                runtime = AgentRuntime(ResponsesPlanner(relay, **self.config), broker)
                result = runtime.step(dict(prompt='human goal', task_id=task,
                    resource_id='a' * 32, operation_key='provider-one'), thread_id=task)
                self.assertEqual(result['status'], 'awaiting_grant')
                self.assertEqual(calls, ['request_approval', 'approval_status'])
                self.assertEqual(journal.db.execute(
                    'SELECT count(*) FROM actions').fetchone()[0], 0)
                self.assertEqual(journal.db.execute('SELECT count(*) FROM grants').fetchone()[0], 0)
                self.assertNotIn(task, canonical(relay.call_args.args[0]))
                self.assertEqual(result['proposal']['task_id'], task)
            finally:
                journal.close()

    def test_write_tool_is_only_a_strict_bounded_non_authoritative_proposal(self):
        plan = dict(args=dict(path='answer.py', text='answer=42\n'), reason='Fix the project')
        response = self.response | dict(output=[dict(type='function_call',
            name='propose_file_write', status='completed', arguments=canonical(plan))])
        self.assertEqual(self.parse(response), plan | dict(capability='files.write'))
        for args in (dict(path='../outside', text='x'), dict(path='file', text='x'*32769),
                     dict(path='file', text='x', mode=511)):
            changed = response | dict(output=[dict(type='function_call', name='propose_file_write',
                status='completed', arguments=canonical(plan | dict(args=args)))])
            with self.assertRaises(ValueError):
                self.parse(changed)

    def test_package_tool_requires_catalog_and_cannot_smuggle_apply_or_options(self):
        plan = dict(args=dict(names=['sl'],catalog_id='a'*64),reason='Preview dependencies')
        def response(value):
            return self.response|dict(output=[dict(type='function_call',
                name='propose_package_plan',status='completed',arguments=canonical(value))])
        self.assertEqual(self.parse(response(plan)),plan|dict(capability='packages.plan_install'))
        for args in (dict(names=['-y'],catalog_id='a'*64),
                     dict(names=['sl'],catalog_id='not-a-catalog'),
                     dict(names=['sl'],catalog_id='a'*64,apply=True)):
            with self.assertRaises(ValueError):
                self.parse(response(plan|dict(args=args)))
