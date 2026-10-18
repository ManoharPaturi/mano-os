import unittest
from unittest.mock import patch

from mano_prompt.intake import LABELS, Intake, parse, read_status

A, B, TASK = 'a' * 32, 'b' * 32, 'c' * 32


def value(prompt=A, state='received', task=None):
    return dict(id=prompt, state=state, task_id=task)


class PromptIntakeTests(unittest.TestCase):
    def test_fixed_labels_and_task_created_does_not_claim_execution(self):
        model = Intake()
        self.assertEqual(model.display(), '')
        for state in LABELS:
            task = TASK if state == 'task_created' else None
            model.select(value(state=state, task=task))
            self.assertIn(LABELS[state], model.display())
            self.assertIn(A, model.display())
        model.select(value(state='task_created', task=TASK))
        self.assertIn(TASK, model.display())
        self.assertIn('execution status is unavailable', model.display())

    def test_malformed_or_cross_identity_reply_is_rejected(self):
        bad = [None, {}, value(prompt='<b>untrusted</b>'), value(state='done'),
               value(state=[]), value(task=TASK), value(state='task_created'),
               {**value(), 'approval': True}]
        for reply in bad:
            with self.subTest(reply=reply), self.assertRaises(ValueError):
                parse(reply)
        with self.assertRaises(ValueError):
            parse(value(prompt=B), A)

    def test_stale_reply_cannot_replace_new_selection_even_same_prompt_id(self):
        model = Intake()
        model.select(value())
        token = model.token()
        model.select(value(prompt=B))
        self.assertFalse(model.update(token, value(state='creating_task')))
        self.assertEqual(model.current['id'], B)
        model.select(value())
        self.assertFalse(model.update(token, value(state='creating_task')))
        self.assertEqual(model.current['state'], 'received')
        self.assertTrue(model.update(model.token(), value(state='creating_task')))

    def test_status_rpc_is_read_only_and_never_retries_or_submits(self):
        with patch('mano_prompt.intake.rpc', return_value=dict(ok=True, prompt=value())) as rpc:
            self.assertEqual(read_status(A), value())
            rpc.assert_called_once_with(b'\x01\x06' + A.encode())
        with patch('mano_prompt.intake.rpc', side_effect=OSError('private detail')) as rpc:
            with self.assertRaises(OSError):
                read_status(A)
            self.assertEqual(rpc.call_count, 1)
        with patch('mano_prompt.intake.rpc', return_value=dict(ok=True, prompt=value(B))):
            with self.assertRaises(ValueError):
                read_status(A)

    def test_rejected_update_preserves_previous_acknowledged_status(self):
        model = Intake()
        model.select(value())
        with self.assertRaises(ValueError):
            model.update(model.token(), value(B))
        self.assertEqual(model.current, value())
