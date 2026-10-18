import unittest

from mano_prompt.permissions import Permissions
from mano_protocol.profiles import scope

P, T, A = 'a'*32, 'b'*32, 'c'*32
ARGS = dict(mode='auto', duration_seconds=60, max_actions=4, max_timeout_seconds=10)


def status(**changes):
    profile = dict(mode='supervised', automatic=False, remaining_actions=0,
                   seconds_remaining=0, max_timeout_seconds=0, scope=scope('supervised')) | changes
    return dict(schema_version='1.0', ok=True, prompt_id=P, task_id=T, profile=profile)


def ack(state='pending'):
    return dict(schema_version='1.0', ok=True, prompt_id=P, task_id=T,
                approval=dict(approval_id=A, state=state,
                              grant_id=None if state == 'pending' else 'd'*32))


class PermissionsViewTests(unittest.TestCase):
    def test_initial_state_cannot_request_before_reading_owned_task(self):
        model = Permissions(P, T)
        with self.assertRaises(ValueError):
            model.prepare(ARGS)
        self.assertIn('has not been read', model.display())
        with self.assertRaises(ValueError):
            model.accept_status(status() | dict(task_id='f'*32))
        self.assertIsNone(model.status)
        model.accept_status(status())
        self.assertIn('New automatic grants: unavailable', model.display())

    def test_uncertain_request_retains_identity_and_args_until_valid_ack(self):
        model = Permissions(P, T)
        model.accept_status(status())
        first = model.prepare(ARGS)
        self.assertEqual(first, model.prepare(dict(ARGS)))
        with self.assertRaises(ValueError):
            model.prepare(ARGS | dict(mode='full-access'))
        with self.assertRaises(ValueError):
            model.accept_request(ack() | dict(task_id='e'*32))
        self.assertEqual(first, model.prepare(ARGS))
        model.accept_request(ack())
        self.assertIsNone(model.pending)
        self.assertIn(A, model.review())
        self.assertIn('activated nothing', model.review())
        self.assertIn('mano_prompt.approve ' + A, model.review())
        self.assertNotEqual(model.prepare(ARGS)[1], first[1])

    def test_status_failure_does_not_erase_previous_acknowledgement(self):
        model = Permissions(P, T)
        model.accept_status(status(mode='auto', automatic=True, remaining_actions=4,
            seconds_remaining=40, max_timeout_seconds=10, scope=scope('auto')))
        before = model.display()
        for value in (status(nonce='private'), status(automatic=True),
                      status() | dict(prompt_id='f'*32)):
            with self.assertRaises(ValueError):
                model.accept_status(value)
            self.assertEqual(model.display(), before)

    def test_approved_history_is_not_rendered_as_current_authority(self):
        model = Permissions(P, T)
        model.accept_status(status())
        model.prepare(ARGS)
        model.accept_request(ack('approved'))
        self.assertIn('already recorded', model.review())
        self.assertIn('Refresh permissions', model.review())
        self.assertIn('unavailable', model.display())
        self.assertNotIn('d'*32, model.review())

    def test_malformed_bounds_secret_fields_and_unsolicited_ack_fail_closed(self):
        model = Permissions(P, T)
        with self.assertRaises(ValueError):
            model.accept_request(ack())
        model.accept_status(status())
        for args in (ARGS | dict(max_actions=True), ARGS | dict(duration_seconds=901),
                     ARGS | dict(mode='full-access', duration_seconds=301)):
            with self.assertRaises(ValueError):
                model.prepare(args)
        model.prepare(ARGS)
        for value in (ack() | dict(nonce='secret'), ack() | dict(prompt_id='f'*32),
                      ack() | dict(approval=ack()['approval'] | dict(nonce='secret'))):
            with self.assertRaises(ValueError):
                model.accept_request(value)
        self.assertIsNotNone(model.pending)
