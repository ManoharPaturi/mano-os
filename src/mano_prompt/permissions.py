"""Selection-bound permission view model; requests are pending-only, never confirmations."""

import secrets

from mano_protocol.actions import identifier
from mano_protocol.profiles import configuration

from .mode import parse_profile_ack, parse_profile_status

NAMES = {'supervised': 'Supervised', 'auto': 'Auto', 'full-access': 'Full Access'}


class Permissions:
    def __init__(self, prompt_id, task_id):
        self.prompt_id, self.task_id = identifier(prompt_id), identifier(task_id)
        self.status = None
        self.pending = None
        self.approval = None

    def accept_status(self, result):
        value = parse_profile_status(result, self.prompt_id)
        if value['task_id'] != self.task_id:
            raise ValueError('Selected task changed')
        self.status = value['profile']

    def prepare(self, args):
        args = configuration(args)
        if self.status is None:
            raise ValueError('Read the selected task status first')
        if self.pending is not None and self.pending[1] != args:
            raise ValueError('Resolve the same uncertain request before changing limits')
        if self.pending is None:
            self.pending = (secrets.token_hex(16), args)
        return self.prompt_id, self.pending[0], dict(self.pending[1])

    def accept_request(self, result):
        if self.pending is None:
            raise ValueError('No matching permission request')
        value = parse_profile_ack(result, self.prompt_id)
        if value['task_id'] != self.task_id:
            raise ValueError('Permission acknowledgement belongs to another task')
        self.approval = dict(value['approval'])
        self.pending = None

    def display(self):
        if self.status is None:
            return 'Permission status has not been read.'
        value = self.status
        available = 'available' if value['automatic'] else 'unavailable'
        return (f"Recorded mode: {NAMES[value['mode']]}\nNew automatic grants: {available}\n"
                f"Remaining: {value['remaining_actions']} grants, "
                f"{value['seconds_remaining']} seconds; "
                f"action timeout: {value['max_timeout_seconds']} seconds")

    def review(self):
        if self.approval is None:
            return 'Requests require separate review and PAM authentication in your human terminal.'
        aid = self.approval['approval_id']
        if self.approval['state'] == 'approved':
            return 'Approval already recorded. Refresh permissions to check new-grant availability.'
        return ('Pending terminal review at acknowledgement; '
                'current approval state may have changed.\n'
                'This window has activated nothing.\nApproval: ' + aid
                + '\nPYTHONPATH=/usr/lib/mano-os python3 -m mano_prompt.approve ' + aid)
