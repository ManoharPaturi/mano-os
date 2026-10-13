"""Human-session prompt transport; submission is intent, never approval."""

import secrets

from mano_protocol.actions import identifier, text

from .approve import rpc


def prompt_packet(prompt, request_key):
    text(prompt, 8192)
    key = identifier(request_key).encode('ascii')
    encoded = prompt.encode('utf8')
    return b'\x01\x05' + key + len(encoded).to_bytes(2, 'big') + encoded


def status_packet(prompt_id):
    return b'\x01\x06' + identifier(prompt_id).encode('ascii')


def submit_prompt(prompt, *, request_key=None):
    key = request_key or secrets.token_hex(16)
    result = rpc(prompt_packet(prompt, key))
    if (result.get('ok') is not True or result['prompt']['state'] != 'received'
            or result['prompt']['task_id'] is not None):
        raise ValueError('Prompt service did not acknowledge this request')
    identifier(result['prompt']['id'])
    return result['prompt']


class Submission:
    """Preserve request identity across uncertain acknowledgements."""

    def __init__(self):
        self.pending = None

    def submit(self, prompt):
        text(prompt, 8192)
        if self.pending is None or self.pending[0] != prompt:
            self.pending = (prompt, secrets.token_hex(16))
        result = submit_prompt(prompt, request_key=self.pending[1])
        self.pending = None
        return result
