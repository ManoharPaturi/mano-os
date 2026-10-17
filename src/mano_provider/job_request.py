"""Validate a broker-attested job before credentials or provider execution."""

import json
import pwd

from mano_protocol.actions import MAX_PACKET, ActionRequest, Capability, canonical
from mano_protocol.provider import decode
from mano_protocol.provider_handoff import validate_binding


def authorize(packet, peer, *, config, boot_id):
    broker = pwd.getpwnam('mano-broker')
    if (broker.pw_uid == 0 or peer.pid <= 0
            or (peer.uid, peer.gid) != (broker.pw_uid, broker.pw_gid)):
        raise ValueError('Original kernel-authenticated broker required')
    if not isinstance(config, dict) or config.get('enabled') is not True:
        raise ValueError('Provider generation policy disabled')
    value = decode(packet, MAX_PACKET)
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'operation', 'body'}
            or value['schema_version'] != '1.0' or value['operation'] != 'generate'
            or not isinstance(value['body'], dict)
            or set(value['body']) != {'binding', 'request'}):
        raise ValueError('Invalid private provider job envelope')
    binding = value['body']['binding']
    validate_binding(binding)
    request = ActionRequest.parse(canonical(value['body']['request']).encode())
    if (request.capability != Capability.PLAN or binding['task_id'] != request.task_id
            or binding['boot_id'] != boot_id or binding['request_sha256'] != request.digest):
        raise ValueError('Provider job differs from original approved disclosure')
    args = json.loads(request.args_json)
    ceiling = config.get('max_output_tokens')
    if (config.get('provider') != 'openai' or args['provider'] != config['provider']
            or args['model'] != config.get('model') or type(ceiling) is not int
            or not 16 <= ceiling <= 8192 or args['max_output_tokens'] > ceiling):
        raise ValueError('Provider job exceeds fixed model policy')
    return dict(binding), args
