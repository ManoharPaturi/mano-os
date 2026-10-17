"""Validate a broker-attested job before credentials or provider execution."""

import json
import math
import pwd
import socket
import time

from mano_protocol.actions import MAX_PACKET, ActionRequest, Capability, canonical
from mano_protocol.provider import decode
from mano_protocol.provider_handoff import send_response, validate_binding
from mano_protocol.stop_state import snapshot

from .https import generate

JOB_LIFETIME_SECONDS = 35


def authorize(packet, peer, *, config, boot_id, now, wall_time):
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
            or set(value['body']) != {'binding', 'request', 'grant_expires_monotonic',
                                     'price_expires_unix', 'native_stop_generation'}):
        raise ValueError('Invalid private provider job envelope')
    body = value['body']
    generation = body['native_stop_generation']
    if type(generation) is not int or not 0 <= generation <= (1 << 63) - 1:
        raise ValueError('Invalid native Stop grant generation')
    native = snapshot()
    if native.latched or native.generation != generation:
        raise ValueError('Native Stop invalidated provider authority')
    for number in (now, wall_time, body['grant_expires_monotonic'], body['price_expires_unix']):
        if (type(number) not in {int, float} or not 0 <= number <= 2**53
                or not math.isfinite(number)):
            raise ValueError('Invalid trusted provider deadline')
    if (body['grant_expires_monotonic'] - now < JOB_LIFETIME_SECONDS
            or body['price_expires_unix'] - wall_time < JOB_LIFETIME_SECONDS):
        raise ValueError('Provider job cannot outlive its grant or price policy')
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


def execute(connection, packet, peer, *, config, credential, boot_id):
    """One authorized fixed-provider invocation, then one sealed handoff; no retry."""
    if connection.family != socket.AF_UNIX or connection.type != socket.SOCK_SEQPACKET:
        raise ValueError('Private provider response connection required before dispatch')
    binding, args = authorize(packet, peer, config=config, boot_id=boot_id,
                              now=time.monotonic(), wall_time=int(time.time()))
    response = generate(args, credential)
    send_response(connection, response, binding=binding)
