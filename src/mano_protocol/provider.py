"""Responses wire contract, no credentials, network or execution authority."""

import json

from mano_protocol.actions import (
    MAX_PACKET,
    ActionRequest,
    canonical,
    model_identifier,
    text,
    unique_object,
)

MAX_RESPONSE = 262144
FUNCTION = 'propose_terminal'


def configuration(model, max_output_tokens):
    model_identifier(model)
    if type(max_output_tokens) is not int or not 16 <= max_output_tokens <= 8192:
        raise ValueError('Invalid explicit provider configuration')


def request_body(prompt, *, model, max_output_tokens):
    configuration(model, max_output_tokens)
    text(prompt, 8192)
    schema = dict(type='object', additionalProperties=False, required=['args', 'reason'],
        properties=dict(reason=dict(type='string'), args=dict(type='object',
            additionalProperties=False, required=['argv', 'cwd', 'timeout_seconds'],
            properties=dict(argv=dict(type='array', items=dict(type='string')),
                cwd=dict(type='string'), timeout_seconds=dict(type='integer')))))
    return dict(model=model, store=False, stream=False, max_output_tokens=max_output_tokens,
        input=[dict(role='developer', content='Propose one workspace terminal operation. '
            'This proposal requires separate broker authorization; do not claim completion.'),
            dict(role='user', content=prompt)],
        tools=[dict(type='function', name=FUNCTION, strict=True, parameters=schema)],
        tool_choice=dict(type='function', name=FUNCTION), parallel_tool_calls=False)


def decode(packet, maximum):
    if not isinstance(packet, bytes) or not 1 <= len(packet) <= maximum:
        raise ValueError('Invalid bounded provider packet')
    try:
        return json.loads(packet.decode('utf8'), object_pairs_hook=unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite provider output')))
    except (UnicodeError, RecursionError, json.JSONDecodeError):
        raise ValueError('Malformed provider JSON') from None


def response_plan(packet, *, model, max_output_tokens):
    configuration(model, max_output_tokens)
    value = decode(packet, MAX_RESPONSE)
    if (not isinstance(value, dict) or value.get('object') != 'response'
            or value.get('model') != model or value.get('status') != 'completed'
            or value.get('error') is not None or value.get('incomplete_details') is not None):
        raise ValueError('Provider did not complete the configured response')
    usage = value.get('usage')
    if (not isinstance(usage, dict) or any(type(usage.get(key)) is not int
            or usage[key] < 0 for key in ('input_tokens', 'output_tokens', 'total_tokens'))
            or usage['output_tokens'] > max_output_tokens
            or usage['total_tokens'] != usage['input_tokens'] + usage['output_tokens']):
        raise ValueError('Invalid provider usage accounting')
    output = value.get('output')
    if not isinstance(output, list) or not 1 <= len(output) <= 8:
        raise ValueError('Invalid provider output list')
    calls = []
    for item in output:
        if not isinstance(item, dict):
            raise ValueError('Invalid provider output item')
        if item.get('type') == 'reasoning':
            continue  # Non-authoritative model material is not forwarded or logged.
        if (item.get('type') != 'function_call' or item.get('name') != FUNCTION
                or item.get('status') != 'completed'):
            raise ValueError('Unexpected or refused provider operation')
        calls.append(item)
    if len(calls) != 1 or not isinstance(calls[0].get('arguments'), str):
        raise ValueError('Expected exactly one terminal proposal')
    plan = decode(calls[0]['arguments'].encode('utf8'), MAX_PACKET)
    if not isinstance(plan, dict) or set(plan) != {'args', 'reason'}:
        raise ValueError('Unexpected provider authority fields')
    ActionRequest.parse(canonical(dict(schema_version='1.0', task_id='0' * 32,
        resource_id='0' * 32, grant_id='0' * 32, capability='terminal.run',
        args=plan['args'], reason=plan['reason'], idempotency_key='provider-validation')).encode())
    return plan


