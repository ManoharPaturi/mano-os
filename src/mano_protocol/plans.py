"""Strict non-authoritative plans shared by provider, core and operator adapters."""

from .actions import ActionRequest, Capability, canonical

EXECUTABLE = {Capability.RUN, Capability.READ}


def parse_plan(value):
    if not isinstance(value, dict) or set(value) not in (
            {'args', 'reason'}, {'capability', 'args', 'reason'}):
        raise ValueError('Unexpected model plan fields')
    capability = Capability(value.get('capability', Capability.RUN))
    if capability not in EXECUTABLE:
        raise ValueError('Unsupported core action capability')
    ActionRequest.parse(canonical(dict(schema_version='1.0', task_id='0' * 32,
        resource_id='0' * 32, grant_id='0' * 32, capability=capability,
        args=value['args'], reason=value['reason'], idempotency_key='plan-validation')).encode())
    return dict(capability=capability.value, args=value['args'], reason=value['reason'])


def proposal(plan, context):
    return dict(schema_version='1.0', task_id=context['task_id'],
        resource_id=context['resource_id'], idempotency_key=context['operation_key'],
        **parse_plan(plan))
