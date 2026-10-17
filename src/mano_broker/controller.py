"""One Root controller cycle; recurring activation is a separate installed policy."""

import argparse
import os
import re
import sys

from mano_protocol.provider import configuration

from .lifecycle import run_broker_step
from .protocol import canonical, identifier
from .stop_state import snapshot
from .task_factory import control_request, create_from_prompt, human_uid


def run_cycle(*, model, max_output_tokens):
    if os.geteuid() != 0 or sys.platform != 'linux':
        raise PermissionError('Trusted Linux Root controller required')
    configuration(model, max_output_tokens)
    before = snapshot()
    if before.latched:
        raise ValueError('Native Stop prevents a controller cycle')
    human = human_uid()
    cycle = control_request('claim_core_cycle', dict(human_uid=human, model=model,
        max_output_tokens=max_output_tokens))['cycle']
    if cycle is None:
        return None
    if (not isinstance(cycle, dict) or set(cycle) != {
            'prompt_id', 'prompt_state', 'nonce', 'model', 'max_output_tokens'}
            or cycle['model'] != model or cycle['max_output_tokens'] != max_output_tokens
            or cycle['prompt_state'] not in {'received', 'task_created'}
            or not isinstance(cycle['nonce'], str)
            or not re.fullmatch('[0-9a-f]{64}', cycle['nonce'])):
        raise ValueError('Invalid original controller claim')
    prompt_id = identifier(cycle['prompt_id'])
    binding = dict(human_uid=human, prompt_id=prompt_id, nonce=cycle['nonce'])
    try:
        current = snapshot()
        if current.latched or current.generation != before.generation:
            raise ValueError('Stop changed before task creation')
        managed = (create_from_prompt(prompt_id) if cycle['prompt_state'] == 'received'
                   else control_request('prompt_context', dict(human_uid=human,
                                                               prompt_id=prompt_id))['managed'])
        if (managed['prompt_id'] != prompt_id
                or managed['context']['operation_key'] != prompt_id):
            raise ValueError('Controller cannot change original prompt scope')
        task = run_broker_step(managed, model=model, max_output_tokens=max_output_tokens)
        after = snapshot()
        if after.latched or after.generation != before.generation:
            raise ValueError('Stop changed during controller cycle')
        control_request('finish_core_cycle', binding | {'status': task['status']})
        return dict(prompt_id=prompt_id, task_id=managed['context']['task_id'],
                    status=task['status'])
    except BaseException:
        try:
            control_request('finish_core_cycle', binding | {'status': 'controller_uncertain'})
        except (OSError, ValueError, KeyError, TypeError):
            pass  # Original claim remains unknown/running; never steal it or allocate again.
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description='Run one protected broker-planner cycle')
    parser.add_argument('--model', required=True)
    parser.add_argument('--max-output-tokens', required=True, type=int)
    args = parser.parse_args(argv)
    try:
        result = run_cycle(model=args.model, max_output_tokens=args.max_output_tokens)
        print(canonical(dict(schema_version='1.0', ok=True, cycle=result)))
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        print(canonical(dict(schema_version='1.0', ok=False, error='uncertain')))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
