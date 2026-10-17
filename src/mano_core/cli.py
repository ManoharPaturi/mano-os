"""Bounded broker-planner or explicit mock core entry point."""

import argparse
import json
import sys

from mano_protocol.actions import MAX_PACKET, canonical, unique_object
from mano_protocol.provider import configuration

from .broker import BrokerClient
from .checkpoints import Session
from .planner import BrokerPlanner
from .profile import ProfileDenied, verify_current


def parse_input(packet, *, broker_model=False):
    if not isinstance(packet, bytes) or not 1 <= len(packet) <= MAX_PACKET:
        raise ValueError('Invalid bounded core input')
    def nonfinite(_):
        raise ValueError('Nonfinite input')

    value = json.loads(packet.decode('utf8'), object_pairs_hook=unique_object,
                       parse_constant=nonfinite)
    field = 'model' if broker_model else 'plan'
    if (not isinstance(value, dict) or set(value) != {'context', field}
            or not isinstance(value['context'], dict)
            or set(value['context']) != {'task_id', 'resource_id', 'operation_key', 'prompt'}
            or not isinstance(value[field], dict)):
        raise ValueError('Unknown core input fields')
    if broker_model:
        if set(value['model']) != {'model', 'max_output_tokens'}:
            raise ValueError('Unknown broker model configuration')
        configuration(value['model']['model'], value['model']['max_output_tokens'])
    elif set(value['plan']) != {'args', 'reason'}:
        raise ValueError('Unknown mock plan fields')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description='Run one broker-reconciled core cycle')
    parser.add_argument('--checkpoint-directory', required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--mock', action='store_true', help='Explicit deterministic test model')
    mode.add_argument('--broker-model', action='store_true', help='Use broker-approved planning')
    args = parser.parse_args(argv)
    client = session = None
    try:
        verify_current()  # Before checkpoint access or broker requests.
        value = parse_input(sys.stdin.buffer.read(MAX_PACKET + 1), broker_model=args.broker_model)
        client = BrokerClient()
        if args.broker_model:
            context = value['context']
            model = BrokerPlanner(client, task_id=context['task_id'],
                resource_id=context['resource_id'], operation_key=context['operation_key'],
                **value['model'])
        else:
            def model(_):
                return value['plan']
        session = Session(args.checkpoint_directory, model, client)
        result = session.step(value['context'])
        print(canonical(dict(schema_version='1.0', ok=True, task=result)))
        return 0
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        detail = str(error) if isinstance(error, ProfileDenied) else type(error).__name__
        print(canonical(dict(event='core-cycle-denied', reason=detail)), file=sys.stderr)
        print(canonical(dict(schema_version='1.0', ok=False, error='denied')))
        return 1
    finally:
        if session is not None:
            session.close()
        if client is not None:
            client.close()


if __name__ == '__main__':
    raise SystemExit(main())
