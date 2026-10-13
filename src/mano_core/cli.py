"""Runnable mock-model core entry point; inputs are data, never host commands."""

import argparse
import json
import sys

from mano_protocol.actions import MAX_PACKET, canonical, unique_object

from .broker import BrokerClient
from .checkpoints import Session
from .profile import ProfileDenied, verify_current


def parse_input(packet):
    if not isinstance(packet, bytes) or not 1 <= len(packet) <= MAX_PACKET:
        raise ValueError('Invalid bounded core input')
    def nonfinite(_):
        raise ValueError('Nonfinite input')

    value = json.loads(packet.decode('utf8'), object_pairs_hook=unique_object,
                       parse_constant=nonfinite)
    if (not isinstance(value, dict) or set(value) != {'context', 'plan'}
            or not isinstance(value['context'], dict)
            or set(value['context']) != {'task_id', 'resource_id', 'operation_key', 'prompt'}
            or not isinstance(value['plan'], dict) or set(value['plan']) != {'args', 'reason'}):
        raise ValueError('Unknown core input fields')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description='Run one broker-reconciled core cycle')
    parser.add_argument('--checkpoint-directory', required=True)
    parser.add_argument('--mock', action='store_true', help='Explicit deterministic test model')
    args = parser.parse_args(argv)
    if not args.mock:
        parser.error('A real provider is not configured; --mock is required for this test adapter')
    client = session = None
    try:
        verify_current()  # Before checkpoint access or broker requests.
        value = parse_input(sys.stdin.buffer.read(MAX_PACKET + 1))
        def model(_):
            return value['plan']
        client = BrokerClient()
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
